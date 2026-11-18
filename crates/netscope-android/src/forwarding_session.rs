//! Session-scoped TCP+UDP forwarding kernel, without JNI exports or TUN ownership.
//!
//! Wraps the portable relays and the combined readiness wait behind one object a platform adapter
//! can drive from a single thread: feed each packet read from the TUN to [`handle_packet`] and
//! call [`service`] in a loop to obtain the packets to write back. The session owns the clock
//! (supplied at construction) so every call sees one monotonic time source. A new session denies every
//! packet; the caller installs rules (which always keep a default of Deny). Revocation is
//! terminal. The limits below are initial, unmeasured on any device.
//!
//! [`handle_packet`]: ForwardingSession::handle_packet
//! [`service`]: ForwardingSession::service
use netscope_engine::Config as EngineConfig;
use netscope_packet::{parse, ChecksumPolicy, ParseError, Protocol};
use netscope_policy::{Action, Context, ContextRule, Policy, PolicyError};
use netscope_transport::{
    event,
    tcp::{self, TcpRelay, TcpSocketProtector},
    RelayError, SocketProtector, UdpRelay,
};
use std::{io, time::Duration};

pub const UDP_MAX_FLOWS: usize = 64;
pub const UDP_TIMEOUT_MS: u64 = 30_000;
pub const MTU: usize = 1500;
/// Long-lived idle connections (push channels) are common, so TCP idle is generous.
pub const TCP_IDLE_TIMEOUT_MS: u64 = 30 * 60 * 1000;
pub const TCP_CONNECT_TIMEOUT_MS: u64 = 10_000;
pub const TCP_MAX_FLOWS: usize = 128;
pub const TCP_MAX_PENDING: usize = 16;
pub const TCP_MAX_FLOWS_PER_UID: usize = 64;
/// Most packets returned by one `service` call; the rest stay queued for the next call.
pub const MAX_BATCH: usize = 64;

#[derive(Debug)]
pub enum ForwardingError {
    Revoked,
    Config,
    Policy(PolicyError),
    /// Not a well-formed, supported IPv4/IPv6 TCP or UDP datagram (e.g. ICMP, fragments).
    Packet(ParseError),
    Udp(RelayError),
    Tcp(tcp::Error),
    /// The TCP relay cannot take this packet yet; re-submit the same packet after `service`.
    Backpressure,
    Io(io::Error),
}

/// Monotonic milliseconds supplied by the platform adapter (e.g. `SystemClock.elapsedRealtime`).
pub type Clock = Box<dyn FnMut() -> u64 + Send>;

pub struct ForwardingSession<U: SocketProtector, T: TcpSocketProtector> {
    udp: UdpRelay<U>,
    tcp: TcpRelay<T>,
    active: bool,
    clock: Clock,
    last_ms: u64,
}

impl<U: SocketProtector, T: TcpSocketProtector> ForwardingSession<U, T> {
    /// All IPv4/IPv6 TCP and UDP packets are denied until explicit rules are installed.
    pub fn new(udp_protector: U, tcp_protector: T, clock: Clock) -> Result<Self, ForwardingError> {
        let deny = || Policy::new(Vec::new(), Action::Deny).map_err(ForwardingError::Policy);
        let udp = UdpRelay::new(
            deny()?,
            EngineConfig {
                max_flows: UDP_MAX_FLOWS,
                timeout: UDP_TIMEOUT_MS,
                checksums: ChecksumPolicy::Require,
            },
            MTU,
            udp_protector,
        )
        .map_err(ForwardingError::Udp)?;
        let tcp = TcpRelay::new(
            deny()?,
            tcp::Config {
                max_flows: TCP_MAX_FLOWS,
                mtu: MTU,
                buffer_bytes: 16 * 1024,
                output_slots: 8,
                buffer_budget: tcp::MAX_BUFFER_BUDGET,
                idle_timeout_ms: TCP_IDLE_TIMEOUT_MS,
                connect_timeout_ms: TCP_CONNECT_TIMEOUT_MS,
                max_pending: TCP_MAX_PENDING,
                max_flows_per_uid: TCP_MAX_FLOWS_PER_UID,
            },
            tcp_protector,
        )
        .map_err(ForwardingError::Tcp)?;
        Ok(Self {
            udp,
            tcp,
            active: true,
            clock,
            last_ms: 0,
        })
    }

    /// The session's own clock, never allowed to go backwards (the relays reject reversed time).
    fn tick(&mut self) -> u64 {
        self.last_ms = (self.clock)().max(self.last_ms);
        self.last_ms
    }

    fn ensure_active(&self) -> Result<(), ForwardingError> {
        if self.active {
            Ok(())
        } else {
            Err(ForwardingError::Revoked)
        }
    }

    /// Install rules (default action fixed to Deny). A valid update revokes every existing flow in
    /// both relays; an invalid one changes nothing.
    pub fn update_rules(&mut self, rules: Vec<ContextRule>) -> Result<(), ForwardingError> {
        self.ensure_active()?;
        // Validate once so a failure cannot leave the two relays on different policies.
        Policy::with_context_rules(rules.clone(), Action::Deny).map_err(ForwardingError::Policy)?;
        self.udp
            .update_context_policy(rules.clone(), Action::Deny)
            .map_err(ForwardingError::Policy)?;
        self.tcp
            .update_context_policy(rules, Action::Deny)
            .map_err(ForwardingError::Policy)
    }

    /// Dispatch one complete IP packet read from the TUN. `context` is the uid/network the
    /// adapter resolved for this flow; it is recorded when the flow is created. On
    /// [`ForwardingError::Backpressure`] re-submit the same packet after the next `service`.
    pub fn handle_packet(
        &mut self,
        packet: &[u8],
        context: &Context,
    ) -> Result<(), ForwardingError> {
        self.ensure_active()?;
        let now_ms = self.tick();
        match parse(packet).map_err(ForwardingError::Packet)?.protocol {
            Protocol::Udp => self
                .udp
                .send_in(packet, now_ms, context)
                .map(|_| ())
                .map_err(ForwardingError::Udp),
            Protocol::Tcp => match self.tcp.ingest_in(packet, now_ms, context) {
                Ok(_) => Ok(()),
                Err(tcp::Error::Backpressure) => Err(ForwardingError::Backpressure),
                Err(error) => Err(ForwardingError::Tcp(error)),
            },
        }
    }

    /// One loop iteration: wait up to `max_wait` for upstream readiness or the next relay
    /// deadline, service both relays and return up to [`MAX_BATCH`] packets for the TUN writer.
    /// The session clock is read before and after the wait, so a blocking wait never leaves the
    /// relays with a stale time. Per-flow failures (a reply the
    /// policy now denies, a vanished flow) drop only that flow and are not reported.
    pub fn service(&mut self, max_wait: Duration) -> Result<Vec<Vec<u8>>, ForwardingError> {
        self.ensure_active()?;
        let before = self.tick();
        let ready = event::wait_ready(&mut self.tcp, &mut self.udp, before, max_wait)
            .map_err(ForwardingError::Io)?;
        let now = self.tick();
        self.tcp
            .poll_ready(now, &ready.tcp)
            .map_err(ForwardingError::Tcp)?;
        self.udp.expire(now).map_err(ForwardingError::Udp)?;
        let mut out = Vec::new();
        for flow in ready.udp {
            while out.len() < MAX_BATCH {
                match self.udp.receive(flow, now) {
                    Ok(packet) => out.push(packet),
                    Err(RelayError::Io(e)) if e.kind() == io::ErrorKind::WouldBlock => break,
                    Err(_) => break, // that flow was dropped or denied; others continue
                }
            }
        }
        // A denied packet forgets its flow and is skipped; bound the attempts regardless.
        for _ in 0..MAX_BATCH * 2 {
            if out.len() >= MAX_BATCH {
                break;
            }
            match self.tcp.next_packet(now) {
                Ok(Some(packet)) => out.push(packet),
                Ok(None) => break,
                Err(tcp::Error::Clock) => return Err(ForwardingError::Tcp(tcp::Error::Clock)),
                Err(_) => {}
            }
        }
        Ok(out)
    }

    /// Must be called when connectivity changes; closes every old socket and resets TCP clients.
    pub fn reset_network(&mut self) -> Result<(), ForwardingError> {
        self.ensure_active()?;
        self.udp.reset_network();
        self.tcp.reset_network();
        Ok(())
    }

    /// Terminal: drop all flow state and sockets, then reject every future call. The caller must
    /// separately revoke the platform protector and stop its workers.
    pub fn revoke(&mut self) {
        self.active = false;
        self.udp.reset_network();
        self.tcp.reset_network();
    }

    pub fn is_active(&self) -> bool {
        self.active
    }
    pub fn flow_count(&self) -> (usize, usize) {
        (self.udp.flow_count(), self.tcp.flow_count())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use netscope_packet::{parse_checked, udp};
    use netscope_policy::{Network, Rule, UidMatch};
    use std::{
        net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpListener, UdpSocket},
        sync::{
            atomic::{AtomicUsize, Ordering},
            Arc,
        },
        time::Instant,
    };

    #[derive(Clone)]
    struct Count(Arc<AtomicUsize>);
    impl SocketProtector for Count {
        fn protect(&self, _: &UdpSocket) -> io::Result<()> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }
    impl TcpSocketProtector for Count {
        fn protect(&self, _: &socket2::Socket) -> io::Result<()> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }
    fn session() -> (ForwardingSession<Count, Count>, Arc<AtomicUsize>) {
        let calls = Arc::new(AtomicUsize::new(0));
        let start = Instant::now();
        let clock: Clock = Box::new(move || start.elapsed().as_millis() as u64);
        (
            ForwardingSession::new(Count(calls.clone()), Count(calls.clone()), clock).unwrap(),
            calls,
        )
    }
    fn allow_uid(uid: u32) -> Vec<ContextRule> {
        vec![ContextRule {
            rule: Rule {
                priority: 0,
                action: Action::Allow,
                source: None,
                destination: None,
                protocol: None,
                source_port: None,
                destination_port: None,
            },
            uid: Some(UidMatch::Range(uid..=uid)),
            network: Some(Network::Wifi),
        }]
    }
    fn app(uid: u32) -> Context {
        Context {
            uid: Some(uid),
            network: Network::Wifi,
        }
    }
    fn checksum(chunks: &[&[u8]]) -> u16 {
        let mut sum = 0u32;
        for chunk in chunks {
            for pair in chunk.chunks(2) {
                sum += u32::from(u16::from_be_bytes([pair[0], *pair.get(1).unwrap_or(&0)]));
            }
        }
        while sum > 0xffff {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        !(sum as u16)
    }
    /// A payload-free IPv4 TCP SYN with valid checksums (the adapter's TUN would supply these).
    fn syn(from: SocketAddrV4, to: SocketAddrV4) -> Vec<u8> {
        let mut tcp = vec![0u8; 20];
        tcp[0..2].copy_from_slice(&from.port().to_be_bytes());
        tcp[2..4].copy_from_slice(&to.port().to_be_bytes());
        tcp[4..8].copy_from_slice(&1000u32.to_be_bytes());
        tcp[12] = 0x50;
        tcp[13] = 0x02;
        tcp[14..16].copy_from_slice(&65535u16.to_be_bytes());
        let pseudo = [
            &from.ip().octets()[..],
            &to.ip().octets()[..],
            &[0, 6],
            &20u16.to_be_bytes(),
        ]
        .concat();
        let sum = checksum(&[&pseudo, &tcp]);
        tcp[16..18].copy_from_slice(&sum.to_be_bytes());
        let mut ip = vec![0u8; 20];
        ip[0] = 0x45;
        ip[2..4].copy_from_slice(&40u16.to_be_bytes());
        ip[6] = 0x40;
        ip[8] = 64;
        ip[9] = 6;
        ip[12..16].copy_from_slice(&from.ip().octets());
        ip[16..20].copy_from_slice(&to.ip().octets());
        let sum = checksum(&[&ip]);
        ip[10..12].copy_from_slice(&sum.to_be_bytes());
        [ip, tcp].concat()
    }
    fn tun_addr() -> SocketAddrV4 {
        SocketAddrV4::new(Ipv4Addr::new(10, 111, 0, 2), 40960)
    }
    fn v4(addr: SocketAddr) -> SocketAddrV4 {
        match addr {
            SocketAddr::V4(a) => a,
            SocketAddr::V6(_) => panic!("ipv4 only"),
        }
    }
    /// Poll `service` until `done` accepts the accumulated packets or two seconds pass.
    fn service_until(
        session: &mut ForwardingSession<Count, Count>,
        mut done: impl FnMut(&[Vec<u8>]) -> bool,
    ) -> Vec<Vec<u8>> {
        let mut all = Vec::new();
        let start = Instant::now();
        while start.elapsed() < Duration::from_secs(2) {
            all.extend(session.service(Duration::from_millis(20)).unwrap());
            if done(&all) {
                break;
            }
        }
        all
    }

    #[test]
    fn a_new_session_denies_everything_without_protecting_a_socket() {
        let (mut s, calls) = session();
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        let to = v4(server.local_addr().unwrap());
        let datagram = udp::encode(tun_addr().into(), to.into(), b"hi").unwrap();
        assert!(matches!(
            s.handle_packet(&datagram, &app(10_001)),
            Err(ForwardingError::Udp(RelayError::Dropped(_)))
        ));
        assert!(matches!(
            s.handle_packet(&syn(tun_addr(), to), &app(10_001)),
            Err(ForwardingError::Tcp(tcp::Error::Dropped(_)))
        ));
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert_eq!(s.flow_count(), (0, 0));
        // Packets this core cannot forward are reported, not silently accepted.
        assert!(matches!(
            s.handle_packet(&[0x45, 0], &app(10_001)),
            Err(ForwardingError::Packet(_))
        ));
    }

    #[test]
    fn udp_is_gated_by_uid_and_replies_come_back_through_service() {
        let (mut s, calls) = session();
        s.update_rules(allow_uid(10_001)).unwrap();
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        server
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let to = v4(server.local_addr().unwrap());
        let datagram = udp::encode(tun_addr().into(), to.into(), b"ping").unwrap();
        assert!(s.handle_packet(&datagram, &app(10_002)).is_err());
        assert!(s.handle_packet(&datagram, &Context::default()).is_err());
        s.handle_packet(&datagram, &app(10_001)).unwrap();
        let mut buffer = [0; 16];
        let (n, peer) = server.recv_from(&mut buffer).unwrap();
        assert_eq!(&buffer[..n], b"ping");
        server.send_to(b"pong", peer).unwrap();
        let replies = service_until(&mut s, |all| !all.is_empty());
        assert_eq!(replies.len(), 1);
        let reply = parse_checked(&replies[0], ChecksumPolicy::Require).unwrap();
        assert_eq!(reply.packet.destination_port, tun_addr().port());
        assert_eq!(&replies[0][28..], b"pong");
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn tcp_syn_is_admitted_for_the_uid_and_answered_after_the_upstream_connects() {
        let (mut s, calls) = session();
        s.update_rules(allow_uid(10_001)).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let to = v4(listener.local_addr().unwrap());
        let packet = syn(tun_addr(), to);
        assert!(s.handle_packet(&packet, &app(10_002)).is_err());
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        s.handle_packet(&packet, &app(10_001)).unwrap();
        assert_eq!(s.flow_count().1, 1);
        // The SYN-ACK is withheld until the OS connect completes, then arrives via service.
        let out = service_until(&mut s, |all| !all.is_empty());
        assert_eq!(out.len(), 1);
        let reply = parse_checked(&out[0], ChecksumPolicy::Require).unwrap();
        assert_eq!(reply.packet.protocol, Protocol::Tcp);
        assert_eq!(reply.packet.source_port, to.port());
        assert_eq!(reply.packet.destination_port, tun_addr().port());
        assert_eq!(out[0][20 + 13] & 0x12, 0x12, "SYN and ACK flags");
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn a_refused_upstream_connect_is_answered_with_a_reset() {
        let (mut s, _) = session();
        s.update_rules(allow_uid(10_001)).unwrap();
        // A bound but never-listening port refuses the connection.
        let socket = socket2::Socket::new(
            socket2::Domain::IPV4,
            socket2::Type::STREAM,
            Some(socket2::Protocol::TCP),
        )
        .unwrap();
        socket
            .bind(&"127.0.0.1:0".parse::<SocketAddr>().unwrap().into())
            .unwrap();
        let to = v4(socket.local_addr().unwrap().as_socket().unwrap());
        let packet = syn(tun_addr(), to);
        // The refusal is seen either right at connect (an error, RST queued) or on a later poll.
        match s.handle_packet(&packet, &app(10_001)) {
            Ok(()) | Err(ForwardingError::Tcp(tcp::Error::Io(_))) => {}
            Err(error) => panic!("unexpected: {error:?}"),
        }
        let out = service_until(&mut s, |all| !all.is_empty());
        assert!(!out.is_empty());
        for packet in &out {
            assert_eq!(packet[20 + 13] & 0x04, 0x04, "RST flag, never a SYN-ACK");
        }
    }

    #[test]
    fn rule_updates_are_atomic_and_revoke_is_terminal() {
        let (mut s, _) = session();
        s.update_rules(allow_uid(10_001)).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let to = v4(listener.local_addr().unwrap());
        s.handle_packet(&syn(tun_addr(), to), &app(10_001)).unwrap();
        assert_eq!(s.flow_count().1, 1);
        // An invalid update changes nothing; a valid one revokes existing flows in both relays.
        let mut bad = allow_uid(1);
        bad[0].uid = Some(UidMatch::Range(std::ops::RangeInclusive::new(5, 4)));
        assert!(matches!(
            s.update_rules(bad),
            Err(ForwardingError::Policy(_))
        ));
        assert_eq!(s.flow_count().1, 1);
        s.update_rules(Vec::new()).unwrap();
        assert_eq!(s.flow_count(), (0, 0));
        s.revoke();
        assert!(!s.is_active());
        assert!(matches!(
            s.handle_packet(&syn(tun_addr(), to), &app(10_001)),
            Err(ForwardingError::Revoked)
        ));
        assert!(matches!(
            s.service(Duration::ZERO),
            Err(ForwardingError::Revoked)
        ));
        assert!(matches!(s.reset_network(), Err(ForwardingError::Revoked)));
        assert!(matches!(
            s.update_rules(Vec::new()),
            Err(ForwardingError::Revoked)
        ));
    }
    #[test]
    fn a_clock_that_goes_backwards_never_reaches_the_relays() {
        let calls = Arc::new(AtomicUsize::new(0));
        let mut values = [100u64, 50, 10, 200].into_iter().cycle();
        let clock: Clock = Box::new(move || values.next().unwrap());
        let mut s = ForwardingSession::new(Count(calls.clone()), Count(calls), clock).unwrap();
        s.update_rules(allow_uid(10_001)).unwrap();
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        let to = v4(server.local_addr().unwrap());
        let datagram = udp::encode(tun_addr().into(), to.into(), b"x").unwrap();
        for _ in 0..4 {
            s.handle_packet(&datagram, &app(10_001)).unwrap();
            s.service(Duration::ZERO).unwrap();
        }
    }
}
