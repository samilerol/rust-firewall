//! Session-scoped UDP forwarding kernel, without JNI exports or TUN ownership.
//!
//! A new session denies every packet. Caller must explicitly install rules;
//! revocation is terminal and closes all Rust-owned upstream sockets.
use netscope_conntrack::FlowId;
use netscope_engine::Config;
use netscope_packet::ChecksumPolicy;
use netscope_policy::{Action, Policy, PolicyError, Rule};
use netscope_transport::{RelayError, Sent, SocketProtector, UdpRelay};

/// Conservative initial cap; a later Android configuration must be independently validated.
pub const SESSION_MAX_FLOWS: usize = 64;
pub const SESSION_MTU: usize = 1500;
pub const SESSION_TIMEOUT_MS: u64 = 30_000;

#[derive(Debug)]
pub enum SessionError {
    Revoked,
    Policy(PolicyError),
    Relay(RelayError),
}

pub struct UdpSession<P: SocketProtector> {
    relay: UdpRelay<P>,
    active: bool,
}

impl<P: SocketProtector> UdpSession<P> {
    /// All IPv4/IPv6 UDP packets are denied until explicit rules are installed.
    pub fn new(protector: P) -> Result<Self, RelayError> {
        let policy = Policy::new(Vec::new(), Action::Deny).map_err(|_| RelayError::Config)?;
        let relay = UdpRelay::new(
            policy,
            Config {
                max_flows: SESSION_MAX_FLOWS,
                timeout: SESSION_TIMEOUT_MS,
                checksums: ChecksumPolicy::Require,
            },
            SESSION_MTU,
            protector,
        )?;
        Ok(Self { relay, active: true })
    }

    /// Always default-deny. A successful update revokes prior flow associations.
    /// An invalid update leaves the active policy and existing flows unchanged.
    pub fn update_rules(&mut self, rules: Vec<Rule>) -> Result<(), SessionError> {
        if !self.active {
            return Err(SessionError::Revoked);
        }
        self.relay
            .update_policy(rules, Action::Deny)
            .map_err(SessionError::Policy)
    }

    /// Process one complete IP/UDP datagram. Upstream sockets are protected by P
    /// before connecting or sending, even for an explicitly admitted rule.
    pub fn send(&mut self, packet: &[u8], now_ms: u64) -> Result<Sent, SessionError> {
        if !self.active {
            return Err(SessionError::Revoked);
        }
        self.relay.send(packet, now_ms).map_err(SessionError::Relay)
    }

    /// Only policy-approved responses from an existing flow may be returned.
    /// The caller must use a separate bounded, fail-stop TUN output gate.
    pub fn receive(&mut self, flow: FlowId, now_ms: u64) -> Result<Vec<u8>, SessionError> {
        if !self.active {
            return Err(SessionError::Revoked);
        }
        self.relay.receive(flow, now_ms).map_err(SessionError::Relay)
    }

    /// Must be called when connectivity changes; closes every old socket.
    pub fn reset_network(&mut self) -> Result<(), SessionError> {
        if !self.active {
            return Err(SessionError::Revoked);
        }
        self.relay.reset_network();
        Ok(())
    }

    /// Terminal: drop all flow state/sockets, then reject all future operations.
    /// Caller must separately revoke the AndroidVpnProtector and stop its workers.
    pub fn revoke(&mut self) {
        self.active = false;
        self.relay.reset_network();
    }

    pub fn is_active(&self) -> bool {
        self.active
    }

    pub fn flow_count(&self) -> usize {
        self.relay.flow_count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use netscope_packet::{udp, Protocol};
    use netscope_policy::Cidr;
    use netscope_transport::RelayError;
    use std::{
        io,
        net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket},
        sync::atomic::{AtomicUsize, Ordering},
    };

    struct CountingProtector<'a>(&'a AtomicUsize);
    impl SocketProtector for CountingProtector<'_> {
        fn protect(&self, _socket: &UdpSocket) -> io::Result<()> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    fn rule(from: SocketAddr, to: SocketAddr) -> Rule {
        Rule {
            priority: 0,
            action: Action::Allow,
            source: Some(Cidr::new(from.ip(), if from.is_ipv4() { 32 } else { 128 }).unwrap()),
            destination: Some(Cidr::new(to.ip(), if to.is_ipv4() { 32 } else { 128 }).unwrap()),
            protocol: Some(Protocol::Udp),
            source_port: Some(from.port()..=from.port()),
            destination_port: Some(to.port()..=to.port()),
        }
    }

    #[test]
    fn default_deny_and_terminal_revoke_never_protect() {
        let calls = AtomicUsize::new(0);
        let mut session = UdpSession::new(CountingProtector(&calls)).unwrap();
        let from = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 111, 0, 2)), 40960);
        let to = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 53);
        let packet = udp::encode(from, to, b"test").unwrap();
        assert!(matches!(session.send(&packet, 1), Err(SessionError::Relay(RelayError::Dropped(_)))));
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        session.revoke();
        assert!(!session.is_active());
        assert_eq!(session.flow_count(), 0);
        assert!(matches!(session.send(&packet, 2), Err(SessionError::Revoked)));
        assert!(matches!(session.update_rules(vec![rule(from, to)]), Err(SessionError::Revoked)));
        assert!(matches!(session.reset_network(), Err(SessionError::Revoked)));
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn loopback_response_requires_reverse_rule_and_reset_closes_flows() {
        let calls = AtomicUsize::new(0);
        let mut session = UdpSession::new(CountingProtector(&calls)).unwrap();
        let server = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        server.set_read_timeout(Some(std::time::Duration::from_secs(1))).unwrap();
        let from = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 111, 0, 2)), 40961);
        let to = server.local_addr().unwrap();
        session.update_rules(vec![rule(from, to)]).unwrap();
        let packet = udp::encode(from, to, b"request").unwrap();
        let flow = session.send(&packet, 1).unwrap().flow;
        let mut buf = [0u8; 64];
        let (n, peer) = server.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"request");
        server.send_to(b"response", peer).unwrap();
        let mut denied = false;
        for time in 2..200 {
            match session.receive(flow, time) {
                Err(SessionError::Relay(RelayError::Io(e))) if e.kind() == io::ErrorKind::WouldBlock => {
                    std::thread::sleep(std::time::Duration::from_millis(2));
                }
                Err(SessionError::Relay(RelayError::Dropped(_))) => {
                    denied = true;
                    break;
                }
                other => panic!("unexpected response: {other:?}"),
            }
        }
        assert!(denied);
        assert_eq!(session.flow_count(), 0);
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        session.update_rules(vec![rule(from, to), rule(to, from)]).unwrap();
        let new_flow = session.send(&packet, 250).unwrap().flow;
        let (_, peer) = server.recv_from(&mut buf).unwrap();
        server.send_to(b"accepted", peer).unwrap();
        let mut accepted = false;
        for time in 251..450 {
            match session.receive(new_flow, time) {
                Ok(bytes) => {
                    assert_eq!(&bytes[28..], b"accepted");
                    accepted = true;
                    break;
                }
                Err(SessionError::Relay(RelayError::Io(e))) if e.kind() == io::ErrorKind::WouldBlock => {
                    std::thread::sleep(std::time::Duration::from_millis(2));
                }
                other => panic!("unexpected response: {other:?}"),
            }
        }
        assert!(accepted);
        assert_eq!(session.flow_count(), 1);
        session.reset_network().unwrap();
        assert_eq!(session.flow_count(), 0);
        assert!(matches!(session.receive(new_flow, 500), Err(SessionError::Relay(RelayError::UnknownFlow))));
        session.revoke();
        assert!(matches!(session.receive(new_flow, 501), Err(SessionError::Revoked)));
    }
}
