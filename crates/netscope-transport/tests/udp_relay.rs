use netscope_engine::{Config, DropReason};
use netscope_packet::{parse_checked, udp, ChecksumPolicy};
use netscope_policy::{Action, Policy, Rule};
use netscope_transport::{RelayError, SocketProtector, UdpRelay};
use std::{
    io,
    net::{SocketAddr, UdpSocket},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};
#[derive(Clone)]
struct Protector {
    calls: Arc<AtomicUsize>,
    fail: bool,
}
impl SocketProtector for Protector {
    fn protect(&self, socket: &UdpSocket) -> io::Result<()> {
        assert!(
            socket.peer_addr().is_err(),
            "protection must precede connect"
        );
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.fail {
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "test protection refusal",
            ))
        } else {
            Ok(())
        }
    }
}
fn relay(capacity: usize, default: Action, fail: bool) -> (UdpRelay<Protector>, Arc<AtomicUsize>) {
    let calls = Arc::new(AtomicUsize::new(0));
    (
        UdpRelay::new(
            Policy::new(vec![], default).unwrap(),
            Config {
                max_flows: capacity,
                timeout: 10,
                checksums: ChecksumPolicy::Require,
            },
            1500,
            Protector {
                calls: calls.clone(),
                fail,
            },
        )
        .unwrap(),
        calls,
    )
}
fn request(endpoint: SocketAddr, port: u16, payload: &[u8]) -> Vec<u8> {
    let source = if endpoint.is_ipv4() {
        format!("192.0.2.1:{port}")
    } else {
        format!("[2001:db8::1]:{port}")
    };
    udp::encode(source.parse().unwrap(), endpoint, payload).unwrap()
}
fn echo(endpoint: &str) -> (SocketAddr, std::thread::JoinHandle<()>) {
    let server = UdpSocket::bind(endpoint).unwrap();
    server
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let addr = server.local_addr().unwrap();
    let worker = std::thread::spawn(move || {
        let mut b = [0; 2048];
        let (n, peer) = server.recv_from(&mut b).unwrap();
        server.send_to(&b[..n], peer).unwrap();
    });
    (addr, worker)
}
fn receive(
    r: &mut UdpRelay<Protector>,
    id: netscope_conntrack::FlowId,
) -> Result<Vec<u8>, RelayError> {
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        match r.receive(id, 1) {
            Err(RelayError::Io(e))
                if e.kind() == io::ErrorKind::WouldBlock && Instant::now() < deadline =>
            {
                std::thread::sleep(Duration::from_millis(1))
            }
            other => return other,
        }
    }
}
#[test]
fn ipv4_real_udp_echo_becomes_a_checked_reverse_ip_datagram() {
    let (endpoint, server) = echo("127.0.0.1:0");
    let (mut r, calls) = relay(1, Action::Allow, false);
    let sent = r.send(&request(endpoint, 1234, b"hello"), 0).unwrap();
    assert_eq!(sent.payload_bytes, 5);
    let response = receive(&mut r, sent.flow).unwrap();
    let p = parse_checked(&response, ChecksumPolicy::Require)
        .unwrap()
        .packet;
    assert_eq!(p.source, endpoint.ip());
    assert_eq!(p.source_port, endpoint.port());
    assert_eq!(p.destination_port, 1234);
    assert_eq!(&response[28..], b"hello");
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(r.flow_count(), 1);
    server.join().unwrap();
}
#[test]
fn ipv6_real_udp_echo_becomes_a_checked_reverse_ip_datagram() {
    let (endpoint, server) = echo("[::1]:0");
    let (mut r, _) = relay(1, Action::Allow, false);
    let sent = r.send(&request(endpoint, 1234, b"v6"), 0).unwrap();
    let response = receive(&mut r, sent.flow).unwrap();
    assert_eq!(
        parse_checked(&response, ChecksumPolicy::Require)
            .unwrap()
            .packet
            .destination,
        "2001:db8::1".parse::<std::net::IpAddr>().unwrap()
    );
    assert_eq!(&response[48..], b"v6");
    server.join().unwrap();
}
#[test]
fn denied_invalid_and_protection_failure_never_send() {
    let server = UdpSocket::bind("127.0.0.1:0").unwrap();
    server.set_nonblocking(true).unwrap();
    let b = request(server.local_addr().unwrap(), 1234, b"no");
    let (mut denied, calls) = relay(1, Action::Deny, false);
    assert!(matches!(
        denied.send(&b, 0),
        Err(RelayError::Dropped(DropReason::Policy { .. }))
    ));
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    let (mut invalid, calls) = relay(1, Action::Allow, false);
    let mut corrupt = b.clone();
    *corrupt.last_mut().unwrap() ^= 1;
    assert!(invalid.send(&corrupt, 0).is_err());
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    let (mut failed, calls) = relay(1, Action::Allow, true);
    assert!(
        matches!(failed.send(&b,0),Err(RelayError::Io(e)) if e.kind()==io::ErrorKind::PermissionDenied)
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(failed.flow_count(), 0);
    assert_eq!(failed.stats().accepted, 1); // admission is not delivery
    let mut received = [0; 10];
    assert_eq!(
        server.recv_from(&mut received).unwrap_err().kind(),
        io::ErrorKind::WouldBlock
    );
}
#[test]
fn expiry_capacity_policy_transactions_and_network_reset_release_sockets() {
    let server = UdpSocket::bind("127.0.0.1:0").unwrap();
    let endpoint = server.local_addr().unwrap();
    let (mut r, calls) = relay(1, Action::Allow, false);
    let first = r.send(&request(endpoint, 1, b"a"), 0).unwrap();
    assert!(matches!(
        r.send(&request(endpoint, 2, b"b"), 1),
        Err(RelayError::Dropped(DropReason::FlowCapacity))
    ));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(r.expire(10).unwrap(), 1);
    assert_eq!(r.flow_count(), 0);
    assert!(matches!(
        r.receive(first.flow, 10),
        Err(RelayError::UnknownFlow)
    ));
    r.send(&request(endpoint, 2, b"b"), 10).unwrap();
    let invalid = Rule {
        priority: 0,
        action: Action::Deny,
        source: None,
        destination: None,
        protocol: None,
        source_port: Some(std::ops::RangeInclusive::new(9, 1)),
        destination_port: None,
    };
    assert!(r.update_policy(vec![invalid], Action::Deny).is_err());
    assert_eq!(r.flow_count(), 1);
    r.update_policy(vec![], Action::Deny).unwrap();
    assert_eq!(r.flow_count(), 0);
    assert!(r.send(&request(endpoint, 2, b"b"), 10).is_err());
    r.update_policy(vec![], Action::Allow).unwrap();
    r.send(&request(endpoint, 3, b"c"), 10).unwrap();
    r.reset_network();
    assert_eq!(r.flow_count(), 0);
    assert!(matches!(
        r.send(&request(endpoint, 3, b"c"), 9),
        Err(RelayError::Dropped(DropReason::ClockReversed))
    ));
}
#[test]
fn inbound_policy_is_checked_before_releasing_response() {
    let (endpoint, server) = echo("127.0.0.1:0");
    let (mut r, _) = relay(1, Action::Deny, false);
    let outbound = Rule {
        priority: 0,
        action: Action::Allow,
        source: None,
        destination: None,
        protocol: None,
        source_port: Some(1234..=1234),
        destination_port: Some(endpoint.port()..=endpoint.port()),
    };
    r.update_policy(vec![outbound], Action::Deny).unwrap();
    let sent = r
        .send(&request(endpoint, 1234, b"deny response"), 0)
        .unwrap();
    assert!(matches!(
        receive(&mut r, sent.flow),
        Err(RelayError::Dropped(DropReason::Policy { .. }))
    ));
    assert_eq!(r.flow_count(), 0);
    server.join().unwrap();
}
#[test]
fn unsupported_aliases_and_mtu_are_rejected_before_opening_sockets() {
    let (mut r, calls) = relay(1, Action::Allow, false);
    for endpoint in [
        "0.0.0.0:53",
        "255.255.255.255:53",
        "224.0.0.1:53",
        "[::]:53",
        "[::ffff:127.0.0.1]:53",
        "[fe80::1]:53",
        "[ff02::1]:53",
        "127.0.0.1:0",
    ] {
        assert!(matches!(
            r.send(&request(endpoint.parse().unwrap(), 1234, b"a"), 0),
            Err(RelayError::UnsupportedAddress)
        ));
    }
    assert!(matches!(
        r.send(
            &request("127.0.0.1:53".parse().unwrap(), 1234, &[0; 1500]),
            0
        ),
        Err(RelayError::MtuExceeded)
    ));
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert_eq!(r.flow_count(), 0);
}
#[test]
fn oversized_reply_is_dropped_instead_of_fragmented_or_truncated() {
    let server = UdpSocket::bind("127.0.0.1:0").unwrap();
    server
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let endpoint = server.local_addr().unwrap();
    let worker = std::thread::spawn(move || {
        let mut b = [0; 100];
        let (_, peer) = server.recv_from(&mut b).unwrap();
        server.send_to(&[0; 1600], peer).unwrap();
        server.send_to(b"ok", peer).unwrap();
    });
    let (mut r, _) = relay(1, Action::Allow, false);
    let sent = r.send(&request(endpoint, 1, b"a"), 0).unwrap();
    assert!(matches!(
        receive(&mut r, sent.flow),
        Err(RelayError::MtuExceeded)
    ));
    // Only the oversized datagram is lost; the flow keeps working.
    assert_eq!(r.flow_count(), 1);
    assert_eq!(&receive(&mut r, sent.flow).unwrap()[28..], b"ok");
    worker.join().unwrap();
}
#[test]
fn authorized_replies_extend_the_idle_lease_but_silence_still_expires() {
    let server = UdpSocket::bind("127.0.0.1:0").unwrap();
    let endpoint = server.local_addr().unwrap();
    let (mut r, _) = relay(1, Action::Allow, false); // idle timeout is 10 ticks
    let sent = r.send(&request(endpoint, 1, b"a"), 0).unwrap();
    let mut buffer = [0; 20];
    let (_, peer) = server.recv_from(&mut buffer).unwrap();
    server.send_to(b"r1", peer).unwrap();
    let deadline = Instant::now() + Duration::from_secs(2);
    let reply = loop {
        match r.receive(sent.flow, 9) {
            Err(RelayError::Io(e)) if e.kind() == io::ErrorKind::WouldBlock => {
                assert!(Instant::now() < deadline);
                std::thread::sleep(Duration::from_millis(1));
            }
            other => break other.unwrap(),
        }
    };
    assert_eq!(&reply[28..], b"r1");
    // Without the reply the flow would have expired at tick 10.
    assert_eq!(r.expire(18).unwrap(), 0);
    assert_eq!(r.flow_count(), 1);
    assert_eq!(r.expire(19).unwrap(), 1);
    assert_eq!(r.flow_count(), 0);
}

#[test]
fn empty_datagrams_and_same_flow_socket_reuse_are_preserved() {
    let server = UdpSocket::bind("127.0.0.1:0").unwrap();
    server
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let endpoint = server.local_addr().unwrap();
    let (mut r, calls) = relay(1, Action::Allow, false);
    let first = r.send(&request(endpoint, 1234, b""), 0).unwrap();
    assert_eq!(first.payload_bytes, 0);
    r.send(&request(endpoint, 1234, b"second"), 1).unwrap();
    let mut buffer = [0; 20];
    let (count, peer) = server.recv_from(&mut buffer).unwrap();
    assert_eq!(count, 0);
    let (count, peer2) = server.recv_from(&mut buffer).unwrap();
    assert_eq!(&buffer[..count], b"second");
    assert_eq!(peer, peer2);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(r.flow_count(), 1);
    server.send_to(b"", peer).unwrap();
    let response = receive(&mut r, first.flow).unwrap();
    assert_eq!(response.len(), 28);
    assert!(parse_checked(&response, ChecksumPolicy::Require).is_ok());
}
#[test]
fn relay_configuration_and_zero_capacity_do_not_allocate_sockets() {
    for (capacity, mtu) in [(1025, 1500), (1, 1279), (1, 65576)] {
        let protector = Protector {
            calls: Arc::new(AtomicUsize::new(0)),
            fail: false,
        };
        assert!(matches!(
            UdpRelay::new(
                Policy::new(vec![], Action::Allow).unwrap(),
                Config {
                    max_flows: capacity,
                    timeout: 10,
                    checksums: ChecksumPolicy::Require
                },
                mtu,
                protector
            ),
            Err(RelayError::Config)
        ));
    }
    let (mut r, calls) = relay(0, Action::Allow, false);
    assert!(matches!(
        r.send(&request("127.0.0.1:53".parse().unwrap(), 1, b"a"), 0),
        Err(RelayError::Dropped(DropReason::FlowCapacity))
    ));
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}
#[cfg(unix)]
#[test]
fn wait_ready_reports_only_flows_with_a_datagram_and_honors_deadlines() {
    let quiet = UdpSocket::bind("127.0.0.1:0").unwrap();
    let talkative = UdpSocket::bind("127.0.0.1:0").unwrap();
    let (mut r, _) = {
        let calls = Arc::new(AtomicUsize::new(0));
        (
            UdpRelay::new(
                Policy::new(vec![], Action::Allow).unwrap(),
                Config {
                    max_flows: 2,
                    timeout: 400, // milliseconds for wait_ready
                    checksums: ChecksumPolicy::Require,
                },
                1500,
                Protector {
                    calls: calls.clone(),
                    fail: false,
                },
            )
            .unwrap(),
            calls,
        )
    };
    let quiet_flow = r
        .send(&request(quiet.local_addr().unwrap(), 1, b"q"), 0)
        .unwrap()
        .flow;
    let talk_flow = r
        .send(&request(talkative.local_addr().unwrap(), 2, b"t"), 0)
        .unwrap()
        .flow;
    // No datagram yet: the wait runs to the caller's cap.
    let started = Instant::now();
    assert!(r
        .wait_ready(1, Duration::from_millis(60))
        .unwrap()
        .is_empty());
    assert!(started.elapsed() >= Duration::from_millis(50));
    assert!(started.elapsed() < Duration::from_secs(2));
    // One server replies while we wait: only that flow is reported, long before the cap.
    let mut buffer = [0; 16];
    let (_, peer) = talkative.recv_from(&mut buffer).unwrap();
    let replier = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(30));
        talkative.send_to(b"pong", peer).unwrap();
    });
    let started = Instant::now();
    let ready = r.wait_ready(1, Duration::from_secs(5)).unwrap();
    assert_eq!(ready, vec![talk_flow]);
    assert!(started.elapsed() < Duration::from_secs(3));
    replier.join().unwrap();
    assert_eq!(&r.receive(talk_flow, 1).unwrap()[28..], b"pong");
    assert!(matches!(
        r.receive(quiet_flow, 1),
        Err(RelayError::Io(e)) if e.kind() == io::ErrorKind::WouldBlock
    ));
    // The oldest flow's idle deadline bounds the wait, and the expired sockets are released.
    let started = Instant::now();
    assert!(r
        .wait_ready(300, Duration::from_secs(60))
        .unwrap()
        .is_empty());
    assert!(
        started.elapsed() < Duration::from_secs(3),
        "ignored idle deadline"
    );
    // The silent flow expires at 400; the one that got a reply at 1 is refreshed to 401.
    assert!(r
        .wait_ready(400, Duration::from_millis(1))
        .unwrap()
        .is_empty());
    assert_eq!(r.flow_count(), 1);
    assert!(r
        .wait_ready(401, Duration::from_millis(1))
        .unwrap()
        .is_empty());
    assert_eq!(r.flow_count(), 0);
}
