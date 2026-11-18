use netscope_conntrack::FlowId;
use netscope_dns::{DomainName, DomainPolicy, Match, Rule};
use netscope_engine::{Config, DropReason};
use netscope_packet::{udp, ChecksumPolicy};
use netscope_policy::{Action, Policy};
use netscope_transport::{DnsError, DnsLimits, RelayError, SocketProtector, UdpRelay};
use std::{
    io,
    net::{SocketAddr, UdpSocket},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};
struct Protector(Arc<AtomicUsize>);
impl SocketProtector for Protector {
    fn protect(&self, socket: &UdpSocket) -> io::Result<()> {
        assert!(socket.peer_addr().is_err());
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}
fn policy() -> DomainPolicy {
    DomainPolicy::new(
        vec![Rule {
            name: DomainName::new("blocked.example").unwrap(),
            kind: Match::DomainAndSubdomains,
            priority: 0,
            action: Action::Deny,
        }],
        Action::Allow,
    )
    .unwrap()
}
fn relay(endpoint: SocketAddr, action: Action) -> (UdpRelay<Protector>, Arc<AtomicUsize>) {
    let calls = Arc::new(AtomicUsize::new(0));
    let mut r = UdpRelay::new(
        Policy::new(vec![], action).unwrap(),
        Config {
            max_flows: 4,
            timeout: 10,
            checksums: ChecksumPolicy::Require,
        },
        1500,
        Protector(calls.clone()),
    )
    .unwrap();
    r.set_dns_filter(Some(policy()), vec![endpoint.port()])
        .unwrap();
    (r, calls)
}
fn query(name: &str, id: u16) -> Vec<u8> {
    let mut b = vec![0; 12];
    b[..2].copy_from_slice(&id.to_be_bytes());
    b[2] = 1;
    b[5] = 1;
    for label in name.split('.') {
        b.push(label.len() as u8);
        b.extend_from_slice(label.as_bytes());
    }
    b.extend_from_slice(&[0, 0, 1, 0, 1]);
    b
}
fn datagram(endpoint: SocketAddr, dns: &[u8]) -> Vec<u8> {
    let source = if endpoint.is_ipv4() {
        "192.0.2.1:1234"
    } else {
        "[2001:db8::1]:1234"
    };
    udp::encode(source.parse().unwrap(), endpoint, dns).unwrap()
}
fn server(address: &str) -> UdpSocket {
    let s = UdpSocket::bind(address).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    s
}
fn response(mut b: Vec<u8>) -> Vec<u8> {
    b[2..4].copy_from_slice(&0x8180u16.to_be_bytes());
    b
}
fn receive(r: &mut UdpRelay<Protector>, flow: FlowId) -> Result<Vec<u8>, RelayError> {
    receive_at(r, flow, 1)
}
fn receive_at(r: &mut UdpRelay<Protector>, flow: FlowId, now: u64) -> Result<Vec<u8>, RelayError> {
    let until = Instant::now() + Duration::from_secs(2);
    loop {
        match r.receive(flow, now) {
            Err(RelayError::Io(e))
                if e.kind() == io::ErrorKind::WouldBlock && Instant::now() < until =>
            {
                std::thread::sleep(Duration::from_millis(1))
            }
            value => return value,
        }
    }
}
/// IPv6 loopback may be missing in containers. CI sets NETSCOPE_REQUIRE_IPV6 so a missing
/// loopback there fails the test instead of silently skipping it.
fn ipv6_loopback_available() -> bool {
    std::env::var_os("NETSCOPE_REQUIRE_IPV6").is_some()
        || std::net::UdpSocket::bind("[::1]:0").is_ok()
}
#[test]
fn blocked_and_malformed_dns_are_not_sent_or_allocated() {
    let s = server("127.0.0.1:0");
    s.set_nonblocking(true).unwrap();
    let endpoint = s.local_addr().unwrap();
    let (mut r, calls) = relay(endpoint, Action::Allow);
    for name in ["blocked.example", "a.BLOCKED.example"] {
        assert!(matches!(
            r.send(&datagram(endpoint, &query(name, 1)), 0),
            Err(RelayError::Dns(DnsError::DomainDenied {
                rule_index: Some(0)
            }))
        ));
    }
    assert!(matches!(
        r.send(&datagram(endpoint, b"bad"), 0),
        Err(RelayError::Dns(DnsError::Malformed(_)))
    ));
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert_eq!(r.flow_count(), 0);
    assert_eq!(r.pending_dns_count(), 0);
    let mut b = [0; 100];
    assert_eq!(
        s.recv_from(&mut b).unwrap_err().kind(),
        io::ErrorKind::WouldBlock
    );
}
#[test]
fn ipv4_and_ipv6_dns_round_trip_consumes_exact_pending_question() {
    if !ipv6_loopback_available() {
        eprintln!("skipped: no IPv6 loopback in this environment (set NETSCOPE_REQUIRE_IPV6=1 to fail instead)");
        return;
    }
    for address in ["127.0.0.1:0", "[::1]:0"] {
        let s = server(address);
        let endpoint = s.local_addr().unwrap();
        let (mut r, calls) = relay(endpoint, Action::Allow);
        let q = query("safe.example", 0x1234);
        let sent = r.send(&datagram(endpoint, &q), 0).unwrap();
        assert_eq!(r.pending_dns_count(), 1);
        let mut b = [0; 1024];
        let (n, peer) = s.recv_from(&mut b).unwrap();
        assert_eq!(&b[..n], q);
        s.send_to(&response(b[..n].to_vec()), peer).unwrap();
        let bytes = receive(&mut r, sent.flow).unwrap();
        let offset = if endpoint.is_ipv4() { 28 } else { 48 };
        assert_eq!(&bytes[offset..], response(q));
        assert_eq!(r.pending_dns_count(), 0);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }
}
#[test]
fn wrong_id_wrong_question_and_query_as_response_are_rejected() {
    for mutation in 0..5 {
        let s = server("127.0.0.1:0");
        let endpoint = s.local_addr().unwrap();
        let (mut r, _) = relay(endpoint, Action::Allow);
        let q = query("safe.example", 0x1234);
        let sent = r.send(&datagram(endpoint, &q), 0).unwrap();
        let mut b = [0; 1024];
        let (n, peer) = s.recv_from(&mut b).unwrap();
        let mut answer = response(b[..n].to_vec());
        match mutation {
            0 => answer[1] ^= 1,
            1 => answer[13] = b'z',
            2 => {
                let end = answer.len();
                answer[end - 3] = 28;
            }
            3 => {
                let end = answer.len();
                answer[end - 1] = 3;
            }
            _ => answer[2] &= 0x7f,
        }
        s.send_to(&answer, peer).unwrap();
        assert!(matches!(
            receive(&mut r, sent.flow),
            Err(RelayError::Dns(
                DnsError::Unsolicited | DnsError::Mismatched | DnsError::Malformed(_)
            ))
        ));
        assert_eq!(r.pending_dns_count(), 1);
        assert_eq!(r.flow_count(), 1);
        // A bad answer must not destroy the still-valid transaction.
        s.send_to(&response(q), peer).unwrap();
        assert!(receive(&mut r, sent.flow).is_ok());
        assert_eq!(r.pending_dns_count(), 0);
    }
}
#[test]
fn retransmission_is_bounded_and_same_id_different_question_is_busy() {
    let s = server("127.0.0.1:0");
    let endpoint = s.local_addr().unwrap();
    let (mut r, calls) = relay(endpoint, Action::Allow);
    let q = query("safe.example", 1);
    let sent = r.send(&datagram(endpoint, &q), 0).unwrap();
    r.send(&datagram(endpoint, &q), 0).unwrap();
    assert_eq!(r.pending_dns_count(), 1);
    assert!(matches!(
        r.send(&datagram(endpoint, &query("different.example", 1)), 0),
        Err(RelayError::Dns(DnsError::Busy))
    ));
    assert_eq!(r.flow_count(), 1);
    assert_eq!(r.pending_dns_count(), 1);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert!(r.set_dns_filter(Some(policy()), vec![]).is_err());
    assert_eq!(r.pending_dns_count(), 1);
    assert_eq!(r.expire(10).unwrap(), 1);
    assert_eq!(r.pending_dns_count(), 0);
    assert!(matches!(
        r.receive(sent.flow, 10),
        Err(RelayError::UnknownFlow)
    ));
    r.send(&datagram(endpoint, &query("safe.example", 2)), 10)
        .unwrap();
    r.set_dns_filter(Some(policy()), vec![endpoint.port()])
        .unwrap();
    assert_eq!(r.pending_dns_count(), 0);
    assert_eq!(r.flow_count(), 0);
    r.send(&datagram(endpoint, &query("safe.example", 3)), 10)
        .unwrap();
    r.reset_network();
    assert_eq!(r.pending_dns_count(), 0);
}
#[test]
fn domain_allow_does_not_override_ip_policy_and_ports_are_explicit() {
    let s = server("127.0.0.1:0");
    let endpoint = s.local_addr().unwrap();
    let (mut r, calls) = relay(endpoint, Action::Deny);
    assert!(matches!(
        r.send(&datagram(endpoint, &query("safe.example", 1)), 0),
        Err(RelayError::Dropped(DropReason::Policy { .. }))
    ));
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    let (mut r, _) = relay(endpoint, Action::Allow);
    r.set_dns_filter(
        Some(policy()),
        vec![if endpoint.port() == 53 { 54 } else { 53 }],
    )
    .unwrap();
    r.send(&datagram(endpoint, b"opaque non-DNS payload"), 0)
        .unwrap();
    assert_eq!(r.pending_dns_count(), 0);
    assert!(r.set_dns_filter(Some(policy()), vec![0]).is_err());
    assert!(r.set_dns_filter(Some(policy()), vec![53, 53]).is_err());
    assert!(r.set_dns_filter(Some(policy()), vec![1; 33]).is_err());
    assert!(r.set_dns_filter(None, vec![53]).is_err());
    assert_eq!(r.flow_count(), 1);
    r.set_dns_filter(None, vec![]).unwrap();
    assert_eq!(r.flow_count(), 0);
}
#[test]
fn a_second_unsolicited_answer_cannot_reuse_consumed_transaction() {
    let s = server("127.0.0.1:0");
    let endpoint = s.local_addr().unwrap();
    let (mut r, _) = relay(endpoint, Action::Allow);
    let sent = r
        .send(&datagram(endpoint, &query("safe.example", 1)), 0)
        .unwrap();
    let mut b = [0; 1024];
    let (n, peer) = s.recv_from(&mut b).unwrap();
    let answer = response(b[..n].to_vec());
    s.send_to(&answer, peer).unwrap();
    assert!(receive(&mut r, sent.flow).is_ok());
    s.send_to(&answer, peer).unwrap();
    assert!(matches!(
        receive(&mut r, sent.flow),
        Err(RelayError::Dns(DnsError::Unsolicited))
    ));
    assert_eq!(r.flow_count(), 1);
    assert_eq!(r.pending_dns_count(), 0);
}

#[test]
fn concurrent_ipv4_ipv6_queries_share_socket_and_complete_out_of_order() {
    if !ipv6_loopback_available() {
        eprintln!("skipped: no IPv6 loopback in this environment (set NETSCOPE_REQUIRE_IPV6=1 to fail instead)");
        return;
    }
    for address in ["127.0.0.1:0", "[::1]:0"] {
        let s = server(address);
        let endpoint = s.local_addr().unwrap();
        let (mut r, calls) = relay(endpoint, Action::Allow);
        let a = query("first.example", 1);
        let b = query("second.example", 2);
        let sent = r.send(&datagram(endpoint, &a), 0).unwrap();
        assert_eq!(r.send(&datagram(endpoint, &b), 0).unwrap().flow, sent.flow);
        assert_eq!(r.pending_dns_count(), 2);
        let mut buffer = [0; 1024];
        let (_, first_peer) = s.recv_from(&mut buffer).unwrap();
        let (_, second_peer) = s.recv_from(&mut buffer).unwrap();
        assert_eq!(first_peer, second_peer);
        let offset = if endpoint.is_ipv4() { 28 } else { 48 };
        s.send_to(&response(b.clone()), first_peer).unwrap();
        assert_eq!(&receive(&mut r, sent.flow).unwrap()[offset..], response(b));
        assert_eq!(r.pending_dns_count(), 1);
        s.send_to(&response(a.clone()), first_peer).unwrap();
        assert_eq!(&receive(&mut r, sent.flow).unwrap()[offset..], response(a));
        assert_eq!(r.pending_dns_count(), 0);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }
}

#[test]
fn independent_deadlines_survive_retries_late_answers_and_clock_reversal() {
    let s = server("127.0.0.1:0");
    let endpoint = s.local_addr().unwrap();
    let (mut r, _) = relay(endpoint, Action::Allow);
    r.set_dns_limits(DnsLimits {
        max_pending_per_flow: 2,
        max_pending_total: 2,
        query_timeout: 3,
    })
    .unwrap();
    let a = query("first.example", 1);
    let b = query("second.example", 2);
    let sent = r.send(&datagram(endpoint, &a), 0).unwrap();
    let mut buffer = [0; 1024];
    let (_, peer) = s.recv_from(&mut buffer).unwrap();
    r.send(&datagram(endpoint, &a), 2).unwrap(); // retry must not extend first deadline
    r.send(&datagram(endpoint, &b), 2).unwrap();
    assert_eq!(r.pending_dns_count(), 2);
    assert_eq!(r.expire(3).unwrap(), 0); // flow is live, only query A expires
    assert_eq!(r.pending_dns_count(), 1);
    assert!(matches!(
        r.expire(2),
        Err(RelayError::Dropped(DropReason::ClockReversed))
    ));
    assert_eq!(r.pending_dns_count(), 1);
    s.send_to(&response(a.clone()), peer).unwrap();
    assert!(matches!(
        receive_at(&mut r, sent.flow, 3),
        Err(RelayError::Dns(DnsError::Unsolicited))
    ));
    assert_eq!(r.pending_dns_count(), 1);
    // Reusing an expired ID with a new question must not accept its old response.
    let replacement = query("replacement.example", 1);
    r.send(&datagram(endpoint, &replacement), 3).unwrap();
    s.send_to(&response(a), peer).unwrap();
    assert!(matches!(
        receive_at(&mut r, sent.flow, 3),
        Err(RelayError::Dns(DnsError::Mismatched))
    ));
    assert_eq!(r.pending_dns_count(), 2);
    s.send_to(&response(b), peer).unwrap();
    assert!(receive_at(&mut r, sent.flow, 3).is_ok());
    assert_eq!(r.pending_dns_count(), 1);
    r.expire(6).unwrap();
    assert_eq!(r.pending_dns_count(), 0);
    assert_eq!(r.flow_count(), 1);
}

#[test]
fn per_flow_global_caps_and_atomic_limit_configuration() {
    let s = server("127.0.0.1:0");
    let endpoint = s.local_addr().unwrap();
    let (mut r, calls) = relay(endpoint, Action::Allow);
    let limits = DnsLimits {
        max_pending_per_flow: 1,
        max_pending_total: 2,
        query_timeout: 3,
    };
    r.set_dns_limits(limits).unwrap();
    let packet = |port, id| {
        udp::encode(
            format!("192.0.2.1:{port}").parse().unwrap(),
            endpoint,
            &query("safe.example", id),
        )
        .unwrap()
    };
    let first = r.send(&packet(1234, 1), 0).unwrap();
    assert!(matches!(
        r.send(&packet(1234, 2), 0),
        Err(RelayError::Dns(DnsError::Capacity))
    ));
    r.send(&packet(1235, 1), 0).unwrap();
    assert!(matches!(
        r.send(&packet(1236, 1), 0),
        Err(RelayError::Dns(DnsError::Capacity))
    ));
    // Retries at capacity do not allocate another slot.
    r.send(&packet(1234, 1), 1).unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    assert_eq!(r.flow_count(), 2);
    assert_eq!(r.pending_dns_count(), 2);
    for bad in [
        DnsLimits {
            max_pending_per_flow: 0,
            ..limits
        },
        DnsLimits {
            max_pending_per_flow: 65,
            ..limits
        },
        DnsLimits {
            max_pending_total: 0,
            ..limits
        },
        DnsLimits {
            max_pending_total: 4097,
            ..limits
        },
        DnsLimits {
            query_timeout: 0,
            ..limits
        },
    ] {
        assert!(matches!(r.set_dns_limits(bad), Err(RelayError::Config)));
        assert_eq!(r.pending_dns_count(), 2);
        assert_eq!(r.flow_count(), 2);
    }
    r.expire(3).unwrap();
    assert_eq!(r.pending_dns_count(), 0);
    assert_eq!(r.flow_count(), 2);
    r.send(&packet(1234, 2), 3).unwrap();
    r.set_dns_limits(limits).unwrap();
    assert_eq!(r.pending_dns_count(), 0);
    assert_eq!(r.flow_count(), 0);
    assert!(matches!(
        r.receive(first.flow, 3),
        Err(RelayError::UnknownFlow)
    ));
}

#[test]
fn pending_queries_require_successful_protection_and_current_packet_policy() {
    struct Refuse;
    impl SocketProtector for Refuse {
        fn protect(&self, _: &UdpSocket) -> io::Result<()> {
            Err(io::Error::other("refused"))
        }
    }
    let s = server("127.0.0.1:0");
    let endpoint = s.local_addr().unwrap();
    let mut denied = UdpRelay::new(
        Policy::new(vec![], Action::Allow).unwrap(),
        Config {
            max_flows: 4,
            timeout: 10,
            checksums: ChecksumPolicy::Require,
        },
        1500,
        Refuse,
    )
    .unwrap();
    denied
        .set_dns_filter(Some(policy()), vec![endpoint.port()])
        .unwrap();
    assert!(matches!(
        denied.send(&datagram(endpoint, &query("safe.example", 1)), 0),
        Err(RelayError::Io(_))
    ));
    assert_eq!(denied.pending_dns_count(), 0);
    assert_eq!(denied.flow_count(), 0);

    let (mut r, _) = relay(endpoint, Action::Allow);
    let sent = r
        .send(&datagram(endpoint, &query("first.example", 1)), 0)
        .unwrap();
    r.send(&datagram(endpoint, &query("second.example", 2)), 0)
        .unwrap();
    // Invalid packet-policy replacement retains both waiting requests.
    let invalid = netscope_policy::Rule {
        source_port: Some(std::ops::RangeInclusive::new(9, 1)),
        priority: 0,
        action: Action::Deny,
        source: None,
        destination: None,
        protocol: None,
        destination_port: None,
    };
    assert!(r.update_policy(vec![invalid], Action::Deny).is_err());
    assert_eq!(r.pending_dns_count(), 2);
    r.update_policy(vec![], Action::Deny).unwrap();
    assert_eq!(r.pending_dns_count(), 0);
    assert_eq!(r.flow_count(), 0);
    assert!(matches!(
        r.receive(sent.flow, 1),
        Err(RelayError::UnknownFlow)
    ));
}
