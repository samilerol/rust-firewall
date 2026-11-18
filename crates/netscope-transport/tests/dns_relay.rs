use netscope_conntrack::FlowId;
use netscope_dns::{DomainName, DomainPolicy, Match, Rule};
use netscope_engine::{Config, DropReason};
use netscope_packet::{udp, ChecksumPolicy};
use netscope_policy::{Action, Policy};
use netscope_transport::{DnsError, RelayError, SocketProtector, UdpRelay};
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
    let until = Instant::now() + Duration::from_secs(2);
    loop {
        match r.receive(flow, 1) {
            Err(RelayError::Io(e))
                if e.kind() == io::ErrorKind::WouldBlock && Instant::now() < until =>
            {
                std::thread::sleep(Duration::from_millis(1))
            }
            value => return value,
        }
    }
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
                DnsError::Mismatched | DnsError::Malformed(_)
            ))
        ));
        assert_eq!(r.pending_dns_count(), 0);
        assert_eq!(r.flow_count(), 0);
    }
}
#[test]
fn retransmission_is_bounded_and_distinct_concurrent_question_is_busy() {
    let s = server("127.0.0.1:0");
    let endpoint = s.local_addr().unwrap();
    let (mut r, calls) = relay(endpoint, Action::Allow);
    let q = query("safe.example", 1);
    let sent = r.send(&datagram(endpoint, &q), 0).unwrap();
    r.send(&datagram(endpoint, &q), 0).unwrap();
    assert_eq!(r.pending_dns_count(), 1);
    assert!(matches!(
        r.send(&datagram(endpoint, &query("safe.example", 2)), 0),
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
    // The duplicate is discarded without revoking the flow, which stays usable.
    assert_eq!(r.flow_count(), 1);
    r.send(&datagram(endpoint, &query("safe.example", 2)), 1)
        .unwrap();
    let (n, peer) = s.recv_from(&mut b).unwrap();
    s.send_to(&response(b[..n].to_vec()), peer).unwrap();
    assert!(receive(&mut r, sent.flow).is_ok());
}
