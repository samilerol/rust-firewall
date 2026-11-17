use super::*;
use crate::DnsLimits;
use netscope_dns::{DomainName, DomainPolicy, Match, Rule as DomainRule};
fn domain_policy() -> DomainPolicy {
    DomainPolicy::new(
        vec![DomainRule {
            name: DomainName::new("blocked.example").unwrap(),
            kind: Match::DomainAndSubdomains,
            priority: 0,
            action: Action::Deny,
        }],
        Action::Allow,
    )
    .unwrap()
}
fn query(name: &str, id: u16, size: usize) -> Vec<u8> {
    let mut b = vec![0; 12];
    b[..2].copy_from_slice(&id.to_be_bytes());
    b[2] = 1;
    b[5] = 1;
    for label in name.split('.') {
        b.push(label.len() as u8);
        b.extend_from_slice(label.as_bytes());
    }
    b.extend_from_slice(&[0, 0, 1, 0, 1]);
    if size > b.len() {
        let rdlen = size - b.len() - 11;
        b[11] = 1;
        b.extend_from_slice(&[0, 0, 41, 4, 208, 0, 0, 0, 0]);
        b.extend_from_slice(&(rdlen as u16).to_be_bytes());
        b.extend_from_slice(&65001u16.to_be_bytes());
        b.extend_from_slice(&((rdlen - 4) as u16).to_be_bytes());
        b.resize(size, 0);
    }
    assert!(netscope_dns::parse_query(&b).is_ok());
    b
}
fn answer(mut query: Vec<u8>) -> Vec<u8> {
    query[2..4].copy_from_slice(&0x8180u16.to_be_bytes());
    query
}
fn framed(body: &[u8]) -> Vec<u8> {
    let mut frame = (body.len() as u16).to_be_bytes().to_vec();
    frame.extend_from_slice(body);
    frame
}
struct Harness {
    relay: TcpRelay<Protector>,
    client: Client,
    server: TcpStream,
    now: u64,
    received: Vec<u8>,
}
impl Harness {
    fn new(address: &str) -> Self {
        Self::with_limits(address, None)
    }
    fn with_limits(address: &str, limits: Option<DnsLimits>) -> Self {
        Self::build(address, limits, true)
    }
    fn build(address: &str, limits: Option<DnsLimits>, selected: bool) -> Self {
        let listener = TcpListener::bind(address).unwrap();
        listener.set_nonblocking(true).unwrap();
        let mut client = Client::new(listener.local_addr().unwrap());
        let mut cfg = config();
        cfg.buffer_bytes = 1024;
        cfg.output_slots = 1;
        let mut relay = TcpRelay::new(
            Policy::new(vec![], Action::Allow).unwrap(),
            cfg,
            Protector {
                calls: Arc::new(AtomicUsize::new(0)),
                fail: false,
            },
        )
        .unwrap();
        if let Some(limits) = limits {
            relay.set_dns_limits(limits).unwrap();
        }
        relay
            .set_dns_filter(
                Some(domain_policy()),
                vec![if selected {
                    client.destination.port()
                } else if client.destination.port() == 53 {
                    54
                } else {
                    53
                }],
            )
            .unwrap();
        let mut server = None;
        let mut now = 0;
        let deadline = Wall::now() + Duration::from_secs(4);
        while Wall::now() < deadline {
            client.step(&mut relay, now);
            if server.is_none() {
                match listener.accept() {
                    Ok((s, _)) => {
                        s.set_nonblocking(true).unwrap();
                        server = Some(s);
                    }
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => (),
                    Err(e) => panic!("accept {e}"),
                }
            }
            if server.is_some() && client.sockets.get::<StackSocket>(client.handle).can_send() {
                break;
            }
            now += 1;
            std::thread::sleep(Duration::from_millis(1));
        }
        assert!(client.sockets.get::<StackSocket>(client.handle).can_send());
        Self {
            relay,
            client,
            server: server.expect("protected upstream connection"),
            now,
            received: vec![],
        }
    }
    fn send(&mut self, bytes: &[u8]) {
        assert_eq!(
            self.client
                .sockets
                .get_mut::<StackSocket>(self.client.handle)
                .send_slice(bytes)
                .unwrap(),
            bytes.len()
        );
    }
    fn tick(&mut self) -> PollReport {
        self.now += 1;
        let report = self.client.step(&mut self.relay, self.now);
        let socket = self
            .client
            .sockets
            .get_mut::<StackSocket>(self.client.handle);
        if socket.can_recv() {
            socket
                .recv(|bytes| {
                    self.received.extend_from_slice(bytes);
                    (bytes.len(), ())
                })
                .unwrap();
        }
        assert!(self.relay.buffers().reserved_payload_bytes <= config().buffer_budget);
        assert!(self.relay.buffers().dns_frame_bytes <= 2 * dns::FRAME_BYTES);
        report
    }
    fn until(&mut self, mut predicate: impl FnMut(&mut Self, PollReport) -> bool) {
        let deadline = Wall::now() + Duration::from_secs(4);
        while Wall::now() < deadline {
            let report = self.tick();
            if predicate(self, report) {
                return;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        panic!("DNS stream did not reach expected state");
    }
    fn upstream_bytes(&mut self) -> Vec<u8> {
        let mut result = vec![];
        let mut buffer = [0; 8192];
        loop {
            match self.server.read(&mut buffer) {
                Ok(0) => break,
                Ok(n) => result.extend_from_slice(&buffer[..n]),
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::ConnectionReset
                    ) =>
                {
                    break
                }
                Err(e) => panic!("server read: {e}"),
            }
        }
        result
    }
    fn take_queries(&mut self, expected: &[u8]) {
        let mut got = vec![];
        self.until(|h, report| {
            assert_eq!(report.dns_failures, 0);
            got.extend(h.upstream_bytes());
            got.len() >= expected.len()
        });
        assert_eq!(got, expected);
    }
}
#[test]
fn ipv4_ipv6_fragmented_pipeline_out_of_order_and_large_frames() {
    for address in ["127.0.0.1:0", "[::1]:0"] {
        let mut h = Harness::new(address);
        let a = query("safe.example", 1, 4096);
        let b = query("other.example", 2, 0);
        let mut requests = framed(&a);
        requests.extend(framed(&b));
        h.send(&requests[..1]);
        for _ in 0..5 {
            assert_eq!(h.tick().dns_failures, 0);
        }
        assert!(h.upstream_bytes().is_empty(), "unvalidated prefix leaked");
        h.send(&requests[1..]);
        // FIN follows the complete pipeline; requests must drain before upstream write shutdown.
        h.client
            .sockets
            .get_mut::<StackSocket>(h.client.handle)
            .close();
        h.take_queries(&requests);
        assert_eq!(h.relay.pending_dns_count(), 2);
        let first = framed(&answer(b));
        h.server.write_all(&first[..first.len() - 1]).unwrap();
        for _ in 0..6 {
            h.tick();
        }
        assert!(h.received.is_empty(), "partial unchecked reply leaked");
        h.server.write_all(&first[first.len() - 1..]).unwrap();
        h.until(|h, _| h.received.len() == first.len());
        assert_eq!(h.received, first);
        assert_eq!(h.relay.pending_dns_count(), 1);
        let second = framed(&answer(a));
        h.server.write_all(&second).unwrap();
        h.until(|h, _| h.received.len() == first.len() + second.len());
        assert_eq!(&h.received[first.len()..], second);
        assert_eq!(h.relay.pending_dns_count(), 0);
        h.server.shutdown(Shutdown::Write).unwrap();
        h.until(|h, _| h.relay.flow_count() == 0);
    }
}
#[test]
fn denied_malformed_oversized_and_incomplete_queries_never_leak_prefixes() {
    for scenario in 0..5 {
        let mut h = Harness::new("127.0.0.1:0");
        let bytes = match scenario {
            0 => framed(&query("a.blocked.example", 1, 0)),
            1 => vec![0, 0],
            2 => vec![16, 1], // 4097, above supported message cap
            3 => framed(&[0; 12]),
            _ => vec![0],
        };
        h.send(&bytes);
        if scenario == 4 {
            h.client
                .sockets
                .get_mut::<StackSocket>(h.client.handle)
                .close();
        }
        h.until(|_, report| report.dns_failures == 1);
        assert!(h.upstream_bytes().is_empty());
        assert!(h.received.is_empty());
        assert_eq!(h.relay.pending_dns_count(), 0);
    }
}
#[test]
fn malformed_unmatched_and_incomplete_responses_close_without_delivering_bytes() {
    for scenario in 0..4 {
        let mut h = Harness::new("127.0.0.1:0");
        let q = query("safe.example", 1, 0);
        let request = framed(&q);
        h.send(&request);
        h.take_queries(&request);
        let bad = match scenario {
            0 => framed(&answer(query("safe.example", 2, 0))),
            1 => framed(&answer(query("different.example", 1, 0))),
            2 => vec![255, 255],
            _ => vec![0],
        };
        h.server.write_all(&bad).unwrap();
        if scenario == 3 {
            h.server.shutdown(Shutdown::Write).unwrap();
        }
        h.until(|_, report| report.dns_failures == 1);
        assert!(h.received.is_empty());
        assert_eq!(h.relay.pending_dns_count(), 0);
    }
}
#[test]
fn duplicate_ids_capacity_and_query_deadlines_are_fail_closed() {
    for scenario in 0..4 {
        let limits = DnsLimits {
            max_pending_per_flow: if scenario == 1 { 1 } else { 8 },
            max_pending_total: if scenario == 3 { 1 } else { 4096 },
            query_timeout: 100,
        };
        let mut h = Harness::with_limits("127.0.0.1:0", Some(limits));
        let request = framed(&query("safe.example", 1, 0));
        h.send(&request);
        h.take_queries(&request);
        if scenario == 2 {
            assert!(matches!(h.relay.poll(h.now - 1), Err(Error::Clock)));
            assert_eq!(h.relay.pending_dns_count(), 1);
            h.now += 100;
            assert_eq!(h.relay.poll(h.now).unwrap().dns_failures, 1);
        } else {
            let second = if scenario == 0 {
                request.clone()
            } else {
                framed(&query("other.example", 2, 0))
            };
            h.send(&second);
            h.until(|_, report| report.dns_failures == 1);
        }
        assert!(
            h.upstream_bytes().is_empty(),
            "rejected second request leaked"
        );
        assert_eq!(h.relay.pending_dns_count(), 0);
    }
}
#[test]
fn filter_limits_budget_and_reset_changes_are_atomic() {
    let mut h = Harness::new("127.0.0.1:0");
    let request = framed(&query("safe.example", 1, 0));
    h.send(&request);
    h.take_queries(&request);
    let old = h.relay.dns_limits;
    assert!(h
        .relay
        .set_dns_limits(DnsLimits {
            query_timeout: 0,
            ..old
        })
        .is_err());
    assert!(h
        .relay
        .set_dns_filter(Some(domain_policy()), vec![0])
        .is_err());
    assert!(h
        .relay
        .set_dns_filter(Some(domain_policy()), vec![53, 53])
        .is_err());
    assert_eq!(h.relay.pending_dns_count(), 1);
    assert_eq!(h.relay.flow_count(), 1);
    h.relay.set_dns_limits(old).unwrap();
    assert_eq!(h.relay.pending_dns_count(), 0);
    assert_eq!(h.relay.flow_count(), 0);
    let mut cfg = config();
    cfg.buffer_budget = cfg.max_flows * (cfg.buffer_bytes * 2 + (cfg.output_slots + 1) * cfg.mtu);
    let mut tight = TcpRelay::new(
        Policy::new(vec![], Action::Allow).unwrap(),
        cfg,
        Protector {
            calls: Arc::new(AtomicUsize::new(0)),
            fail: false,
        },
    )
    .unwrap();
    assert!(matches!(
        tight.set_dns_filter(Some(domain_policy()), vec![53]),
        Err(Error::Config)
    ));
    assert!(tight.dns_policy.is_none());
    tight.set_dns_filter(None, vec![]).unwrap();
}

#[test]
fn partial_frame_deadline_is_not_refreshed_by_more_bytes_or_acks() {
    for inbound in [false, true] {
        let limits = DnsLimits {
            max_pending_per_flow: 8,
            max_pending_total: 16,
            query_timeout: 100,
        };
        let mut h = Harness::with_limits("127.0.0.1:0", Some(limits));
        if inbound {
            h.server.write_all(&[0]).unwrap();
        } else {
            h.send(&[0]);
        }
        h.until(|h, _| h.relay.buffers().dns_frame_bytes == 1);
        let started = h.now;
        if inbound {
            h.server.write_all(&[40]).unwrap();
        } else {
            h.send(&[40]);
        }
        h.until(|h, _| h.relay.buffers().dns_frame_bytes == 2);
        assert!(matches!(h.relay.poll(started - 1), Err(Error::Clock)));
        assert_eq!(h.relay.buffers().dns_frame_bytes, 2);
        h.now = started + 100;
        assert_eq!(h.relay.poll(h.now).unwrap().dns_failures, 1);
        assert_eq!(h.relay.pending_dns_count(), 0);
        assert_eq!(h.relay.buffers().dns_frame_bytes, 0);
        assert!(h.received.is_empty());
        assert!(h.upstream_bytes().is_empty());
    }
}

#[test]
fn dns_allow_never_grants_outbound_or_inbound_packet_permission() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let endpoint = listener.local_addr().unwrap();
    let (mut r, calls) = relay(Action::Deny, false);
    r.set_dns_filter(Some(domain_policy()), vec![endpoint.port()])
        .unwrap();
    let mut c = Client::new(endpoint);
    assert!(matches!(
        r.ingest(&c.syn(), 0),
        Err(Error::Dropped(DropReason::Policy { .. }))
    ));
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert_eq!(r.pending_dns_count(), 0);
    assert_eq!(
        listener.accept().unwrap_err().kind(),
        io::ErrorKind::WouldBlock
    );

    let mut h = Harness::new("127.0.0.1:0");
    let q = framed(&query("safe.example", 1, 0));
    h.send(&q);
    h.take_queries(&q);
    // Replacing packet policy through the public API revokes before later replies can leave.
    h.relay.update_policy(vec![], Action::Deny).unwrap();
    assert_eq!(h.relay.pending_dns_count(), 0);
    assert_eq!(h.relay.flow_count(), 0);
    assert!(h.relay.next_packet(h.now).unwrap().is_none());
}

#[test]
fn unselected_port_remains_an_opaque_tcp_stream() {
    let mut h = Harness::build("127.0.0.1:0", None, false);
    let bytes = b"opaque bytes, no DNS length prefix";
    h.send(bytes);
    h.take_queries(bytes);
    h.server.write_all(bytes).unwrap();
    h.until(|h, _| h.received.len() == bytes.len());
    assert_eq!(h.received, bytes);
    assert_eq!(h.relay.pending_dns_count(), 0);
    assert_eq!(h.relay.buffers().dns_frame_bytes, 0);
}

#[test]
fn revocation_discards_pending_queries_and_partial_response_frames() {
    for cause in 0..3 {
        let mut h = Harness::new("127.0.0.1:0");
        let q = framed(&query("safe.example", 1, 0));
        h.send(&q);
        h.take_queries(&q);
        h.server.write_all(&[0]).unwrap();
        h.until(|h, _| h.relay.buffers().dns_frame_bytes == 1);
        match cause {
            0 => h.relay.reset_network(),
            1 => h.relay.set_dns_filter(None, vec![]).unwrap(),
            _ => h.relay.update_policy(vec![], Action::Deny).unwrap(),
        }
        assert_eq!(h.relay.flow_count(), 0);
        assert_eq!(h.relay.pending_dns_count(), 0);
        assert_eq!(h.relay.buffers().dns_frame_bytes, 0);
        assert!(h.relay.next_packet(h.now).unwrap().is_none());
        assert!(h.received.is_empty());
    }
}
