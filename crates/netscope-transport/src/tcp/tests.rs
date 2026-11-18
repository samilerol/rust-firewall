use super::*;
use std::{
    net::TcpListener,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::Instant as Wall,
};
#[derive(Clone)]
struct Protector {
    calls: Arc<AtomicUsize>,
    fail: bool,
}
impl TcpSocketProtector for Protector {
    fn protect(&self, socket: &Socket) -> io::Result<()> {
        assert!(
            socket.peer_addr().is_err(),
            "protect must run BEFORE connect"
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
fn config() -> Config {
    Config {
        max_flows: 2,
        mtu: 1500,
        buffer_bytes: 4096,
        output_slots: 4,
        buffer_budget: 64 * 1024,
        idle_timeout_ms: 30000,
        connect_timeout_ms: 1000,
    }
}
fn relay(action: Action, fail: bool) -> (TcpRelay<Protector>, Arc<AtomicUsize>) {
    let calls = Arc::new(AtomicUsize::new(0));
    (
        TcpRelay::new(
            Policy::new(vec![], action).unwrap(),
            config(),
            Protector {
                calls: calls.clone(),
                fail,
            },
        )
        .unwrap(),
        calls,
    )
}
struct Client {
    iface: Interface,
    device: Device,
    sockets: SocketSet<'static>,
    handle: SocketHandle,
    source: SocketAddr,
    destination: SocketAddr,
}
impl Client {
    fn new(destination: SocketAddr) -> Self {
        Self::with_port(destination, 12345)
    }
    fn with_port(destination: SocketAddr, port: u16) -> Self {
        let mut source = if destination.is_ipv4() {
            "192.0.2.1:12345"
        } else {
            "[2001:db8::1]:12345"
        }
        .parse::<SocketAddr>()
        .unwrap();
        source.set_port(port);
        let mut device = Device::new(1500, 64);
        let mut cfg = IfaceConfig::new(HardwareAddress::Ip);
        cfg.random_seed = 123456;
        let mut iface = Interface::new(cfg, &mut device, Instant::from_millis(0));
        iface.update_ip_addrs(|a| {
            a.push(IpCidr::new(
                source.ip().into(),
                if source.is_ipv4() { 32 } else { 128 },
            ))
            .unwrap()
        });
        match destination.ip() {
            std::net::IpAddr::V4(ip) => {
                iface.routes_mut().add_default_ipv4_route(ip).unwrap();
            }
            std::net::IpAddr::V6(ip) => {
                iface.routes_mut().add_default_ipv6_route(ip).unwrap();
            }
        }
        let mut socket = StackSocket::new(
            SocketBuffer::new(vec![0; 32768]),
            SocketBuffer::new(vec![0; 32768]),
        );
        socket.set_ack_delay(None);
        socket
            .connect(
                iface.context(),
                (IpAddress::from(destination.ip()), destination.port()),
                source.port(),
            )
            .unwrap();
        let mut sockets = SocketSet::new(vec![]);
        let handle = sockets.add(socket);
        Self {
            iface,
            device,
            sockets,
            handle,
            source,
            destination,
        }
    }
    fn poll(&mut self, now: u64) {
        self.iface.poll(
            Instant::from_millis(now as i64),
            &mut self.device,
            &mut self.sockets,
        );
    }
    fn syn(&mut self) -> Vec<u8> {
        self.poll(0);
        self.device.tx.pop_front().expect("client SYN")
    }
    fn step(&mut self, relay: &mut TcpRelay<Protector>, now: u64) -> PollReport {
        self.poll(now);
        while let Some(bytes) = self.device.tx.pop_front() {
            match relay.ingest(&bytes, now) {
                Ok(_) => {}
                Err(Error::Backpressure) => {
                    self.device.tx.push_front(bytes);
                    break;
                }
                Err(error) => panic!("ingest: {error:?}"),
            }
        }
        let report = relay.poll(now).unwrap();
        while let Some(bytes) = relay.next_packet(now).unwrap() {
            assert!(parse_checked(&bytes, ChecksumPolicy::Require).is_ok());
            assert!(self.device.rx.is_none());
            self.device.rx = Some(bytes);
            self.poll(now);
        }
        report
    }
}
fn echo(address: &str, payload: Vec<u8>, drop_synack: bool) {
    let listener = TcpListener::bind(address).unwrap();
    let endpoint = listener.local_addr().unwrap();
    let expected = payload.clone();
    let worker = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(4)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(4)))
            .unwrap();
        if expected.len() > 32768 {
            SockRef::from(&stream).set_recv_buffer_size(4096).unwrap();
            std::thread::sleep(Duration::from_millis(50));
        }
        let mut received = Vec::new();
        stream.read_to_end(&mut received).unwrap();
        assert_eq!(received, expected);
        stream.write_all(&received).unwrap();
        stream.shutdown(Shutdown::Write).unwrap();
    });
    let (mut relay, calls) = relay(Action::Allow, false);
    let mut client = Client::new(endpoint);
    let mut sent = 0;
    let mut received = Vec::new();
    let mut closed = false;
    let mut dropped = !drop_synack;
    let deadline = Wall::now() + Duration::from_secs(6);
    let mut now = 0u64;
    while Wall::now() < deadline {
        client.poll(now);
        while let Some(bytes) = client.device.tx.pop_front() {
            relay.ingest(&bytes, now).unwrap();
        }
        relay.poll(now).unwrap();
        while let Some(bytes) = relay.next_packet(now).unwrap() {
            assert!(parse_checked(&bytes, ChecksumPolicy::Require).is_ok());
            if !dropped {
                dropped = true;
                continue;
            }
            client.device.rx = Some(bytes);
            client.poll(now);
        }
        let socket = client.sockets.get_mut::<StackSocket>(client.handle);
        if socket.can_send() && sent < payload.len() {
            sent += socket.send_slice(&payload[sent..]).unwrap();
        }
        if sent == payload.len() && socket.may_send() && !closed {
            socket.close();
            closed = true;
        }
        if socket.can_recv() {
            socket
                .recv(|bytes| {
                    received.extend_from_slice(bytes);
                    (bytes.len(), ())
                })
                .unwrap();
        }
        let used = relay.buffers();
        assert!(used.reserved_payload_bytes <= config().buffer_budget);
        assert!(used.queued_packets <= config().max_flows * (config().output_slots + 1));
        if closed && received == payload && !socket.may_recv() && relay.flow_count() == 0 {
            break;
        }
        now += 5;
        std::thread::sleep(Duration::from_millis(1));
    }
    assert_eq!(sent, payload.len());
    assert_eq!(received, payload, "TCP echo did not finish");
    assert_eq!(relay.flow_count(), 0, "virtual FIN/ACK must complete");
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    worker.join().unwrap();
}
#[test]
fn ipv4_tcp_echo_half_close_and_partial_buffering() {
    echo(
        "127.0.0.1:0",
        (0..100_000).map(|i| (i % 251) as u8).collect(),
        false,
    );
}
#[test]
fn ipv6_tcp_echo_half_close() {
    echo("[::1]:0", b"IPv6 real TCP echo".repeat(100), false);
}
#[test]
fn dropped_synack_retransmits_without_duplicate_upstream_socket() {
    echo("127.0.0.1:0", b"retransmission".to_vec(), true);
}
#[test]
fn invalid_denied_or_unprotected_syn_never_connects() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let endpoint = listener.local_addr().unwrap();
    let mut client = Client::new(endpoint);
    let syn = client.syn();
    let (mut denied, calls) = relay(Action::Deny, false);
    assert!(matches!(
        denied.ingest(&syn, 0),
        Err(Error::Dropped(DropReason::Policy { .. }))
    ));
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    let (mut invalid, calls) = relay(Action::Allow, false);
    let mut bad = syn.clone();
    *bad.last_mut().unwrap() ^= 1;
    assert!(matches!(invalid.ingest(&bad, 0), Err(Error::Packet(_))));
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    let (mut blocked, calls) = relay(Action::Allow, true);
    assert!(
        matches!(blocked.ingest(&syn,0),Err(Error::Io(e)) if e.kind()==io::ErrorKind::PermissionDenied)
    );
    assert_eq!(blocked.flow_count(), 0);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        listener.accept().unwrap_err().kind(),
        io::ErrorKind::WouldBlock
    );
}
#[test]
fn capacity_clock_budget_and_first_syn_are_explicit() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = listener.local_addr().unwrap();
    let mut client = Client::new(endpoint);
    let syn = client.syn();
    let (mut relay, calls) = relay(Action::Allow, false);
    let mut cfg = config();
    cfg.max_flows = 0;
    let mut zero = TcpRelay::new(
        Policy::new(vec![], Action::Allow).unwrap(),
        cfg,
        Protector {
            calls: calls.clone(),
            fail: false,
        },
    )
    .unwrap();
    assert!(matches!(
        zero.ingest(&syn, 0),
        Err(Error::Dropped(DropReason::FlowCapacity))
    ));
    assert!(matches!(relay.ingest(&syn, u64::MAX), Err(Error::Clock)));
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    for cfg in [
        Config {
            max_flows: 65,
            ..config()
        },
        Config {
            buffer_budget: 1,
            ..config()
        },
        Config {
            buffer_bytes: usize::MAX,
            ..config()
        },
        Config {
            mtu: 1501,
            ..config()
        },
        Config {
            connect_timeout_ms: 30001,
            ..config()
        },
    ] {
        assert!(matches!(
            TcpRelay::new(
                Policy::new(vec![], Action::Allow).unwrap(),
                cfg,
                Protector {
                    calls: calls.clone(),
                    fail: false
                }
            ),
            Err(Error::Config)
        ));
    }
}

#[test]
fn first_ack_and_bad_syn_options_never_open_upstream() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let mut client = Client::new(listener.local_addr().unwrap());
    let syn = client.syn();
    let (mut r, calls) = relay(Action::Allow, false);
    let mut ack = syn.clone();
    ack[33] = 0x10;
    TcpPacket::new_unchecked(&mut ack[20..])
        .fill_checksum(&client.source.ip().into(), &client.destination.ip().into());
    assert!(matches!(r.ingest(&ack, 0), Err(Error::InitialSynRequired)));
    let mut bad = syn;
    if (bad[32] >> 4) > 5 {
        bad[41] = 1;
        TcpPacket::new_unchecked(&mut bad[20..])
            .fill_checksum(&client.source.ip().into(), &client.destination.ip().into());
        assert!(matches!(r.ingest(&bad, 0), Err(Error::Stack)));
    }
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert_eq!(r.flow_count(), 0);
    assert_eq!(
        listener.accept().unwrap_err().kind(),
        io::ErrorKind::WouldBlock
    );
}
#[test]
fn real_flow_capacity_and_policy_reset_revoke_queued_packets() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = listener.local_addr().unwrap();
    let mut first = Client::with_port(endpoint, 12345);
    let mut second = Client::with_port(endpoint, 12346);
    let calls = Arc::new(AtomicUsize::new(0));
    let mut cfg = config();
    cfg.max_flows = 1;
    let mut r = TcpRelay::new(
        Policy::new(vec![], Action::Allow).unwrap(),
        cfg,
        Protector {
            calls: calls.clone(),
            fail: false,
        },
    )
    .unwrap();
    r.ingest(&first.syn(), 0).unwrap();
    assert_eq!(r.flow_count(), 1);
    assert!(matches!(
        r.ingest(&second.syn(), 0),
        Err(Error::Dropped(DropReason::FlowCapacity))
    ));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    let invalid = Rule {
        priority: 0,
        action: Action::Deny,
        source: None,
        destination: None,
        protocol: None,
        source_port: Some(std::ops::RangeInclusive::new(2, 1)),
        destination_port: None,
    };
    assert!(r.update_policy(vec![invalid], Action::Deny).is_err());
    assert_eq!(r.flow_count(), 1);
    r.update_policy(vec![], Action::Deny).unwrap();
    assert_eq!(r.flow_count(), 0);
    // The queued SYN-ACK is revoked; the client is told with a RST instead.
    let revoked = r.next_packet(0).unwrap().expect("RST for revoked flow");
    let tcp = TcpPacket::new_checked(&revoked[20..]).unwrap();
    assert!(tcp.rst() && !tcp.syn());
    assert!(r.next_packet(0).unwrap().is_none());
    r.update_policy(vec![], Action::Allow).unwrap();
    let mut third = Client::with_port(endpoint, 12347);
    r.ingest(&third.syn(), 10).unwrap();
    r.reset_network();
    assert_eq!(r.flow_count(), 0);
    assert!(matches!(r.poll(9), Err(Error::Clock)));
}
#[test]
fn packet_queue_backpressure_is_bounded_and_does_not_duplicate_socket() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let mut client = Client::new(listener.local_addr().unwrap());
    let syn = client.syn();
    let calls = Arc::new(AtomicUsize::new(0));
    let mut cfg = config();
    cfg.output_slots = 1;
    let mut r = TcpRelay::new(
        Policy::new(vec![], Action::Allow).unwrap(),
        cfg,
        Protector {
            calls: calls.clone(),
            fail: false,
        },
    )
    .unwrap();
    r.ingest(&syn, 0).unwrap();
    r.ingest(&syn, 0).unwrap();
    assert!(matches!(r.ingest(&syn, 0), Err(Error::Backpressure)));
    assert_eq!(r.buffers().queued_packets, 2);
    settle(&mut r, 0);
    assert!(r.next_packet(0).unwrap().is_some());
    r.poll(1).unwrap();
    assert!(r.buffers().queued_packets <= 2);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}
#[test]
fn pending_connect_deadline_discards_old_output_and_emits_reset() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let mut client = Client::new(listener.local_addr().unwrap());
    let (mut r, _) = relay(Action::Allow, false);
    let id = r.ingest(&client.syn(), 0).unwrap();
    r.flows.get_mut(&id).unwrap().connecting = true; // deterministic unit model of an unobserved pending connect
    let report = r.poll(1000).unwrap();
    assert_eq!(report.connect_timeouts, 1);
    let reset = r.next_packet(1000).unwrap().expect("RST after timeout");
    let tcp = TcpPacket::new_checked(&reset[20..]).unwrap();
    assert!(tcp.rst());
    assert!(!tcp.syn());
    r.poll(1001).unwrap();
    assert_eq!(r.flow_count(), 0);
}
#[test]
fn a_refused_real_loopback_connection_cannot_become_a_stream() {
    let bound = Socket::new(Domain::IPV4, Type::STREAM, Some(OsProtocol::TCP)).unwrap();
    bound
        .bind(&"127.0.0.1:0".parse::<SocketAddr>().unwrap().into())
        .unwrap();
    let mut client = Client::new(bound.local_addr().unwrap().as_socket().unwrap());
    let (mut r, _) = relay(Action::Allow, false);
    match r.ingest(&client.syn(), 0) {
        Err(Error::Io(_)) => assert_eq!(r.flow_count(), 0),
        Ok(_) => {
            let deadline = Wall::now() + Duration::from_secs(2);
            let mut now = 1;
            let mut failures = 0;
            while Wall::now() < deadline && failures == 0 {
                failures += r.poll(now).unwrap().io_failures;
                now += 1;
                std::thread::sleep(Duration::from_millis(1));
            }
            assert_eq!(failures, 1);
            while r.next_packet(now).unwrap().is_some() {}
            r.poll(now).unwrap();
            assert_eq!(r.flow_count(), 0);
        }
        Err(error) => panic!("unexpected refusal path: {error:?}"),
    }
}
#[test]
fn idle_expiry_and_response_policy_are_enforced_during_handshake() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let mut client = Client::new(listener.local_addr().unwrap());
    let (mut r, _) = relay(Action::Allow, false);
    client.step(&mut r, 0);
    assert_eq!(r.flow_count(), 1);
    r.poll(30000).unwrap();
    assert_eq!(r.flow_count(), 0);
    let outbound = Rule {
        priority: 0,
        action: Action::Allow,
        source: None,
        destination: None,
        protocol: None,
        source_port: Some(12345..=12345),
        destination_port: None,
    };
    let calls = Arc::new(AtomicUsize::new(0));
    let mut r = TcpRelay::new(
        Policy::new(vec![outbound], Action::Deny).unwrap(),
        config(),
        Protector { calls, fail: false },
    )
    .unwrap();
    let mut fresh = Client::new(listener.local_addr().unwrap());
    r.ingest(&fresh.syn(), 0).unwrap();
    settle(&mut r, 0);
    assert!(matches!(
        r.next_packet(0),
        Err(Error::Dropped(DropReason::Policy { .. }))
    ));
    assert_eq!(r.flow_count(), 0);
}

#[test]
fn accepted_client_reset_releases_half_open_upstream_immediately() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let mut client = Client::new(listener.local_addr().unwrap());
    let (mut r, _) = relay(Action::Allow, false);
    r.ingest(&client.syn(), 0).unwrap();
    settle(&mut r, 0);
    let synack = r.next_packet(0).unwrap().unwrap();
    client.device.rx = Some(synack);
    client.poll(0);
    client.device.tx.clear(); // hold the handshake ACK so relay remains SYN-RECEIVED
    client.sockets.get_mut::<StackSocket>(client.handle).abort();
    client.poll(1);
    let reset = client.device.tx.pop_front().unwrap();
    assert!(TcpPacket::new_checked(&reset[20..]).unwrap().rst());
    let mut invalid = reset.clone();
    {
        let mut packet = TcpPacket::new_unchecked(&mut invalid[20..]);
        packet.set_seq_number(packet.seq_number() + 1_000_000);
        packet.fill_checksum(&client.source.ip().into(), &client.destination.ip().into());
    }
    r.ingest(&invalid, 1).unwrap();
    assert_eq!(
        r.flow_count(),
        1,
        "invalid RST must not kill the connection"
    );
    r.ingest(&reset, 2).unwrap();
    assert_eq!(
        r.flow_count(),
        0,
        "accepted RST returning listener to LISTEN must close upstream"
    );
}
#[test]
fn upstream_fin_still_allows_the_client_to_send_after_eof() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = listener.local_addr().unwrap();
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(4)))
            .unwrap();
        stream.write_all(b"greeting").unwrap();
        stream.shutdown(Shutdown::Write).unwrap();
        let mut bytes = Vec::new();
        stream.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, b"after EOF");
    });
    let (mut r, _) = relay(Action::Allow, false);
    let mut client = Client::new(endpoint);
    let mut received = Vec::new();
    let mut sent = false;
    let deadline = Wall::now() + Duration::from_secs(5);
    let mut now = 0;
    while Wall::now() < deadline {
        client.step(&mut r, now);
        let socket = client.sockets.get_mut::<StackSocket>(client.handle);
        if socket.can_recv() {
            socket
                .recv(|b| {
                    received.extend_from_slice(b);
                    (b.len(), ())
                })
                .unwrap();
        }
        if received == b"greeting" && !socket.may_recv() && !sent {
            assert_eq!(socket.send_slice(b"after EOF").unwrap(), 9);
            socket.close();
            sent = true;
        }
        if sent && !socket.is_active() {
            client.step(&mut r, now);
            break;
        }
        now += 5;
        std::thread::sleep(Duration::from_millis(1));
    }
    assert!(sent);
    server.join().unwrap();
    r.poll(now + 30001).unwrap();
    assert_eq!(r.flow_count(), 0);
}

#[cfg(feature = "fuzzing")]
#[test]
fn deterministic_in_memory_harness_exercises_both_families() {
    exercise_stack(&[]);
    exercise_stack(&[0; 1024]);
    exercise_stack(&[255; 1024]);
    exercise_stack(&(0..=255u8).collect::<Vec<_>>());
}

#[test]
fn clock_conversion_and_zero_mss_cannot_overflow_or_open_an_invalid_flow() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let mut client = Client::new(listener.local_addr().unwrap());
    let syn = client.syn();
    let (mut r, calls) = relay(Action::Allow, false);
    for now in [
        MAX_TIME_MS + 1,
        i64::MAX as u64 / 1000,
        i64::MAX as u64,
        u64::MAX,
    ] {
        assert!(matches!(r.ingest(&syn, now), Err(Error::Clock)));
    }
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    let mut zero = syn.clone();
    assert_eq!(zero[40], 2);
    assert_eq!(zero[41], 4);
    zero[42..44].fill(0);
    TcpPacket::new_unchecked(&mut zero[20..])
        .fill_checksum(&client.source.ip().into(), &client.destination.ip().into());
    assert!(matches!(r.ingest(&zero, 0), Err(Error::Stack)));
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert_eq!(
        listener.accept().unwrap_err().kind(),
        io::ErrorKind::WouldBlock
    );
    r.ingest(&syn, MAX_TIME_MS).unwrap();
    assert_eq!(r.flow_count(), 1);
    assert!(matches!(r.poll(MAX_TIME_MS + 1), Err(Error::Clock)));
    r.reset_network();
}

#[test]
fn nonunicast_source_and_reserved_tcp_bits_do_not_open_sockets() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let mut client = Client::new(listener.local_addr().unwrap());
    let syn = client.syn();
    let (mut r, calls) = relay(Action::Allow, false);
    for ip in [
        std::net::Ipv4Addr::UNSPECIFIED,
        std::net::Ipv4Addr::BROADCAST,
        std::net::Ipv4Addr::new(224, 0, 0, 1),
    ] {
        let mut bytes = syn.clone();
        {
            let mut header = smoltcp::wire::Ipv4Packet::new_unchecked(&mut bytes);
            header.set_src_addr(ip);
            header.fill_checksum();
        }
        TcpPacket::new_unchecked(&mut bytes[20..])
            .fill_checksum(&IpAddress::from(ip), &client.destination.ip().into());
        assert!(matches!(r.ingest(&bytes, 0), Err(Error::Endpoint)));
    }
    let mut reserved = syn;
    reserved[32] |= 1;
    TcpPacket::new_unchecked(&mut reserved[20..])
        .fill_checksum(&client.source.ip().into(), &client.destination.ip().into());
    assert!(matches!(r.ingest(&reserved, 0), Err(Error::Unsupported)));
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert_eq!(r.flow_count(), 0);
    assert_eq!(
        listener.accept().unwrap_err().kind(),
        io::ErrorKind::WouldBlock
    );
}
fn client_state(client: &Client) -> State {
    client.sockets.get::<StackSocket>(client.handle).state()
}
/// Hand every relay output packet to the client stack; returns how many were delivered.
fn deliver(client: &mut Client, r: &mut TcpRelay<Protector>, now: u64) -> usize {
    let mut delivered = 0;
    while let Some(bytes) = r.next_packet(now).unwrap() {
        client.device.rx = Some(bytes);
        client.poll(now);
        delivered += 1;
    }
    delivered
}
fn established(listener: &TcpListener) -> (Client, TcpRelay<Protector>) {
    let mut client = Client::new(listener.local_addr().unwrap());
    let (mut r, _) = relay(Action::Allow, false);
    for now in 0..4 {
        client.step(&mut r, now);
    }
    assert_eq!(client_state(&client), State::Established);
    (client, r)
}
#[test]
fn network_reset_and_policy_update_reset_established_clients() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let (mut client, mut r) = established(&listener);
    r.reset_network();
    assert_eq!(r.flow_count(), 0);
    assert_eq!(deliver(&mut client, &mut r, 4), 1);
    assert_eq!(client_state(&client), State::Closed);

    let (mut client, mut r) = established(&listener);
    r.update_policy(vec![], Action::Deny).unwrap();
    assert_eq!(deliver(&mut client, &mut r, 4), 1);
    assert_eq!(client_state(&client), State::Closed);
}
#[test]
fn idle_expiry_resets_established_clients() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let (mut client, mut r) = established(&listener);
    r.poll(40_000).unwrap();
    assert_eq!(r.flow_count(), 0);
    assert_eq!(deliver(&mut client, &mut r, 40_000), 1);
    assert_eq!(client_state(&client), State::Closed);
}
#[test]
fn failed_upstream_setup_answers_the_syn_with_a_reset() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let mut client = Client::new(listener.local_addr().unwrap());
    let (mut r, _) = relay(Action::Allow, true); // protect() refuses, so no upstream exists
    assert!(matches!(r.ingest(&client.syn(), 0), Err(Error::Io(_))));
    assert_eq!(r.flow_count(), 0);
    assert_eq!(deliver(&mut client, &mut r, 0), 1);
    assert_eq!(client_state(&client), State::Closed);
}
#[test]
fn policy_denied_response_resets_the_client_after_the_error() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let mut client = Client::new(listener.local_addr().unwrap());
    let outbound = Rule {
        priority: 0,
        action: Action::Allow,
        source: None,
        destination: None,
        protocol: None,
        source_port: Some(12345..=12345),
        destination_port: None,
    };
    let mut r = TcpRelay::new(
        Policy::new(vec![outbound], Action::Deny).unwrap(),
        config(),
        Protector {
            calls: Arc::new(AtomicUsize::new(0)),
            fail: false,
        },
    )
    .unwrap();
    r.ingest(&client.syn(), 0).unwrap();
    settle(&mut r, 0);
    assert!(matches!(
        r.next_packet(0),
        Err(Error::Dropped(DropReason::Policy { .. }))
    ));
    let reset = r.next_packet(0).unwrap().expect("RST after denied reply");
    assert!(TcpPacket::new_checked(&reset[20..]).unwrap().rst());
}
#[test]
fn queued_resets_are_bounded() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let (_, mut r) = established(&listener);
    let limit = r.reset_limit();
    for _ in 0..3 {
        queue_reset(&mut r.resets, limit, Some(vec![0; 40]));
    }
    assert_eq!(r.resets.len(), limit.min(3));
    for _ in 0..limit * 2 {
        queue_reset(&mut r.resets, limit, Some(vec![0; 40]));
    }
    assert_eq!(r.resets.len(), limit);
}
/// Poll until no upstream connect is pending (the OS may finish it a moment after `connect`).
fn settle(r: &mut TcpRelay<Protector>, now: u64) {
    let deadline = Wall::now() + Duration::from_secs(2);
    while r.flows.values().any(|f| f.connecting && !f.failed) {
        assert!(Wall::now() < deadline, "upstream connect never completed");
        r.poll(now).unwrap();
        std::thread::sleep(Duration::from_millis(1));
    }
}
#[test]
fn syn_ack_is_withheld_until_the_upstream_connect_completes() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let mut client = Client::new(listener.local_addr().unwrap());
    let (mut r, _) = relay(Action::Allow, false);
    let id = r.ingest(&client.syn(), 0).unwrap();
    r.flows.get_mut(&id).unwrap().connecting = true; // deterministic model of a pending connect
    assert!(r.next_packet(0).unwrap().is_none(), "SYN-ACK must be held");
    assert_eq!(r.buffers().queued_packets, 1);
    settle(&mut r, 0); // the real connection completes and the pump observes it
    let synack = r.next_packet(0).unwrap().expect("released SYN-ACK");
    let tcp = TcpPacket::new_checked(&synack[20..]).unwrap();
    assert!(tcp.syn() && tcp.ack());
    client.device.rx = Some(synack);
    client.poll(0);
    assert_eq!(client_state(&client), State::Established);
}
#[test]
fn refused_upstream_never_shows_the_client_an_established_connection() {
    let bound = Socket::new(Domain::IPV4, Type::STREAM, Some(OsProtocol::TCP)).unwrap();
    bound
        .bind(&"127.0.0.1:0".parse::<SocketAddr>().unwrap().into())
        .unwrap();
    let mut client = Client::new(bound.local_addr().unwrap().as_socket().unwrap());
    let (mut r, _) = relay(Action::Allow, false);
    let syn = client.syn();
    let mut seen = Vec::new();
    // Drain before every poll so a SYN-ACK that was merely discarded later cannot hide.
    let mut drain = |r: &mut TcpRelay<Protector>, now: u64| {
        while let Some(bytes) = r.next_packet(now).unwrap() {
            let tcp = TcpPacket::new_checked(&bytes[20..]).unwrap();
            assert!(!tcp.syn(), "a refused connection must never be SYN-ACKed");
            seen.push(tcp.rst());
            client.device.rx = Some(bytes);
            client.poll(now);
        }
    };
    let mut now = 0;
    match r.ingest(&syn, now) {
        Err(Error::Io(_)) => {} // refused immediately: RST was queued for the SYN
        Ok(_) => {
            let deadline = Wall::now() + Duration::from_secs(2);
            loop {
                drain(&mut r, now);
                if r.poll(now).unwrap().io_failures > 0 {
                    break;
                }
                assert!(Wall::now() < deadline, "refusal never observed");
                now += 1;
                std::thread::sleep(Duration::from_millis(1));
            }
        }
        Err(error) => panic!("unexpected refusal path: {error:?}"),
    }
    drain(&mut r, now);
    assert_eq!(seen, [true]);
    assert_eq!(client_state(&client), State::Closed);
}
