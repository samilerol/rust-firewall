use super::*;
use smoltcp::wire::{Ipv4Packet, Ipv6Packet};
fn wire(id: FlowId, seq: u32, ack: u32, flags: u8, payload: &[u8]) -> Vec<u8> {
    let offset = if id.source.is_ipv4() { 20 } else { 40 };
    let mut bytes = vec![0; offset + 20 + payload.len()];
    match (id.source, id.destination) {
        (std::net::IpAddr::V4(src), std::net::IpAddr::V4(dst)) => {
            let mut ip = Ipv4Packet::new_unchecked(&mut bytes);
            ip.set_version(4);
            ip.set_header_len(20);
            ip.set_total_len((offset + 20 + payload.len()) as u16);
            ip.set_hop_limit(64);
            ip.set_next_header(smoltcp::wire::IpProtocol::Tcp);
            ip.set_src_addr(src);
            ip.set_dst_addr(dst);
            ip.fill_checksum();
        }
        (std::net::IpAddr::V6(src), std::net::IpAddr::V6(dst)) => {
            let mut ip = Ipv6Packet::new_unchecked(&mut bytes);
            ip.set_version(6);
            ip.set_payload_len((20 + payload.len()) as u16);
            ip.set_hop_limit(64);
            ip.set_next_header(smoltcp::wire::IpProtocol::Tcp);
            ip.set_src_addr(src);
            ip.set_dst_addr(dst);
        }
        _ => unreachable!(),
    }
    let tcp = &mut bytes[offset..];
    tcp[..2].copy_from_slice(&id.source_port.to_be_bytes());
    tcp[2..4].copy_from_slice(&id.destination_port.to_be_bytes());
    tcp[4..8].copy_from_slice(&seq.to_be_bytes());
    tcp[8..12].copy_from_slice(&ack.to_be_bytes());
    tcp[12] = 0x50;
    tcp[13] = flags;
    tcp[14..16].copy_from_slice(&4096u16.to_be_bytes());
    tcp[20..].copy_from_slice(payload);
    TcpPacket::new_unchecked(tcp).fill_checksum(&id.source.into(), &id.destination.into());
    bytes
}
pub(super) fn exercise(input: &[u8]) {
    if let Ok(parsed) = parse_checked(input, ChecksumPolicy::Require) {
        if parsed.packet.protocol == Protocol::Tcp {
            let p = parsed.packet;
            let offset = if p.source.is_ipv4() { 20 } else { 40 };
            if let Ok(tcp) = TcpPacket::new_checked(&input[offset..]) {
                let _ = TcpRepr::parse(
                    &tcp,
                    &p.source.into(),
                    &p.destination.into(),
                    &ChecksumCapabilities::default(),
                );
            }
        }
    }
    for (source, destination) in [
        ("192.0.2.1", "198.51.100.2"),
        ("2001:db8::1", "2001:db8::2"),
    ] {
        let config = Config {
            max_flows: 1,
            mtu: 1500,
            buffer_bytes: 1024,
            output_slots: 2,
            buffer_budget: 8192,
            idle_timeout_ms: 1000,
            connect_timeout_ms: 100,
        };
        let id = FlowId {
            source: source.parse().unwrap(),
            destination: destination.parse().unwrap(),
            source_port: 12345,
            destination_port: 443,
            protocol: Protocol::Tcp,
        };
        let mut flow = Flow::with_seed(id, config, 0, 1).unwrap();
        let mut now = 0u64;
        let mut seq = 0x12340001u32;
        let mut ack = 0u32;
        flow.device.rx = Some(wire(id, seq - 1, 0, 2, &[]));
        flow.stack_poll(0);
        if let Some(synack) = flow.device.tx.pop_front() {
            let offset = if id.source.is_ipv4() { 20 } else { 40 };
            ack = (TcpPacket::new_checked(&synack[offset..])
                .unwrap()
                .seq_number()
                .0 as u32)
                .wrapping_add(1);
        }
        flow.device.rx = Some(wire(id, seq, ack, 0x10, &[]));
        flow.stack_poll(1);
        for data in input.chunks(16).take(64) {
            if data.is_empty() {
                continue;
            }
            now += u64::from(data[0] % 30) + 1;
            if flow.device.rx.is_none() {
                let flags = [0x10, 0x18, 0x11, 0x14, 2][usize::from(data[0]) % 5];
                let chosen = if data[0] & 32 == 0 {
                    seq
                } else {
                    seq.wrapping_add(1_000_000)
                };
                flow.device.rx = Some(wire(id, chosen, ack, flags, data));
                seq = seq.wrapping_add(data.len() as u32 + u32::from(flags & 3 != 0));
            }
            flow.stack_poll(now);
            let socket = flow.sockets.get_mut::<StackSocket>(flow.handle);
            if socket.can_recv() {
                let _ = socket.recv(|bytes| (bytes.len().min(usize::from(data[0])), ()));
            }
            if socket.can_send() {
                let _ = socket.send_slice(data);
            }
            if data[0] & 64 != 0 {
                socket.close();
            }
            assert!(
                socket.recv_queue() <= config.buffer_bytes
                    && socket.send_queue() <= config.buffer_bytes
            );
            if data[0] & 128 == 0 {
                while let Some(bytes) = flow.device.tx.pop_front() {
                    assert!(bytes.len() <= config.mtu);
                    assert!(parse_checked(&bytes, ChecksumPolicy::Require).is_ok());
                    let offset = if id.source.is_ipv4() { 20 } else { 40 };
                    let packet = TcpPacket::new_checked(&bytes[offset..]).unwrap();
                    ack = (packet.seq_number().0 as u32).wrapping_add(
                        packet.payload().len() as u32 + u32::from(packet.syn() || packet.fin()),
                    );
                }
            }
            assert!(flow.device.tx.len() <= config.output_slots);
            assert!(flow
                .device
                .rx
                .as_ref()
                .is_none_or(|b| b.len() <= config.mtu));
        }
        assert!(flow.upstream.is_none());
    }
}
