#![no_main]
use libfuzzer_sys::fuzz_target;
use netscope_packet::{parse, Protocol};

fuzz_target!(|bytes: &[u8]| {
    if let Ok(packet) = parse(bytes) {
        assert_eq!(packet.length, bytes.len());
        assert_eq!(packet.source.is_ipv4(), packet.destination.is_ipv4());
        let offset = if packet.source.is_ipv4() { 20 } else { 40 };
        let minimum = match packet.protocol {
            Protocol::Tcp => 20,
            Protocol::Udp => 8,
        };
        assert!(bytes.len() >= offset + minimum);
        assert_eq!(
            packet.source_port,
            u16::from_be_bytes([bytes[offset], bytes[offset + 1]])
        );
        assert_eq!(
            packet.destination_port,
            u16::from_be_bytes([bytes[offset + 2], bytes[offset + 3]])
        );
        // Exact datagram length means shortening or appending cannot remain valid.
        assert!(parse(&bytes[..bytes.len() - 1]).is_err());
        let mut appended = bytes.to_vec();
        appended.push(0);
        assert!(parse(&appended).is_err());
    }
});
