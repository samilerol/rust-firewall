#![no_main]
use libfuzzer_sys::fuzz_target;
use netscope_packet::{parse, parse_checked, ChecksumPolicy, Protocol, TransportChecksum};

fuzz_target!(|bytes: &[u8]| {
    for (source, destination) in [
        ("192.0.2.1:1234", "198.51.100.2:53"),
        ("[2001:db8::1]:1234", "[2001:db8::2]:53"),
    ] {
        if let Ok(encoded) = netscope_packet::udp::encode(
            source.parse().unwrap(),
            destination.parse().unwrap(),
            bytes,
        ) {
            assert!(parse_checked(&encoded, ChecksumPolicy::Require).is_ok());
            let offset = if encoded[0] >> 4 == 4 { 28 } else { 48 };
            assert_eq!(&encoded[offset..], bytes);
        }
    }
    for policy in [
        ChecksumPolicy::Require,
        ChecksumPolicy::AllowIpv4UdpOmission,
    ] {
        if let Ok(checked) = parse_checked(bytes, policy) {
            assert_eq!(parse(bytes), Ok(checked.packet));
            if checked.transport_checksum == TransportChecksum::OmittedIpv4Udp {
                assert_eq!(policy, ChecksumPolicy::AllowIpv4UdpOmission);
                assert!(checked.packet.source.is_ipv4());
                assert_eq!(checked.packet.protocol, Protocol::Udp);
                assert!(parse_checked(bytes, ChecksumPolicy::Require).is_err());
            }
        }
    }
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
