use netscope_packet::{parse, parse_checked, ChecksumPolicy, ParseError, TransportChecksum};

fn hex(text: &str) -> Vec<u8> {
    text.trim()
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}
fn fixtures() -> Vec<Vec<u8>> {
    [
        include_str!("fixtures/v4-tcp-empty.hex"),
        include_str!("fixtures/v4-tcp-odd.hex"),
        include_str!("fixtures/v4-tcp-even.hex"),
        include_str!("fixtures/v4-udp-empty.hex"),
        include_str!("fixtures/v4-udp-odd.hex"),
        include_str!("fixtures/v4-udp-even.hex"),
        include_str!("fixtures/v6-tcp-empty.hex"),
        include_str!("fixtures/v6-tcp-odd.hex"),
        include_str!("fixtures/v6-tcp-even.hex"),
        include_str!("fixtures/v6-udp-empty.hex"),
        include_str!("fixtures/v6-udp-odd.hex"),
        include_str!("fixtures/v6-udp-even.hex"),
        include_str!("fixtures/v6-tcp-options.hex"),
        include_str!("fixtures/v6-udp-negative-zero.hex"),
    ]
    .into_iter()
    .map(hex)
    .collect()
}
#[test]
fn independent_python_vectors_pass_both_policies() {
    for b in fixtures().into_iter().chain([
        include_bytes!("fixtures/v6-udp-max.bin").to_vec(),
        include_bytes!("fixtures/v4-tcp-max.bin").to_vec(),
    ]) {
        for policy in [
            ChecksumPolicy::Require,
            ChecksumPolicy::AllowIpv4UdpOmission,
        ] {
            let checked = parse_checked(&b, policy).unwrap();
            assert_eq!(checked.packet, parse(&b).unwrap());
            assert_eq!(checked.transport_checksum, TransportChecksum::Verified);
        }
    }
}
#[test]
fn single_bit_transport_corruption_rejected() {
    for b in fixtures() {
        let offset = if b[0] >> 4 == 4 { 20 } else { 40 };
        // Includes ports, length/data-offset, checksum field, options and payload.
        for index in offset..b.len() {
            for bit in 0..8 {
                let mut corrupt = b.clone();
                corrupt[index] ^= 1 << bit;
                assert!(
                    parse_checked(&corrupt, ChecksumPolicy::Require).is_err(),
                    "index={index} bit={bit}"
                );
            }
        }
    }
}
#[test]
fn header_and_pseudo_header_corruption_rejected() {
    let original = hex(include_str!("fixtures/v4-tcp-odd.hex"));
    for index in [1, 4, 8, 10, 12, 16] {
        let mut b = original.clone();
        b[index] ^= 1;
        assert_eq!(
            parse_checked(&b, ChecksumPolicy::Require),
            Err(ParseError::InvalidIpv4Checksum)
        );
    }
    let original = hex(include_str!("fixtures/v6-tcp-odd.hex"));
    for index in 8..40 {
        let mut b = original.clone();
        b[index] ^= 1;
        assert_eq!(
            parse_checked(&b, ChecksumPolicy::Require),
            Err(ParseError::InvalidTransportChecksum)
        );
    }
    // Hop limit is outside IPv6's transport pseudo-header; IPv6 has no header checksum.
    let mut b = original;
    b[7] ^= 1;
    assert!(parse_checked(&b, ChecksumPolicy::Require).is_ok());
}
#[test]
fn udp_omission_is_explicit_and_ipv6_never_allows_it() {
    for v6 in [false, true] {
        let mut b = hex(if v6 {
            include_str!("fixtures/v6-udp-odd.hex")
        } else {
            include_str!("fixtures/v4-udp-odd.hex")
        });
        let offset = if v6 { 40 } else { 20 };
        b[offset + 6..offset + 8].fill(0);
        assert_eq!(
            parse_checked(&b, ChecksumPolicy::Require),
            Err(ParseError::MissingTransportChecksum)
        );
        let allowed = parse_checked(&b, ChecksumPolicy::AllowIpv4UdpOmission);
        if v6 {
            assert_eq!(allowed, Err(ParseError::MissingTransportChecksum));
        } else {
            assert_eq!(
                allowed.unwrap().transport_checksum,
                TransportChecksum::OmittedIpv4Udp
            );
        }
        assert!(parse(&b).is_ok());
    }
}
#[test]
fn ones_udp_checksum_is_not_treated_as_omitted() {
    let b = hex(include_str!("fixtures/v6-udp-negative-zero.hex"));
    assert_eq!(&b[46..48], &[255, 255]);
    assert_eq!(
        parse_checked(&b, ChecksumPolicy::Require)
            .unwrap()
            .transport_checksum,
        TransportChecksum::Verified
    );
}
#[test]
fn malformed_structure_precedes_checksum_errors() {
    for b in fixtures() {
        for length in 0..b.len() {
            assert_eq!(
                parse_checked(&b[..length], ChecksumPolicy::Require).unwrap_err(),
                parse(&b[..length]).unwrap_err()
            );
        }
    }
}

#[test]
fn ipv4_pseudo_header_corruption_with_repaired_ip_checksum_rejected() {
    let b = hex(include_str!("fixtures/v4-tcp-bad-pseudo.hex"));
    assert_eq!(
        parse_checked(&b, ChecksumPolicy::Require),
        Err(ParseError::InvalidTransportChecksum)
    );
}
#[test]
fn zero_tcp_checksum_can_be_valid_and_is_not_udp_omission() {
    let b = hex(include_str!("fixtures/v6-tcp-zero-checksum.hex"));
    assert_eq!(&b[56..58], &[0, 0]);
    assert_eq!(
        parse_checked(&b, ChecksumPolicy::Require)
            .unwrap()
            .transport_checksum,
        TransportChecksum::Verified
    );
}
#[test]
fn ipv4_udp_omission_still_requires_a_valid_ip_header() {
    let mut b = hex(include_str!("fixtures/v4-udp-odd.hex"));
    b[26..28].fill(0);
    b[8] ^= 1;
    assert_eq!(
        parse_checked(&b, ChecksumPolicy::AllowIpv4UdpOmission),
        Err(ParseError::InvalidIpv4Checksum)
    );
}
