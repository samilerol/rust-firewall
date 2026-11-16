use netscope_packet::{
    parse_checked,
    udp::{encode, EncodeError},
    ChecksumPolicy,
};
#[test]
fn independent_oracle_vectors_match_udp_encoding() {
    for (v6, text) in [
        (false, include_str!("fixtures/v4-udp-odd.hex")),
        (true, include_str!("fixtures/v6-udp-odd.hex")),
    ] {
        let expected: Vec<_> = text
            .trim()
            .as_bytes()
            .chunks_exact(2)
            .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap())
            .collect();
        let (src, dst) = if v6 {
            ("[2001:db8::1]:12345", "[2001:db8::2]:53")
        } else {
            ("192.0.2.1:12345", "198.51.100.2:53")
        };
        let encoded = encode(src.parse().unwrap(), dst.parse().unwrap(), b"abc").unwrap();
        let offset = if v6 { 40 } else { 20 };
        assert_eq!(&encoded[offset..], &expected[offset..]);
        assert!(parse_checked(&encoded, ChecksumPolicy::Require).is_ok());
    }
}
#[test]
fn boundary_payloads_families_and_negative_zero() {
    for v6 in [false, true] {
        let (src, dst, max) = if v6 {
            ("[2001:db8::1]:12345", "[2001:db8::2]:53", 65527)
        } else {
            ("192.0.2.1:12345", "198.51.100.2:53", 65507)
        };
        for length in [0, 1, 2, 3, max] {
            let payload = vec![0xff; length];
            let bytes = encode(src.parse().unwrap(), dst.parse().unwrap(), &payload).unwrap();
            assert!(parse_checked(&bytes, ChecksumPolicy::Require).is_ok());
            assert_eq!(&bytes[if v6 { 48 } else { 28 }..], payload);
        }
        assert_eq!(
            encode(
                src.parse().unwrap(),
                dst.parse().unwrap(),
                &vec![0; max + 1]
            ),
            Err(EncodeError::PayloadTooLarge)
        );
    }
    assert_eq!(
        encode(
            "127.0.0.1:1".parse().unwrap(),
            "[::1]:2".parse().unwrap(),
            &[]
        ),
        Err(EncodeError::AddressFamily)
    );
    let reference = include_str!("fixtures/v6-udp-negative-zero.hex").trim();
    let bytes: Vec<_> = reference
        .as_bytes()
        .chunks_exact(2)
        .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap())
        .collect();
    assert_eq!(
        encode(
            "[2001:db8::1]:12345".parse().unwrap(),
            "[2001:db8::2]:53".parse().unwrap(),
            &bytes[48..]
        )
        .unwrap(),
        bytes
    );
}
