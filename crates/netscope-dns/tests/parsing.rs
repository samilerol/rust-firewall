use netscope_dns::{decode_name, parse_query, parse_response, DomainName, ParseError};
fn query() -> Vec<u8> {
    // Standard wire query: ID 0x1234, RD, one IN/A question for Example.COM.
    vec![
        0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 7, b'E', b'x', b'a', b'm', b'p', b'l', b'e', 3,
        b'C', b'O', b'M', 0, 0, 1, 0, 1,
    ]
}
fn response() -> Vec<u8> {
    let mut b = query();
    b[2..4].copy_from_slice(&0x8180u16.to_be_bytes());
    b[7] = 1;
    b.extend_from_slice(&[0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 1, 2, 3, 4]);
    b
}
#[test]
fn standard_query_and_compressed_response_preserve_question_identity() {
    let q = parse_query(&query()).unwrap();
    let r = parse_response(&response()).unwrap();
    assert_eq!(q.id, 0x1234);
    assert_eq!(q.question.name.as_str(), "example.com");
    assert_eq!(q.question.qtype, 1);
    assert_eq!(q.question, r.question);
    assert!(!r.truncated);
    assert!(parse_response(&query()).is_err());
    assert!(parse_query(&response()).is_err());
}
#[test]
fn every_truncated_prefix_and_trailing_bytes_rejected() {
    for b in [query(), response()] {
        for n in 0..b.len() {
            assert!(parse_query(&b[..n]).is_err());
            assert!(parse_response(&b[..n]).is_err());
        }
    }
    let mut q = query();
    q.push(0);
    assert_eq!(parse_query(&q), Err(ParseError::Trailing));
}
#[test]
fn compressed_name_returns_original_end_and_supports_nested_backward_pointers() {
    let mut b = query();
    let first = b.len();
    b.extend_from_slice(&[0xc0, 12]);
    let second = b.len();
    b.extend_from_slice(&[0xc0, first as u8]);
    let (name, end) = decode_name(&b, second).unwrap();
    assert_eq!(name.as_str(), "example.com");
    assert_eq!(end, second + 2);
}
#[test]
fn compression_cycles_forward_header_and_missing_targets_rejected() {
    for suffix in [
        vec![0xc0, 12],
        vec![0xc0, 14, 0],
        vec![0xc0, 0],
        vec![0xff, 0xff],
        vec![0xc0],
        vec![1, b'a', 0xc0, 12],
    ] {
        let mut b = vec![0; 12];
        b.extend(suffix);
        assert!(decode_name(&b, 12).is_err());
    }
    // Seventeen pointer hops exceed the explicit work budget.
    let mut b = query();
    let mut previous = 12;
    for _ in 0..17 {
        let at = b.len();
        b.extend_from_slice(&[0xc0, previous as u8]);
        previous = at;
    }
    assert_eq!(decode_name(&b, previous), Err(ParseError::Compression));
}
#[test]
fn name_length_label_grammar_and_idna_are_explicit() {
    let mut b = vec![0; 12];
    for len in [63, 63, 63, 61] {
        b.push(len);
        b.extend(vec![b'a'; usize::from(len)]);
    }
    b.push(0);
    assert_eq!(decode_name(&b, 12).unwrap().0.as_str().len(), 253);
    let mut long = vec![0; 12];
    for len in [63, 63, 63, 62] {
        long.push(len);
        long.extend(vec![b'a'; usize::from(len)]);
    }
    long.push(0);
    assert_eq!(decode_name(&long, 12), Err(ParseError::NameTooLong));
    for suffix in [
        vec![64, 0],
        vec![3, b'a', b'.', b'b', 0],
        vec![2, 0xc3, 0xa9, 0],
        vec![0x80, 0],
    ] {
        let mut b = vec![0; 12];
        b.extend(suffix);
        assert!(decode_name(&b, 12).is_err());
    }
    assert_eq!(
        DomainName::new("XN--BCHER-KVA.Example.").unwrap().as_str(),
        "xn--bcher-kva.example"
    );
    assert!(DomainName::new("bücher.example").is_err());
    assert!(DomainName::new("a..b").is_err());
    assert!(DomainName::new("a..").is_err());
    assert!(DomainName::new(" a.b").is_err());
    assert_eq!(
        DomainName::new("_sip._tcp.example").unwrap().as_str(),
        "_sip._tcp.example"
    );
    assert_eq!(decode_name(&[0; 13], 12).unwrap().0.as_str(), ".");
}
#[test]
fn flags_counts_class_and_message_limits_are_conservative() {
    for (at, value) in [(2, 0x80), (2, 0x08), (3, 0x40), (5, 2), (7, 1), (11, 2)] {
        let mut q = query();
        q[at] = value;
        assert!(parse_query(&q).is_err());
    }
    let mut q = query();
    *q.last_mut().unwrap() = 3;
    assert!(parse_query(&q).is_err());
    let mut q = query();
    q[3] = 0x30;
    assert!(parse_query(&q).is_ok()); // AD/CD queries allowed
    assert_eq!(parse_query(&vec![0; 4097]), Err(ParseError::TooLarge));
    let mut r = response();
    r[6..8].copy_from_slice(&65535u16.to_be_bytes());
    assert_eq!(parse_response(&r), Err(ParseError::Counts));
    let mut r = query();
    r[2..4].copy_from_slice(&0x8380u16.to_be_bytes());
    assert!(parse_response(&r).unwrap().truncated);
}
#[test]
fn edns_options_are_bounded_and_structurally_checked() {
    let mut q = query();
    q[11] = 1;
    q.extend_from_slice(&[0, 0, 41, 4, 208, 0, 0, 0x80, 0, 0, 4, 0, 10, 0, 0]);
    assert!(parse_query(&q).is_ok());
    let mut wrong = q.clone();
    wrong[35] = 1;
    assert!(parse_query(&wrong).is_err()); // unsupported EDNS version
    let mut wrong = q.clone();
    *wrong.last_mut().unwrap() = 1;
    assert!(parse_query(&wrong).is_err()); // option exceeds RDLENGTH
    let mut lots = query();
    lots[11] = 1;
    lots.extend_from_slice(&[0, 0, 41, 4, 208, 0, 0, 0, 0, 0, 132]);
    for _ in 0..33 {
        lots.extend_from_slice(&[0, 1, 0, 0]);
    }
    assert_eq!(parse_query(&lots), Err(ParseError::Counts));
}
#[test]
fn rdata_lengths_and_name_targets_are_checked() {
    let mut r = response();
    r[40] = 3;
    assert!(parse_response(&r).is_err());
    let mut cname = query();
    cname[2..4].copy_from_slice(&0x8180u16.to_be_bytes());
    cname[7] = 1;
    cname.extend_from_slice(&[0xc0, 12, 0, 5, 0, 1, 0, 0, 0, 60, 0, 2, 0xc0, 12]);
    assert!(parse_response(&cname).is_ok());
    let end = cname.len();
    cname[end - 1] = (end - 2) as u8;
    assert!(parse_response(&cname).is_err());
    let mut unknown = query();
    unknown[2..4].copy_from_slice(&0x8180u16.to_be_bytes());
    unknown[7] = 1;
    unknown.extend_from_slice(&[0xc0, 12, 0xfd, 0xe8, 0, 1, 0, 0, 0, 60, 0, 3, 0xff, 0, 0x7f]);
    assert!(parse_response(&unknown).is_ok());
}
