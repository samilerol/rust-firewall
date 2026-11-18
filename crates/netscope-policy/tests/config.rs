use netscope_packet::{Packet, Protocol};
use netscope_policy::{
    config::{parse_policy, parse_policy_from, ConfigErrorKind, MAX_CONFIG_BYTES, MAX_LINE_BYTES},
    Action, Cidr, Context, ContextRule, Network, Policy, PolicyError, Rule, UidMatch,
};
use std::io;

const SAMPLE: &str = "\
# sample
default deny

allow priority=10 proto=tcp dst=10.0.0.0/8 dport=443 uid=10001-10099 network=wifi
deny  dst=203.0.113.0/24   # blocked range
allow proto=udp dport=53 uid=unknown
allow src=2001:db8::/32 sport=1000-2000
";

fn packet(dst: &str, protocol: Protocol, sport: u16, dport: u16) -> Packet {
    Packet {
        source: "10.1.1.1".parse().unwrap(),
        destination: dst.parse().unwrap(),
        source_port: sport,
        destination_port: dport,
        protocol,
        length: 60,
    }
}
fn cidr(text: &str, prefix: u8) -> Option<Cidr> {
    Some(Cidr::new(text.parse().unwrap(), prefix).unwrap())
}
fn plain(priority: u32, action: Action) -> Rule {
    Rule {
        priority,
        action,
        source: None,
        destination: None,
        protocol: None,
        source_port: None,
        destination_port: None,
    }
}
fn err(text: &str) -> (usize, ConfigErrorKind) {
    let e = parse_policy(text.as_bytes()).unwrap_err();
    (e.line, e.kind)
}

#[test]
fn a_valid_file_equals_the_hand_built_policy_on_every_probe() {
    let parsed = parse_policy(SAMPLE.as_bytes()).unwrap();
    let mut first = plain(10, Action::Allow);
    first.protocol = Some(Protocol::Tcp);
    first.destination = cidr("10.0.0.0", 8);
    first.destination_port = Some(443..=443);
    let mut second = plain(0, Action::Deny);
    second.destination = cidr("203.0.113.0", 24);
    let mut third = plain(0, Action::Allow);
    third.protocol = Some(Protocol::Udp);
    third.destination_port = Some(53..=53);
    let mut fourth = plain(0, Action::Allow);
    fourth.source = cidr("2001:db8::", 32);
    fourth.source_port = Some(1000..=2000);
    let expected = Policy::with_context_rules(
        vec![
            ContextRule {
                rule: first,
                uid: Some(UidMatch::Range(10_001..=10_099)),
                network: Some(Network::Wifi),
            },
            second.into(),
            ContextRule {
                rule: third,
                uid: Some(UidMatch::Unknown),
                network: None,
            },
            fourth.into(),
        ],
        Action::Deny,
    )
    .unwrap();
    let contexts = [
        Context::default(),
        Context {
            uid: Some(10_050),
            network: Network::Wifi,
        },
        Context {
            uid: Some(10_050),
            network: Network::Cellular,
        },
        Context {
            uid: Some(5),
            network: Network::Wifi,
        },
    ];
    let packets = [
        packet("10.9.9.9", Protocol::Tcp, 40000, 443),
        packet("10.9.9.9", Protocol::Tcp, 40000, 80),
        packet("203.0.113.5", Protocol::Tcp, 40000, 443),
        packet("8.8.8.8", Protocol::Udp, 40000, 53),
        packet("8.8.8.8", Protocol::Udp, 40000, 54),
    ];
    for packet in &packets {
        for context in &contexts {
            assert_eq!(
                parsed.decide_in(packet, context),
                expected.decide_in(packet, context),
                "{packet:?} {context:?}"
            );
        }
    }
}

#[test]
fn file_order_breaks_priority_ties_and_crlf_and_missing_final_newline_are_accepted() {
    let policy = parse_policy(
        b"default allow\r\ndeny proto=tcp\r\nallow proto=tcp\r\nallow priority=0 proto=udp",
    )
    .unwrap();
    let tcp = policy.decide(&packet("1.1.1.1", Protocol::Tcp, 1, 2));
    assert_eq!((tcp.action, tcp.rule_index), (Action::Deny, Some(0)));
    let udp = policy.decide(&packet("1.1.1.1", Protocol::Udp, 1, 2));
    assert_eq!((udp.action, udp.rule_index), (Action::Allow, Some(2)));
}

#[test]
fn every_malformed_input_rejects_the_whole_file_with_a_line_number() {
    use ConfigErrorKind::*;
    assert_eq!(err(""), (0, MissingDefault));
    assert_eq!(err("allow\n"), (0, MissingDefault));
    assert_eq!(err("default deny\ndefault allow"), (2, DuplicateDefault));
    assert_eq!(err("default maybe"), (1, BadValue));
    assert_eq!(err("default"), (1, BadValue));
    assert_eq!(err("default deny extra"), (1, BadValue));
    assert_eq!(err("default deny\nblock"), (2, UnknownDirective));
    assert_eq!(err("default deny\nallow color=red"), (2, UnknownKey));
    assert_eq!(err("default deny\nallow tcp"), (2, UnknownKey));
    assert_eq!(
        err("default deny\nallow proto=tcp proto=udp"),
        (2, DuplicateKey)
    );
    for bad in [
        "proto=icmp",
        "dst=10.0.0.0",
        "dst=10.0.0.0/33",
        "dst=::/129",
        "dst=nonsense/8",
        "dport=65536",
        "dport=1-70000",
        "sport=-5",
        "sport=",
        "priority=-1",
        "priority=4294967296",
        "uid=abc",
        "uid=1-",
        "network=satellite",
    ] {
        assert_eq!(
            err(&format!("default deny\nallow {bad}")),
            (2, BadValue),
            "{bad}"
        );
    }
    // Inverted ranges are reported by the policy with the rule's index.
    assert_eq!(
        err("default deny\nallow dport=9-1"),
        (0, Policy(PolicyError::InvalidPortRange { rule_index: 0 }))
    );
    assert_eq!(
        err("default deny\nallow\nallow uid=9-1"),
        (0, Policy(PolicyError::InvalidUidRange { rule_index: 1 }))
    );
}

#[test]
fn limits_are_enforced_before_allocating_for_the_data_they_bound() {
    use ConfigErrorKind::*;
    let mut many = String::from("default deny\n");
    for _ in 0..4096 {
        many.push_str("allow\n");
    }
    assert!(parse_policy(many.as_bytes()).is_ok());
    many.push_str("allow\n");
    let rejected = parse_policy(many.as_bytes()).unwrap_err();
    assert_eq!((rejected.line, rejected.kind), (4098, TooManyRules));

    let huge = vec![b'#'; MAX_CONFIG_BYTES + 1];
    assert_eq!(parse_policy(&huge).unwrap_err().kind, TooLarge);
    // An endless reader is cut off at the limit instead of exhausting memory.
    assert_eq!(
        parse_policy_from(io::repeat(b'#')).unwrap_err().kind,
        TooLarge
    );
    assert!(parse_policy_from(SAMPLE.as_bytes()).is_ok());

    let long = format!("default deny\n# {}\n", "x".repeat(MAX_LINE_BYTES));
    assert_eq!(parse_policy(long.as_bytes()).unwrap_err().kind, LineTooLong);
    assert_eq!(parse_policy(&[0xff, 0xfe]).unwrap_err().kind, NotUtf8);
}

#[test]
fn arbitrary_mutations_never_panic() {
    // Deterministic xorshift so a failure is reproducible without a fuzzer.
    let mut state = 0x9e3779b97f4a7c15u64;
    let mut next = move || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    let base = SAMPLE.as_bytes();
    for _ in 0..20_000 {
        let mut input = base.to_vec();
        for _ in 0..(next() % 6) {
            let at = (next() as usize) % input.len();
            match next() % 4 {
                0 => input[at] = next() as u8,
                1 => {
                    input.remove(at);
                }
                2 => input.insert(at, b"=-/ #\n\xff"[(next() % 7) as usize]),
                _ => input.truncate(at),
            }
            if input.is_empty() {
                input.push(b'a');
            }
        }
        let _ = parse_policy(&input);
    }
}
