use netscope_conntrack::FlowId;
use netscope_engine::{Config, DropReason, Engine, Outcome, MAX_FLOWS};
use netscope_packet::{parse, udp, ChecksumPolicy, ParseError};
use netscope_policy::{Action, Policy, Rule};
fn packet(port: u16) -> Vec<u8> {
    udp::encode(
        format!("192.0.2.1:{port}").parse().unwrap(),
        "198.51.100.2:53".parse().unwrap(),
        b"abc",
    )
    .unwrap()
}
fn engine(capacity: usize) -> Engine {
    Engine::new(
        Policy::new(vec![], Action::Allow).unwrap(),
        Config {
            max_flows: capacity,
            timeout: 10,
            checksums: ChecksumPolicy::Require,
        },
    )
    .unwrap()
}
fn accepted(outcome: Outcome) -> bool {
    matches!(outcome, Outcome::Accepted { .. })
}
#[test]
fn integrity_precedes_policy_even_when_default_allows() {
    let mut e = engine(2);
    let mut b = packet(1234);
    *b.last_mut().unwrap() ^= 1;
    assert_eq!(
        e.process(&b, 0),
        Outcome::Dropped(DropReason::Packet(ParseError::InvalidTransportChecksum))
    );
    assert_eq!(e.flow_count(), 0);
    assert_eq!(e.stats().malformed, 1);
}
#[test]
fn bounded_flow_capacity_expiration_clock_and_zero_config() {
    let mut e = engine(1);
    assert!(accepted(e.process(&packet(1), 0)));
    assert_eq!(
        e.process(&packet(2), 1),
        Outcome::Dropped(DropReason::FlowCapacity)
    );
    assert_eq!(
        e.process(&packet(1), 0),
        Outcome::Dropped(DropReason::ClockReversed)
    );
    assert_eq!(e.flow_count(), 1);
    assert!(accepted(e.process(&packet(2), 10)));
    assert_eq!(e.flow_count(), 1);
    assert_eq!(e.stats().accepted, 2);
    assert_eq!(
        engine(0).process(&packet(1), 0),
        Outcome::Dropped(DropReason::FlowCapacity)
    );
    assert!(Engine::new(
        Policy::new(vec![], Action::Deny).unwrap(),
        Config {
            max_flows: MAX_FLOWS + 1,
            timeout: 1,
            checksums: ChecksumPolicy::Require
        }
    )
    .is_err());
}
#[test]
fn policy_updates_are_atomic_and_revoke_existing_flows() {
    let mut e = engine(2);
    let b = packet(1);
    assert!(accepted(e.process(&b, 0)));
    let invalid = Rule {
        priority: 0,
        action: Action::Deny,
        source: None,
        destination: None,
        protocol: None,
        source_port: Some(std::ops::RangeInclusive::new(9, 1)),
        destination_port: None,
    };
    assert!(e.update_policy(vec![invalid], Action::Deny).is_err());
    assert_eq!(e.flow_count(), 1);
    assert!(accepted(e.process(&b, 1)));
    e.update_policy(vec![], Action::Deny).unwrap();
    assert_eq!(e.flow_count(), 0);
    assert_eq!(
        e.process(&b, 2),
        Outcome::Dropped(DropReason::Policy { rule_index: None })
    );
}
#[test]
fn responses_require_active_reverse_tuple_and_current_policy() {
    let mut e = engine(1);
    let b = packet(1234);
    let p = parse(&b).unwrap();
    let id = FlowId::from(&p);
    let response = udp::encode(
        "198.51.100.2:53".parse().unwrap(),
        "192.0.2.1:1234".parse().unwrap(),
        b"reply",
    )
    .unwrap();
    assert_eq!(
        e.authorize_response(&response, &id, 0),
        Outcome::Dropped(DropReason::UnmatchedResponse)
    );
    assert!(accepted(e.process(&b, 0)));
    assert!(accepted(e.authorize_response(&response, &id, 1)));
    assert_eq!(e.flow_count(), 1);
    let bad = udp::encode(
        "198.51.100.3:53".parse().unwrap(),
        "192.0.2.1:1234".parse().unwrap(),
        b"reply",
    )
    .unwrap();
    assert_eq!(
        e.authorize_response(&bad, &id, 1),
        Outcome::Dropped(DropReason::UnmatchedResponse)
    );
    assert_eq!(
        e.authorize_response(&response, &id, 10),
        Outcome::Dropped(DropReason::UnmatchedResponse)
    );
    assert_eq!(e.flow_count(), 0);
    assert_eq!(e.stats().unmatched_responses, 3);
}
#[test]
fn inbound_allow_is_not_inherited_from_outbound_allow() {
    let only_outbound = Rule {
        priority: 0,
        action: Action::Allow,
        source: None,
        destination: None,
        protocol: None,
        source_port: Some(1234..=1234),
        destination_port: Some(53..=53),
    };
    let mut e = Engine::new(
        Policy::new(vec![only_outbound], Action::Deny).unwrap(),
        Config {
            max_flows: 1,
            timeout: 10,
            checksums: ChecksumPolicy::Require,
        },
    )
    .unwrap();
    let b = packet(1234);
    assert!(accepted(e.process(&b, 0)));
    let id = FlowId::from(&parse(&b).unwrap());
    let response = udp::encode(
        "198.51.100.2:53".parse().unwrap(),
        "192.0.2.1:1234".parse().unwrap(),
        b"reply",
    )
    .unwrap();
    assert_eq!(
        e.authorize_response(&response, &id, 1),
        Outcome::Dropped(DropReason::Policy { rule_index: None })
    );
}
#[test]
fn network_reset_keeps_monotonic_clock_and_explicit_omission_policy() {
    let mut e = engine(1);
    let b = packet(1);
    assert!(accepted(e.process(&b, 4)));
    assert_eq!(e.reset_network(), 1);
    assert_eq!(e.flow_count(), 0);
    assert_eq!(
        e.process(&b, 3),
        Outcome::Dropped(DropReason::ClockReversed)
    );
    let mut omitted = b;
    omitted[26..28].fill(0);
    assert_eq!(
        e.process(&omitted, 4),
        Outcome::Dropped(DropReason::Packet(ParseError::MissingTransportChecksum))
    );
    let mut allowed = Engine::new(
        Policy::new(vec![], Action::Allow).unwrap(),
        Config {
            max_flows: 1,
            timeout: 10,
            checksums: ChecksumPolicy::AllowIpv4UdpOmission,
        },
    )
    .unwrap();
    assert!(accepted(allowed.process(&omitted, 0)));
}
#[test]
fn refresh_extends_an_existing_flow_but_never_creates_one() {
    let mut e = engine(2);
    let id = FlowId::from(&parse(&packet(1234)).unwrap());
    e.refresh_flow(&id, 0);
    assert_eq!(e.flow_count(), 0, "refresh must not create a flow");
    assert!(accepted(e.process(&packet(1234), 0)));
    e.refresh_flow(&id, 9);
    assert_eq!(e.expire(18), Ok(0));
    assert!(e.contains_flow(&id));
    assert_eq!(e.expire(19), Ok(1));
}
