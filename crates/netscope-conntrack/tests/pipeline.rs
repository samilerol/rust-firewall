use netscope_conntrack::{FlowId, Tracker};
use netscope_packet::parse;
use netscope_policy::{Action, Policy, Rule};

#[test]
fn parse_decide_then_track_only_allowed_packets() {
    let mut bytes = [0u8; 28];
    bytes[0] = 0x45;
    bytes[2..4].copy_from_slice(&28u16.to_be_bytes());
    bytes[9] = 17;
    bytes[12..16].copy_from_slice(&[10, 0, 0, 1]);
    bytes[16..20].copy_from_slice(&[1, 1, 1, 1]);
    bytes[20..22].copy_from_slice(&1234u16.to_be_bytes());
    bytes[22..24].copy_from_slice(&53u16.to_be_bytes());
    bytes[24..26].copy_from_slice(&8u16.to_be_bytes());
    let policy = Policy::new(
        vec![Rule {
            priority: 1,
            action: Action::Allow,
            source: None,
            destination: None,
            protocol: Some(netscope_packet::Protocol::Udp),
            source_port: None,
            destination_port: Some(53..=53),
        }],
        Action::Deny,
    );
    let mut tracker = Tracker::new(1, 10);
    for (port, expected) in [(53u16, Action::Allow), (443, Action::Deny)] {
        bytes[22..24].copy_from_slice(&port.to_be_bytes());
        let packet = parse(&bytes).unwrap();
        let decision = policy.decide(&packet);
        assert_eq!(decision.action, expected);
        if decision.action == Action::Allow {
            tracker.observe(FlowId::from(&packet), 1).unwrap();
        }
    }
    assert_eq!(tracker.len(), 1);
    assert_eq!(tracker.expire(11), Ok(1));
    assert!(tracker.is_empty());
}
