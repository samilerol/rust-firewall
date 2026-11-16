#![no_main]
use libfuzzer_sys::fuzz_target;
use netscope_engine::{Config, Engine, Outcome};
use netscope_packet::{udp, ChecksumPolicy};
use netscope_policy::{Action, Policy, Rule};
fuzz_target!(|input: &[u8]| {
    let mut engine = Engine::new(
        Policy::new(vec![], Action::Deny).unwrap(),
        Config {
            max_flows: 8,
            timeout: 10,
            checksums: ChecksumPolicy::Require,
        },
    )
    .unwrap();
    let mut allowed = false;
    let mut now = 0u64;
    for bytes in input.chunks(16).take(64) {
        if bytes.len() < 2 {
            continue;
        }
        now += u64::from(bytes[1] & 3);
        match bytes[0] % 6 {
            0 => {
                let source = format!("192.0.2.1:{}", u16::from(bytes[1]) + 1)
                    .parse()
                    .unwrap();
                let packet =
                    udp::encode(source, "198.51.100.2:53".parse().unwrap(), bytes).unwrap();
                let time = if bytes[1] & 128 != 0 {
                    now.saturating_sub(4)
                } else {
                    now
                };
                if matches!(engine.process(&packet, time), Outcome::Accepted { .. }) {
                    assert!(allowed);
                }
            }
            1 => {
                engine.update_policy(vec![], Action::Deny).unwrap();
                allowed = false;
                assert_eq!(engine.flow_count(), 0);
            }
            2 => {
                engine.update_policy(vec![], Action::Allow).unwrap();
                allowed = true;
                assert_eq!(engine.flow_count(), 0);
            }
            3 => {
                engine.reset_network();
                assert_eq!(engine.flow_count(), 0);
            }
            4 => {
                let _ = engine.expire(now);
            }
            _ => {
                let before = engine.flow_count();
                let invalid = Rule {
                    priority: 0,
                    action: Action::Allow,
                    source: None,
                    destination: None,
                    protocol: None,
                    source_port: Some(std::ops::RangeInclusive::new(2, 1)),
                    destination_port: None,
                };
                assert!(engine.update_policy(vec![invalid], Action::Allow).is_err());
                assert_eq!(engine.flow_count(), before);
            }
        }
        assert!(engine.flow_count() <= 8);
    }
});
