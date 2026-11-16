//! Lower numeric priority wins; equal priorities use input order. Default is explicit.
use netscope_packet::{Packet, Protocol};
use std::{net::IpAddr, ops::RangeInclusive};
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Action {
    Allow,
    Deny,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Cidr {
    network: IpAddr,
    prefix: u8,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InvalidPrefix;
impl Cidr {
    pub fn new(network: IpAddr, prefix: u8) -> Result<Self, InvalidPrefix> {
        if prefix > if network.is_ipv4() { 32 } else { 128 } {
            return Err(InvalidPrefix);
        }
        Ok(Self { network, prefix })
    }
    pub fn contains(&self, address: IpAddr) -> bool {
        match (self.network, address) {
            (IpAddr::V4(a), IpAddr::V4(b)) => {
                self.prefix == 0
                    || (u32::from(a) >> (32 - self.prefix)) == (u32::from(b) >> (32 - self.prefix))
            }
            (IpAddr::V6(a), IpAddr::V6(b)) => {
                self.prefix == 0
                    || (u128::from(a) >> (128 - self.prefix))
                        == (u128::from(b) >> (128 - self.prefix))
            }
            _ => false,
        }
    }
}
#[derive(Clone, Debug)]
pub struct Rule {
    pub priority: u32,
    pub action: Action,
    pub source: Option<Cidr>,
    pub destination: Option<Cidr>,
    pub protocol: Option<Protocol>,
    pub source_port: Option<RangeInclusive<u16>>,
    pub destination_port: Option<RangeInclusive<u16>>,
}
impl Rule {
    pub fn matches(&self, packet: &Packet) -> bool {
        self.source.is_none_or(|c| c.contains(packet.source))
            && self
                .destination
                .is_none_or(|c| c.contains(packet.destination))
            && self.protocol.is_none_or(|p| p == packet.protocol)
            && self
                .source_port
                .as_ref()
                .is_none_or(|r| r.contains(&packet.source_port))
            && self
                .destination_port
                .as_ref()
                .is_none_or(|r| r.contains(&packet.destination_port))
    }
}
/// Absolute rule-count ceiling; callers may impose a smaller bound.
pub const MAX_RULES: usize = 4096;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PolicyError {
    TooManyRules { limit: usize },
    InvalidPortRange { rule_index: usize },
}
#[derive(Debug)]
pub struct Policy {
    rules: Vec<(usize, Rule)>,
    default: Action,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Decision {
    pub action: Action,
    pub rule_index: Option<usize>,
}
impl Policy {
    /// Rules are immutable after construction; index refers to original input order.
    pub fn new(rules: Vec<Rule>, default: Action) -> Result<Self, PolicyError> {
        Self::with_limit(rules, default, MAX_RULES)
    }
    /// Consumes already-allocated rules. Future file loaders must bound input before allocation.
    /// Rejects the entire configuration; never silently truncates or skips invalid rules.
    pub fn with_limit(
        rules: Vec<Rule>,
        default: Action,
        limit: usize,
    ) -> Result<Self, PolicyError> {
        let limit = limit.min(MAX_RULES);
        if rules.len() > limit {
            return Err(PolicyError::TooManyRules { limit });
        }
        for (rule_index, rule) in rules.iter().enumerate() {
            if rule.source_port.as_ref().is_some_and(|r| r.is_empty())
                || rule.destination_port.as_ref().is_some_and(|r| r.is_empty())
            {
                return Err(PolicyError::InvalidPortRange { rule_index });
            }
        }
        let mut rules: Vec<_> = rules.into_iter().enumerate().collect();
        rules.sort_unstable_by_key(|(index, rule)| (rule.priority, *index));
        Ok(Self { rules, default })
    }
    pub fn decide(&self, packet: &Packet) -> Decision {
        let matched = self.rules.iter().find(|(_, r)| r.matches(packet));
        match matched {
            Some((i, r)) => Decision {
                action: r.action,
                rule_index: Some(*i),
            },
            None => Decision {
                action: self.default,
                rule_index: None,
            },
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn cidr(ip: &str, prefix: u8) -> Cidr {
        Cidr::new(ip.parse().unwrap(), prefix).unwrap()
    }
    fn packet() -> Packet {
        Packet {
            source: "10.0.0.1".parse().unwrap(),
            destination: "1.1.1.1".parse().unwrap(),
            source_port: 1234,
            destination_port: 443,
            protocol: Protocol::Tcp,
            length: 40,
        }
    }
    fn rule(priority: u32, action: Action) -> Rule {
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
    #[test]
    fn cidr_boundaries() {
        for (net, prefix, inside, outside) in [
            ("10.0.0.9", 24, "10.0.0.255", "10.0.1.0"),
            ("10.0.0.1", 32, "10.0.0.1", "10.0.0.2"),
            ("2001:db8::1", 64, "2001:db8::ffff", "2001:db8:0:1::"),
            ("::1", 128, "::1", "::2"),
        ] {
            let c = cidr(net, prefix);
            assert!(c.contains(inside.parse().unwrap()));
            assert!(!c.contains(outside.parse().unwrap()));
        }
        assert!(cidr("1.2.3.4", 0).contains("255.255.255.255".parse().unwrap()));
        assert!(cidr("::1", 0).contains("ffff::".parse().unwrap()));
        assert!(!cidr("::", 0).contains("0.0.0.0".parse().unwrap()));
        assert!(Cidr::new("0.0.0.0".parse().unwrap(), 33).is_err());
        assert!(Cidr::new("::".parse().unwrap(), 129).is_err());
    }
    #[test]
    fn overlap_priority_ties_and_defaults() {
        let p = packet();
        assert_eq!(
            Policy::new(vec![], Action::Deny).unwrap().decide(&p).action,
            Action::Deny
        );
        let mut allow = rule(5, Action::Allow);
        allow.source = Some(cidr("10.0.0.0", 24));
        let policy = Policy::new(
            vec![rule(10, Action::Deny), allow.clone(), rule(5, Action::Deny)],
            Action::Deny,
        )
        .unwrap();
        assert_eq!(
            policy.decide(&p),
            Decision {
                action: Action::Allow,
                rule_index: Some(1)
            }
        );
        assert_eq!(
            Policy::new(vec![rule(5, Action::Deny), allow], Action::Allow)
                .unwrap()
                .decide(&p)
                .action,
            Action::Deny
        );
    }
    #[test]
    fn every_filter_is_required() {
        let mut r = rule(0, Action::Allow);
        let p = packet();
        r.source = Some(cidr("10.0.0.0", 24));
        r.destination = Some(cidr("1.1.1.1", 32));
        r.protocol = Some(Protocol::Tcp);
        r.source_port = Some(1234..=1234);
        r.destination_port = Some(443..=443);
        assert!(r.matches(&p));
        let variants = [
            Packet {
                source: "10.1.0.1".parse().unwrap(),
                ..p
            },
            Packet {
                destination: "1.1.1.2".parse().unwrap(),
                ..p
            },
            Packet {
                protocol: Protocol::Udp,
                ..p
            },
            Packet {
                source_port: 1235,
                ..p
            },
            Packet {
                destination_port: 444,
                ..p
            },
        ];
        for v in variants {
            assert!(!r.matches(&v));
        }
    }
    #[test]
    fn configuration_limits_and_invalid_ranges_reject_whole_policy() {
        assert!(Policy::with_limit(vec![], Action::Deny, 0).is_ok());
        assert_eq!(
            Policy::with_limit(vec![rule(1, Action::Deny)], Action::Allow, 0).unwrap_err(),
            PolicyError::TooManyRules { limit: 0 }
        );
        assert!(Policy::with_limit(vec![rule(1, Action::Deny)], Action::Allow, 1).is_ok());
        assert!(Policy::new(vec![rule(1, Action::Deny); MAX_RULES], Action::Deny).is_ok());
        assert_eq!(
            Policy::with_limit(
                vec![rule(1, Action::Deny); MAX_RULES + 1],
                Action::Allow,
                usize::MAX
            )
            .unwrap_err(),
            PolicyError::TooManyRules { limit: MAX_RULES }
        );
        for source in [true, false] {
            let mut invalid = rule(0, Action::Deny);
            let reversed = RangeInclusive::new(100, 99);
            if source {
                invalid.source_port = Some(reversed);
            } else {
                invalid.destination_port = Some(reversed);
            }
            assert_eq!(
                Policy::new(vec![rule(5, Action::Allow), invalid], Action::Allow).unwrap_err(),
                PolicyError::InvalidPortRange { rule_index: 1 }
            );
        }
    }
    #[test]
    fn cidr_prefix_properties_for_every_prefix() {
        // Independent mask oracle, all prefix lengths and every one-bit address difference.
        let base = 0x20010db812345678fedcba9876543210u128;
        for prefix in 0..=128u8 {
            let c = Cidr::new(IpAddr::V6(base.into()), prefix).unwrap();
            let mask = if prefix == 0 {
                0
            } else {
                u128::MAX << (128 - prefix)
            };
            for bit in 0..128 {
                let other = base ^ (1u128 << bit);
                assert_eq!(
                    c.contains(IpAddr::V6(other.into())),
                    (base & mask) == (other & mask)
                );
            }
        }
        let base = 0xc0000201u32;
        for prefix in 0..=32u8 {
            let c = Cidr::new(IpAddr::V4(base.into()), prefix).unwrap();
            let mask = if prefix == 0 {
                0
            } else {
                u32::MAX << (32 - prefix)
            };
            for bit in 0..32 {
                let other = base ^ (1u32 << bit);
                assert_eq!(
                    c.contains(IpAddr::V4(other.into())),
                    (base & mask) == (other & mask)
                );
            }
        }
    }
    #[test]
    fn compiled_precedence_matches_original_order_linear_oracle() {
        let mut seed = 17u64;
        for round in 0..64 {
            let mut rules = Vec::new();
            for _ in 0..96 {
                seed ^= seed << 13;
                seed ^= seed >> 7;
                seed ^= seed << 17;
                let mut r = rule(
                    (seed % 8) as u32,
                    if seed & 1 == 0 {
                        Action::Allow
                    } else {
                        Action::Deny
                    },
                );
                r.destination_port = Some((seed % 16) as u16..=(seed % 16 + 4) as u16);
                rules.push(r);
            }
            let default = if round % 2 == 0 {
                Action::Allow
            } else {
                Action::Deny
            };
            let policy = Policy::new(rules.clone(), default).unwrap();
            for port in 0..32 {
                let p = Packet {
                    destination_port: port,
                    ..packet()
                };
                let expected = rules
                    .iter()
                    .enumerate()
                    .filter(|(_, r)| r.matches(&p))
                    .min_by_key(|(i, r)| (r.priority, *i));
                let decision = expected.map_or(
                    Decision {
                        action: default,
                        rule_index: None,
                    },
                    |(i, r)| Decision {
                        action: r.action,
                        rule_index: Some(i),
                    },
                );
                assert_eq!(policy.decide(&p), decision);
            }
        }
    }
}
