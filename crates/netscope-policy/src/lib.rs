//! Lower numeric priority wins; equal priorities use input order. Default is explicit.
pub mod config;
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
/// Coarse class of the network a flow uses. Supplied by the caller; never inferred from packets.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum Network {
    #[default]
    Unknown,
    Wifi,
    Cellular,
    Other,
}
/// Caller-supplied facts about a flow that packets cannot prove. The default (unknown uid,
/// unknown network) is what the context-free APIs use. Treat these as untrusted-quality
/// attribution: the platform's resolution can fail or race, which is why `Unknown` is explicit.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Context {
    /// Owning application uid, or None when it could not be resolved.
    pub uid: Option<u32>,
    pub network: Network,
}
/// Uid constraint of a context rule. `Unknown` matches only flows whose uid is unresolved;
/// `Range` never matches an unresolved uid.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum UidMatch {
    Unknown,
    Range(RangeInclusive<u32>),
}
/// A packet [`Rule`] plus optional uid/network constraints; all present constraints must match.
#[derive(Clone, Debug)]
pub struct ContextRule {
    pub rule: Rule,
    pub uid: Option<UidMatch>,
    pub network: Option<Network>,
}
impl From<Rule> for ContextRule {
    fn from(rule: Rule) -> Self {
        Self {
            rule,
            uid: None,
            network: None,
        }
    }
}
impl ContextRule {
    fn matches(&self, packet: &Packet, context: &Context) -> bool {
        self.rule.matches(packet)
            && self
                .uid
                .as_ref()
                .is_none_or(|wanted| match (wanted, context.uid) {
                    (UidMatch::Unknown, None) => true,
                    (UidMatch::Range(range), Some(uid)) => range.contains(&uid),
                    _ => false,
                })
            && self.network.is_none_or(|wanted| wanted == context.network)
    }
}
/// Absolute rule-count ceiling; callers may impose a smaller bound.
pub const MAX_RULES: usize = 4096;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PolicyError {
    TooManyRules { limit: usize },
    InvalidPortRange { rule_index: usize },
    InvalidUidRange { rule_index: usize },
}
#[derive(Debug)]
pub struct Policy {
    rules: Vec<(usize, ContextRule)>,
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
        Self::with_context_limit(
            rules.into_iter().map(ContextRule::from).collect(),
            default,
            limit,
        )
    }
    /// Like [`Policy::new`] for rules that may also constrain the flow's uid or network.
    pub fn with_context_rules(
        rules: Vec<ContextRule>,
        default: Action,
    ) -> Result<Self, PolicyError> {
        Self::with_context_limit(rules, default, MAX_RULES)
    }
    pub fn with_context_limit(
        rules: Vec<ContextRule>,
        default: Action,
        limit: usize,
    ) -> Result<Self, PolicyError> {
        let limit = limit.min(MAX_RULES);
        if rules.len() > limit {
            return Err(PolicyError::TooManyRules { limit });
        }
        for (rule_index, entry) in rules.iter().enumerate() {
            let rule = &entry.rule;
            if rule.source_port.as_ref().is_some_and(|r| r.is_empty())
                || rule.destination_port.as_ref().is_some_and(|r| r.is_empty())
            {
                return Err(PolicyError::InvalidPortRange { rule_index });
            }
            if matches!(&entry.uid, Some(UidMatch::Range(r)) if r.is_empty()) {
                return Err(PolicyError::InvalidUidRange { rule_index });
            }
        }
        let mut rules: Vec<_> = rules.into_iter().enumerate().collect();
        rules.sort_unstable_by_key(|(index, entry)| (entry.rule.priority, *index));
        Ok(Self { rules, default })
    }
    /// Decision for a flow with unknown uid and network; context-constrained rules only match
    /// if they ask for `UidMatch::Unknown` / `Network::Unknown`.
    pub fn decide(&self, packet: &Packet) -> Decision {
        self.decide_in(packet, &Context::default())
    }
    /// Decision for a flow with the caller-supplied `context`; same ordering as [`Policy::decide`].
    pub fn decide_in(&self, packet: &Packet, context: &Context) -> Decision {
        let matched = self
            .rules
            .iter()
            .find(|(_, entry)| entry.matches(packet, context));
        match matched {
            Some((i, entry)) => Decision {
                action: entry.rule.action,
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
    fn ctx(uid: Option<u32>, network: Network) -> Context {
        Context { uid, network }
    }
    fn with(rule: Rule, uid: Option<UidMatch>, network: Option<Network>) -> ContextRule {
        ContextRule { rule, uid, network }
    }
    #[test]
    fn uid_rules_match_known_ranges_and_unknown_explicitly() {
        let p = packet();
        let policy = Policy::with_context_rules(
            vec![
                with(
                    rule(0, Action::Allow),
                    Some(UidMatch::Range(10_100..=10_199)),
                    None,
                ),
                with(rule(1, Action::Deny), Some(UidMatch::Unknown), None),
            ],
            Action::Allow,
        )
        .unwrap();
        let known = policy.decide_in(&p, &ctx(Some(10_150), Network::Wifi));
        assert_eq!((known.action, known.rule_index), (Action::Allow, Some(0)));
        // Outside the range falls through to the default; a range never matches unknown.
        let other = policy.decide_in(&p, &ctx(Some(10_200), Network::Wifi));
        assert_eq!((other.action, other.rule_index), (Action::Allow, None));
        let unknown = policy.decide_in(&p, &ctx(None, Network::Wifi));
        assert_eq!(
            (unknown.action, unknown.rule_index),
            (Action::Deny, Some(1))
        );
        // Context-free decide() is the unknown-uid case.
        assert_eq!(policy.decide(&p), unknown);
    }
    #[test]
    fn network_constraint_and_priority_order_with_context() {
        let p = packet();
        let policy = Policy::with_context_rules(
            vec![
                with(rule(5, Action::Allow), None, None),
                with(rule(5, Action::Deny), None, Some(Network::Cellular)),
                with(
                    rule(0, Action::Deny),
                    Some(UidMatch::Range(7..=7)),
                    Some(Network::Wifi),
                ),
            ],
            Action::Deny,
        )
        .unwrap();
        // Lowest priority number first, then input order among equals (the unconstrained allow).
        let wifi_uid7 = policy.decide_in(&p, &ctx(Some(7), Network::Wifi));
        assert_eq!(wifi_uid7.rule_index, Some(2));
        let cellular = policy.decide_in(&p, &ctx(Some(8), Network::Cellular));
        assert_eq!(
            (cellular.action, cellular.rule_index),
            (Action::Allow, Some(0))
        );
        // Every present constraint must match: right uid, wrong network.
        let cellular_uid7 = policy.decide_in(&p, &ctx(Some(7), Network::Cellular));
        assert_eq!(cellular_uid7.rule_index, Some(0));
    }
    #[test]
    fn plain_rules_ignore_context_and_invalid_uid_ranges_are_rejected() {
        let p = packet();
        let plain = Policy::new(vec![rule(0, Action::Deny)], Action::Allow).unwrap();
        for context in [ctx(None, Network::Unknown), ctx(Some(1), Network::Cellular)] {
            assert_eq!(plain.decide_in(&p, &context).action, Action::Deny);
        }
        let inverted = with(
            rule(0, Action::Allow),
            Some(UidMatch::Range(std::ops::RangeInclusive::new(5, 4))),
            None,
        );
        assert_eq!(
            Policy::with_context_rules(vec![rule(0, Action::Allow).into(), inverted], Action::Deny)
                .unwrap_err(),
            PolicyError::InvalidUidRange { rule_index: 1 }
        );
        assert_eq!(
            Policy::with_context_limit(vec![rule(0, Action::Allow).into(); 2], Action::Deny, 1)
                .unwrap_err(),
            PolicyError::TooManyRules { limit: 1 }
        );
    }
}
