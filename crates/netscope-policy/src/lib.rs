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
pub struct Policy {
    rules: Vec<Rule>,
    default: Action,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Decision {
    pub action: Action,
    pub rule_index: Option<usize>,
}
impl Policy {
    /// Rules are immutable after construction; index refers to original input order.
    pub fn new(rules: Vec<Rule>, default: Action) -> Self {
        Self { rules, default }
    }
    pub fn decide(&self, packet: &Packet) -> Decision {
        let matched = self
            .rules
            .iter()
            .enumerate()
            .filter(|(_, r)| r.matches(packet))
            .min_by_key(|(i, r)| (r.priority, *i));
        match matched {
            Some((i, r)) => Decision {
                action: r.action,
                rule_index: Some(i),
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
            Policy::new(vec![], Action::Deny).decide(&p).action,
            Action::Deny
        );
        let mut allow = rule(5, Action::Allow);
        allow.source = Some(cidr("10.0.0.0", 24));
        let policy = Policy::new(
            vec![rule(10, Action::Deny), allow.clone(), rule(5, Action::Deny)],
            Action::Deny,
        );
        assert_eq!(
            policy.decide(&p),
            Decision {
                action: Action::Allow,
                rule_index: Some(1)
            }
        );
        assert_eq!(
            Policy::new(vec![rule(5, Action::Deny), allow], Action::Allow)
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
}
