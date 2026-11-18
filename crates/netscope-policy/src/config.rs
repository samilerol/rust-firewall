//! Load versioned packet rules from a bounded UTF-8 stream.
use crate::{Action, Policy, PolicyError, Rule, MAX_RULES};
use netscope_packet::Protocol;
use std::{
    io::{self, Read},
    ops::RangeInclusive,
    str::FromStr,
};

pub const MAX_BYTES: usize = 256 * 1024;

#[derive(Debug)]
pub enum LoadError {
    Io(io::Error),
    TooLarge,
    InvalidUtf8,
    MissingHeader,
    MissingDefault,
    InvalidLine { line: usize },
    Policy(PolicyError),
}

/// Read at most MAX_BYTES + 1 bytes and build an immutable policy.
/// The first two nonblank, noncomment lines must be the version and default.
pub fn load(reader: impl Read) -> Result<Policy, LoadError> {
    let mut bytes = Vec::new();
    reader
        .take((MAX_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(LoadError::Io)?;
    if bytes.len() > MAX_BYTES {
        return Err(LoadError::TooLarge);
    }
    let text = std::str::from_utf8(&bytes).map_err(|_| LoadError::InvalidUtf8)?;
    let mut lines = text.lines().enumerate().filter_map(|(index, line)| {
        let line = line.trim_ascii();
        (!line.is_empty() && !line.starts_with('#')).then_some((index + 1, line))
    });
    let (line, header) = lines.next().ok_or(LoadError::MissingHeader)?;
    if header != "netscope-policy 1" {
        return Err(LoadError::InvalidLine { line });
    }
    let (line, default) = lines.next().ok_or(LoadError::MissingDefault)?;
    let default = default
        .strip_prefix("default ")
        .and_then(action)
        .ok_or(LoadError::InvalidLine { line })?;
    let mut rules = Vec::new();
    for (line, text) in lines {
        if rules.len() == MAX_RULES {
            return Err(LoadError::Policy(PolicyError::TooManyRules {
                limit: MAX_RULES,
            }));
        }
        rules.push(rule(text).ok_or(LoadError::InvalidLine { line })?);
    }
    Policy::new(rules, default).map_err(LoadError::Policy)
}

fn action(value: &str) -> Option<Action> {
    match value {
        "allow" => Some(Action::Allow),
        "deny" => Some(Action::Deny),
        _ => None,
    }
}

fn decimal<T: FromStr>(value: &str) -> Option<T> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    value.parse().ok()
}

fn optional<T>(value: &str, parse: impl FnOnce(&str) -> Option<T>) -> Option<Option<T>> {
    if value == "*" {
        Some(None)
    } else {
        parse(value).map(Some)
    }
}

fn ports(value: &str) -> Option<RangeInclusive<u16>> {
    let (first, last) = value.split_once('-').unwrap_or((value, value));
    let (first, last) = (decimal(first)?, decimal(last)?);
    (first <= last).then_some(first..=last)
}

fn rule(text: &str) -> Option<Rule> {
    let mut fields = text.split_ascii_whitespace();
    if fields.next()? != "rule" {
        return None;
    }
    let rule = Rule {
        priority: decimal(fields.next()?)?,
        action: action(fields.next()?)?,
        protocol: optional(fields.next()?, |value| match value {
            "tcp" => Some(Protocol::Tcp),
            "udp" => Some(Protocol::Udp),
            _ => None,
        })?,
        source: optional(fields.next()?, |value| value.parse().ok())?,
        destination: optional(fields.next()?, |value| value.parse().ok())?,
        source_port: optional(fields.next()?, ports)?,
        destination_port: optional(fields.next()?, ports)?,
    };
    fields.next().is_none().then_some(rule)
}

#[cfg(test)]
mod tests {
    use super::*;
    use netscope_packet::Packet;

    #[test]
    fn loaded_policy_preserves_input_order_and_uses_explicit_default() {
        let text = b"# example\nnetscope-policy 1\ndefault deny\nrule 10 allow tcp 192.0.2.0/24 * * 443-444\nrule 10 deny tcp * * * 443\n";
        let policy = load(&text[..]).unwrap();
        let mut packet = Packet {
            source: "192.0.2.2".parse().unwrap(),
            destination: "198.51.100.1".parse().unwrap(),
            source_port: 1024,
            destination_port: 443,
            protocol: Protocol::Tcp,
            length: 40,
        };
        assert_eq!(policy.decide(&packet).rule_index, Some(0));
        assert_eq!(policy.decide(&packet).action, Action::Allow);
        packet.protocol = Protocol::Udp;
        assert_eq!(policy.decide(&packet).rule_index, None);
        assert_eq!(policy.decide(&packet).action, Action::Deny);
    }

    #[test]
    fn rejects_invalid_late_rules_and_bounds_reader_and_rule_count() {
        let header = "netscope-policy 1\ndefault deny\n";
        for rule in [
            "default allow",
            "rule 1 allow tcp * * * 2-1",
            "rule 1 allow icmp * * * *",
            "rule +1 allow tcp * * * *",
            "rule 1 allow tcp * * * * trailing",
        ] {
            let text = format!("{header}rule 1 allow tcp * * * 443\n{rule}");
            assert!(matches!(
                load(text.as_bytes()),
                Err(LoadError::InvalidLine { line: 4 })
            ));
        }
        assert!(matches!(load(io::repeat(b' ')), Err(LoadError::TooLarge)));
        assert!(matches!(load(&[0xff][..]), Err(LoadError::InvalidUtf8)));
        assert!(matches!(
            load(b"netscope-policy 1\n".as_slice()),
            Err(LoadError::MissingDefault)
        ));
        let text = format!(
            "{header}{}",
            "rule 0 deny * * * * *\n".repeat(MAX_RULES + 1)
        );
        assert!(matches!(
            load(text.as_bytes()),
            Err(LoadError::Policy(PolicyError::TooManyRules {
                limit: MAX_RULES
            }))
        ));
    }
}
