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
    reject_control_chars(text)?;
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

/// Reject control characters other than tab, LF and CR directly before LF,
/// plus C1 controls, U+2028 and U+2029, so hidden text cannot survive in
/// comments or blank lines.
fn reject_control_chars(text: &str) -> Result<(), LoadError> {
    let mut line = 1;
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\n' => line += 1,
            '\r' if chars.peek() == Some(&'\n') => {}
            '\t' => {}
            '\0'..='\x1f' | '\x7f'..='\u{9f}' | '\u{2028}' | '\u{2029}' => {
                return Err(LoadError::InvalidLine { line })
            }
            _ => {}
        }
    }
    Ok(())
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

    fn invalid_line(text: &str) -> Option<usize> {
        match load(text.as_bytes()) {
            Err(LoadError::InvalidLine { line }) => Some(line),
            _ => None,
        }
    }

    #[test]
    fn bare_cr_hidden_in_comment_is_rejected() {
        let text = "netscope-policy 1\ndefault allow\n# block exfil\rrule 1 deny * * * * *\n";
        assert_eq!(invalid_line(text), Some(3));
    }

    #[test]
    fn bare_cr_rejected_on_every_line_kind_and_at_end() {
        for text in [
            "netscope-policy 1\r\r\ndefault allow\n",
            "netscope-policy 1\ndefault\rallow\n",
            "netscope-policy 1\ndefault allow\nrule 1 deny * * * * *\r\r\n",
            "netscope-policy 1\ndefault allow\n\r\r\nrule 1 deny * * * * *\n",
        ] {
            assert!(invalid_line(text).is_some(), "{text:?}");
        }
        assert_eq!(
            invalid_line("netscope-policy 1\rx\ndefault allow\n"),
            Some(1)
        );
        assert_eq!(
            invalid_line("netscope-policy 1\ndefault allow\r\r\n"),
            Some(2)
        );
        assert_eq!(
            invalid_line("netscope-policy 1\ndefault allow\n\r\r\n"),
            Some(3)
        );
        assert_eq!(
            invalid_line("netscope-policy 1\ndefault allow\n\r"),
            Some(3)
        );
        assert_eq!(
            invalid_line("netscope-policy 1\ndefault allow\n# x\r"),
            Some(3)
        );
    }

    #[test]
    fn control_characters_in_comments_are_rejected() {
        for control in ['\0', '\x1b', '\x7f'] {
            let text = format!("netscope-policy 1\ndefault allow\n# a{control}b\n");
            assert_eq!(invalid_line(&text), Some(3), "{control:?}");
        }
    }

    #[test]
    fn tabs_and_crlf_still_load() {
        let text = "netscope-policy 1\r\n# note\r\ndefault deny\r\n\r\nrule\t1\tallow\ttcp\t*\t*\t*\t443\r\n";
        let policy = load(text.as_bytes()).unwrap();
        let packet = Packet {
            source: "192.0.2.2".parse().unwrap(),
            destination: "198.51.100.1".parse().unwrap(),
            source_port: 1024,
            destination_port: 443,
            protocol: Protocol::Tcp,
            length: 40,
        };
        assert_eq!(policy.decide(&packet).action, Action::Allow);
    }

    #[test]
    fn control_character_line_number_counts_earlier_lines() {
        let text =
            "# one\nnetscope-policy 1\n\ndefault allow\n# four\nrule 1 deny * * * * *\n#\x1b\n";
        assert_eq!(invalid_line(text), Some(7));
    }

    #[test]
    fn line_separators_and_c1_controls_are_rejected_but_other_unicode_loads() {
        for c in ['\u{85}', '\u{2028}', '\u{2029}', '\u{9b}'] {
            let text = format!("netscope-policy 1\ndefault allow\n# a{c}b\n");
            assert_eq!(invalid_line(&text), Some(3), "{c:?}");
            let text = format!("netscope-policy 1\ndefault allow\n# ok\n# a{c}b\n");
            assert_eq!(invalid_line(&text), Some(4), "{c:?}");
        }
        let text = "netscope-policy 1\ndefault allow\n# \u{15f}\u{11f}\u{131}\u{fc}\u{f6}\u{e7} \u{a0} \u{2027}\n";
        assert!(load(text.as_bytes()).is_ok());
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
