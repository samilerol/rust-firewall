//! Strict, bounded text format for packet policies. No dependencies, no partial results:
//! any problem rejects the whole configuration with a line number.
//!
//! ```text
//! # comment
//! default deny
//! allow priority=10 proto=tcp dst=10.0.0.0/8 dport=443 uid=10001-10099 network=wifi
//! deny  dst=203.0.113.0/24
//! ```
//!
//! Exactly one `default allow|deny` line is required. A rule line is `allow|deny` followed by
//! unique `key=value` tokens: `priority` (u32, default 0), `proto` (`tcp`|`udp`), `src`/`dst`
//! (CIDR), `sport`/`dport` (`N` or `A-B`), `uid` (`N`, `A-B` or `unknown`) and `network`
//! (`wifi`|`cellular`|`other`|`unknown`). Rules keep their file order as the tie-break among
//! equal priorities, exactly like [`Policy::new`]. The text must be UTF-8 and every limit below
//! is enforced before anything is allocated for the data it bounds.
use crate::{Action, Cidr, ContextRule, Network, Policy, PolicyError, Rule, UidMatch, MAX_RULES};
use netscope_packet::Protocol;
use std::{io::Read, net::IpAddr, ops::RangeInclusive};

/// Largest accepted configuration, in bytes.
pub const MAX_CONFIG_BYTES: usize = 512 * 1024;
/// Largest accepted line, in bytes.
pub const MAX_LINE_BYTES: usize = 512;
/// Most `key=value` tokens on one rule line (there are only eight distinct keys).
const MAX_TOKENS: usize = 9;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ConfigErrorKind {
    TooLarge,
    NotUtf8,
    Io,
    LineTooLong,
    MissingDefault,
    DuplicateDefault,
    UnknownDirective,
    UnknownKey,
    DuplicateKey,
    TooManyTokens,
    BadValue,
    TooManyRules,
    Policy(PolicyError),
}
/// Why a configuration was rejected. `line` is 1-based, 0 when not tied to a line.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConfigError {
    pub line: usize,
    pub kind: ConfigErrorKind,
}
fn error<T>(line: usize, kind: ConfigErrorKind) -> Result<T, ConfigError> {
    Err(ConfigError { line, kind })
}

/// Parse a policy from a reader, reading at most [`MAX_CONFIG_BYTES`] + 1 bytes.
pub fn parse_policy_from(reader: impl Read) -> Result<Policy, ConfigError> {
    let mut bytes = Vec::new();
    reader
        .take(MAX_CONFIG_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .or_else(|_| error(0, ConfigErrorKind::Io))?;
    parse_policy(&bytes)
}

/// Parse a policy from bytes. Never panics on any input.
pub fn parse_policy(bytes: &[u8]) -> Result<Policy, ConfigError> {
    if bytes.len() > MAX_CONFIG_BYTES {
        return error(0, ConfigErrorKind::TooLarge);
    }
    let text = std::str::from_utf8(bytes).or_else(|_| error(0, ConfigErrorKind::NotUtf8))?;
    let mut default = None;
    let mut rules: Vec<ContextRule> = Vec::new();
    for (index, line) in text.split('\n').enumerate() {
        let number = index + 1;
        if line.len() > MAX_LINE_BYTES {
            return error(number, ConfigErrorKind::LineTooLong);
        }
        let line = line.strip_suffix('\r').unwrap_or(line);
        let content = line.split('#').next().unwrap_or("").trim();
        if content.is_empty() {
            continue;
        }
        let mut tokens = content.split_whitespace();
        let directive = tokens.next().unwrap_or("");
        match directive {
            "default" => {
                let action = match (tokens.next(), tokens.next()) {
                    (Some(word), None) => action(word, number)?,
                    _ => return error(number, ConfigErrorKind::BadValue),
                };
                if default.replace(action).is_some() {
                    return error(number, ConfigErrorKind::DuplicateDefault);
                }
            }
            "allow" | "deny" => {
                if rules.len() == MAX_RULES {
                    return error(number, ConfigErrorKind::TooManyRules);
                }
                rules.push(rule(action(directive, number)?, tokens, number)?);
            }
            _ => return error(number, ConfigErrorKind::UnknownDirective),
        }
    }
    let Some(default) = default else {
        return error(0, ConfigErrorKind::MissingDefault);
    };
    Policy::with_context_rules(rules, default).map_err(|e| ConfigError {
        line: 0,
        kind: ConfigErrorKind::Policy(e),
    })
}

fn action(word: &str, line: usize) -> Result<Action, ConfigError> {
    match word {
        "allow" => Ok(Action::Allow),
        "deny" => Ok(Action::Deny),
        _ => error(line, ConfigErrorKind::BadValue),
    }
}
fn rule<'a>(
    action: Action,
    tokens: impl Iterator<Item = &'a str>,
    line: usize,
) -> Result<ContextRule, ConfigError> {
    let mut out = ContextRule {
        rule: Rule {
            priority: 0,
            action,
            source: None,
            destination: None,
            protocol: None,
            source_port: None,
            destination_port: None,
        },
        uid: None,
        network: None,
    };
    let mut seen: Vec<&str> = Vec::new();
    for token in tokens {
        if seen.len() == MAX_TOKENS {
            return error(line, ConfigErrorKind::TooManyTokens);
        }
        let Some((key, value)) = token.split_once('=') else {
            return error(line, ConfigErrorKind::UnknownKey);
        };
        if seen.contains(&key) {
            return error(line, ConfigErrorKind::DuplicateKey);
        }
        let bad = || ConfigError {
            line,
            kind: ConfigErrorKind::BadValue,
        };
        match key {
            "priority" => out.rule.priority = value.parse().map_err(|_| bad())?,
            "proto" => {
                out.rule.protocol = Some(match value {
                    "tcp" => Protocol::Tcp,
                    "udp" => Protocol::Udp,
                    _ => return Err(bad()),
                })
            }
            "src" => out.rule.source = Some(cidr(value).ok_or_else(bad)?),
            "dst" => out.rule.destination = Some(cidr(value).ok_or_else(bad)?),
            "sport" => out.rule.source_port = Some(range::<u16>(value).ok_or_else(bad)?),
            "dport" => out.rule.destination_port = Some(range::<u16>(value).ok_or_else(bad)?),
            "uid" => {
                out.uid = Some(if value == "unknown" {
                    UidMatch::Unknown
                } else {
                    UidMatch::Range(range::<u32>(value).ok_or_else(bad)?)
                })
            }
            "network" => {
                out.network = Some(match value {
                    "wifi" => Network::Wifi,
                    "cellular" => Network::Cellular,
                    "other" => Network::Other,
                    "unknown" => Network::Unknown,
                    _ => return Err(bad()),
                })
            }
            _ => return error(line, ConfigErrorKind::UnknownKey),
        }
        seen.push(key);
    }
    Ok(out)
}
fn cidr(value: &str) -> Option<Cidr> {
    let (address, prefix) = value.split_once('/')?;
    Cidr::new(address.parse::<IpAddr>().ok()?, prefix.parse().ok()?).ok()
}
/// `N` or `A-B` (inclusive). An inverted range is kept so the policy rejects it with its index.
fn range<T: std::str::FromStr + Copy>(value: &str) -> Option<RangeInclusive<T>> {
    match value.split_once('-') {
        Some((a, b)) => Some(RangeInclusive::new(a.parse().ok()?, b.parse().ok()?)),
        None => {
            let n = value.parse().ok()?;
            Some(RangeInclusive::new(n, n))
        }
    }
}
