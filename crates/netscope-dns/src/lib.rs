//! Bounded classic DNS parsing and question-based domain policy. No resolver or DNSSEC validation.
use netscope_policy::Action;
pub const MAX_MESSAGE: usize = 4096;
pub const MAX_RECORDS: usize = 128;
pub const MAX_RULES: usize = 4096;
const MAX_POINTERS: usize = 16;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ParseError {
    Truncated,
    TooLarge,
    InvalidName,
    NameTooLong,
    Compression,
    Unsupported,
    Counts,
    Trailing,
    InvalidRecord,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DomainName(String);
impl DomainName {
    /// ASCII DNS label subset (letters/digits/hyphen/underscore), optional single trailing dot.
    /// Unicode must be converted to an ASCII IDNA A-label by a separate trusted configuration layer.
    pub fn new(text: &str) -> Result<Self, ParseError> {
        if text == "." {
            return Ok(Self(".".into()));
        }
        let text = text.strip_suffix('.').unwrap_or(text);
        if text.is_empty() || text.len() > 253 {
            return Err(ParseError::InvalidName);
        }
        for label in text.split('.') {
            if label.is_empty() || label.len() > 63 || !label.bytes().all(valid_label_byte) {
                return Err(ParseError::InvalidName);
            }
        }
        Ok(Self(text.to_ascii_lowercase()))
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}
fn valid_label_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'-' || b == b'_'
}
fn take<'a>(bytes: &'a [u8], at: &mut usize, size: usize) -> Result<&'a [u8], ParseError> {
    let end = at.checked_add(size).ok_or(ParseError::Truncated)?;
    let result = bytes.get(*at..end).ok_or(ParseError::Truncated)?;
    *at = end;
    Ok(result)
}
fn word(bytes: &[u8], at: &mut usize) -> Result<u16, ParseError> {
    let b = take(bytes, at, 2)?;
    Ok(u16::from_be_bytes([b[0], b[1]]))
}
/// Decode one DNS name and the offset immediately after its original encoding.
/// Only backward, non-header pointers are accepted; jumps/expanded wire length are bounded.
pub fn decode_name(bytes: &[u8], start: usize) -> Result<(DomainName, usize), ParseError> {
    name(bytes, start, true)
}
fn name(bytes: &[u8], start: usize, compression: bool) -> Result<(DomainName, usize), ParseError> {
    if bytes.len() > MAX_MESSAGE {
        return Err(ParseError::TooLarge);
    }
    if start < 12 {
        return Err(ParseError::Compression);
    }
    let mut at = start;
    let mut end = None;
    let mut pointers = 0;
    let mut expanded = 1usize;
    let mut result = String::new();
    loop {
        let marker = *bytes.get(at).ok_or(ParseError::Truncated)?;
        if marker & 0xc0 == 0xc0 {
            if !compression {
                return Err(ParseError::Compression);
            }
            let next = *bytes.get(at + 1).ok_or(ParseError::Truncated)?;
            let target = (usize::from(marker & 63) << 8) | usize::from(next);
            pointers += 1;
            if pointers > MAX_POINTERS || target < 12 || target >= at {
                return Err(ParseError::Compression);
            }
            end.get_or_insert(at + 2);
            at = target;
            continue;
        }
        if marker & 0xc0 != 0 {
            return Err(ParseError::InvalidName);
        }
        at += 1;
        if marker == 0 {
            return Ok((
                DomainName(if result.is_empty() {
                    ".".into()
                } else {
                    result
                }),
                end.unwrap_or(at),
            ));
        }
        let label = take(bytes, &mut at, usize::from(marker))?;
        expanded += label.len() + 1;
        if expanded > 255 {
            return Err(ParseError::NameTooLong);
        }
        if !label.iter().copied().all(valid_label_byte) {
            return Err(ParseError::InvalidName);
        }
        if !result.is_empty() {
            result.push('.');
        }
        for b in label {
            result.push(b.to_ascii_lowercase() as char);
        }
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Question {
    pub name: DomainName,
    pub qtype: u16,
    pub qclass: u16,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Message {
    pub id: u16,
    pub question: Question,
    pub truncated: bool,
}
pub fn parse_query(bytes: &[u8]) -> Result<Message, ParseError> {
    message(bytes, false)
}
pub fn parse_response(bytes: &[u8]) -> Result<Message, ParseError> {
    message(bytes, true)
}
fn message(bytes: &[u8], response: bool) -> Result<Message, ParseError> {
    if bytes.len() > MAX_MESSAGE {
        return Err(ParseError::TooLarge);
    }
    let mut at = 0;
    let id = word(bytes, &mut at)?;
    let flags = word(bytes, &mut at)?;
    let qd = word(bytes, &mut at)?;
    let an = word(bytes, &mut at)?;
    let ns = word(bytes, &mut at)?;
    let ar = word(bytes, &mut at)?;
    if (flags & 0x8000 != 0) != response
        || flags & 0x7840 != 0
        || (!response && flags & !0x0130 != 0)
    {
        return Err(ParseError::Unsupported);
    }
    if qd != 1
        || usize::from(an) + usize::from(ns) + usize::from(ar) > MAX_RECORDS
        || (!response && (an != 0 || ns != 0 || ar > 1))
    {
        return Err(ParseError::Counts);
    }
    // The sole first question has no preceding name to compress against.
    let (qname, next) = name(bytes, at, false)?;
    at = next;
    let qtype = word(bytes, &mut at)?;
    let qclass = word(bytes, &mut at)?;
    if qtype == 0 || qclass != 1 {
        return Err(ParseError::Unsupported);
    }
    let mut opt_seen = false;
    for (section, count) in [an, ns, ar].into_iter().enumerate() {
        for _ in 0..count {
            let owner_start = at;
            let (owner, next) = decode_name(bytes, at)?;
            at = next;
            let kind = word(bytes, &mut at)?;
            let _class = word(bytes, &mut at)?;
            let ttl = take(bytes, &mut at, 4)?;
            let size = usize::from(word(bytes, &mut at)?);
            let data_start = at;
            let data = take(bytes, &mut at, size)?;
            if kind == 41 {
                if section != 2
                    || opt_seen
                    || owner.as_str() != "."
                    || bytes[owner_start] != 0
                    || ttl[1] != 0
                    || (ttl[2] & 0x7f) != 0
                    || ttl[3] != 0
                    || (!response && ttl[0] != 0)
                {
                    return Err(ParseError::InvalidRecord);
                }
                opt_seen = true;
                let mut option = 0;
                let mut options = 0;
                while option < data.len() {
                    let _code = word(data, &mut option)?;
                    let len = usize::from(word(data, &mut option)?);
                    take(data, &mut option, len)?;
                    options += 1;
                    if options > 32 {
                        return Err(ParseError::Counts);
                    }
                }
            } else {
                if !response {
                    return Err(ParseError::Unsupported);
                }
                validate_rdata(bytes, data_start, at, kind)?;
            }
        }
    }
    if at != bytes.len() {
        return Err(ParseError::Trailing);
    }
    Ok(Message {
        id,
        question: Question {
            name: qname,
            qtype,
            qclass,
        },
        truncated: flags & 0x0200 != 0,
    })
}
fn validate_rdata(bytes: &[u8], start: usize, end: usize, kind: u16) -> Result<(), ParseError> {
    let size = end - start;
    match kind {
        1 if size != 4 => return Err(ParseError::InvalidRecord),
        28 if size != 16 => return Err(ParseError::InvalidRecord),
        2 | 5 | 12 | 39 => {
            if decode_name(bytes, start)?.1 != end {
                return Err(ParseError::InvalidRecord);
            }
        }
        15 | 33 => {
            let prefix = if kind == 15 { 2 } else { 6 };
            if size < prefix || decode_name(bytes, start + prefix)?.1 != end {
                return Err(ParseError::InvalidRecord);
            }
        }
        6 => {
            let next = decode_name(bytes, start)?.1;
            let next = decode_name(bytes, next)?.1;
            if next.checked_add(20) != Some(end) {
                return Err(ParseError::InvalidRecord);
            }
        }
        _ => {} // Unknown RDATA is length-bounded but not semantically interpreted.
    }
    Ok(())
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Match {
    Exact,
    DomainAndSubdomains,
}
#[derive(Clone, Debug)]
pub struct Rule {
    pub name: DomainName,
    pub kind: Match,
    pub priority: u32,
    pub action: Action,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PolicyError {
    TooManyRules,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Decision {
    pub action: Action,
    pub rule_index: Option<usize>,
}
#[derive(Debug)]
pub struct DomainPolicy {
    rules: Vec<(usize, Rule)>,
    default: Action,
}
impl DomainPolicy {
    pub fn new(rules: Vec<Rule>, default: Action) -> Result<Self, PolicyError> {
        if rules.len() > MAX_RULES {
            return Err(PolicyError::TooManyRules);
        }
        let mut rules: Vec<_> = rules.into_iter().enumerate().collect();
        rules.sort_unstable_by_key(|(i, r)| (r.priority, *i));
        Ok(Self { rules, default })
    }
    pub fn decide(&self, name: &DomainName) -> Decision {
        let matched = self.rules.iter().find(|(_, rule)| {
            name == &rule.name
                || (rule.kind == Match::DomainAndSubdomains
                    && name
                        .0
                        .strip_suffix(&rule.name.0)
                        .is_some_and(|prefix| prefix.ends_with('.')))
        });
        matched.map_or(
            Decision {
                action: self.default,
                rule_index: None,
            },
            |(i, r)| Decision {
                action: r.action,
                rule_index: Some(*i),
            },
        )
    }
}
