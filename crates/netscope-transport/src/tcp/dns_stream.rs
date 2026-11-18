//! Domain filtering for DNS-over-TCP flows (two-byte length framing, RFC 1035 section 4.2.2).
//!
//! Pure stream logic with no sockets, so it is testable on its own. A flow is gated in both
//! directions: a client frame is released to the upstream only when it is complete, parses as a
//! query and its name is allowed; an upstream frame is released to the client only when it is
//! complete, parses as a response matching an outstanding question and its name is allowed. Any
//! violation is returned and the caller tears the flow down. Not DoT/DoH, not DNSSEC validation.
use netscope_dns::{parse_query, parse_response, DomainPolicy, Message, MAX_MESSAGE};
use netscope_policy::Action;

/// One frame: two length bytes plus the largest accepted message.
pub(super) const FRAME_MAX: usize = MAX_MESSAGE + 2;
/// Upstream staging bound: one partial frame while validated frames wait for the client.
pub(super) const STAGE_MAX: usize = 2 * FRAME_MAX;
/// Most outstanding questions per flow (matches the UDP relay).
const MAX_PENDING: usize = crate::MAX_DNS_PENDING;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Violation {
    /// Zero or oversized length prefix, or a frame larger than the client buffer can hold.
    BadFrame,
    Malformed,
    DomainDenied,
    /// A ninth distinct outstanding question.
    Busy,
    /// A response with nothing, or nothing matching, outstanding.
    Unsolicited,
}

pub(super) struct DnsStream {
    /// Bytes at the front of the client stream already approved for the upstream.
    approved: usize,
    pending: Vec<Message>,
    /// Reusable copy of the client bytes being inspected.
    scratch: Vec<u8>,
    /// Upstream bytes not yet delivered: validated whole frames first, then a partial frame.
    staged: Vec<u8>,
    validated: usize,
}

fn frame_len(rest: &[u8]) -> Result<Option<usize>, Violation> {
    if rest.len() < 2 {
        return Ok(None);
    }
    let len = usize::from(u16::from_be_bytes([rest[0], rest[1]]));
    if len == 0 || len > MAX_MESSAGE {
        return Err(Violation::BadFrame);
    }
    Ok((rest.len() >= 2 + len).then_some(len))
}

impl DnsStream {
    pub fn new() -> Self {
        Self {
            approved: 0,
            pending: Vec::new(),
            scratch: Vec::new(),
            staged: Vec::new(),
            validated: 0,
        }
    }
    /// Scratch space for the caller to copy the queued client bytes into (without consuming).
    pub fn scratch(&mut self, queued: usize) -> &mut [u8] {
        self.scratch.clear();
        self.scratch.resize(queued, 0);
        &mut self.scratch
    }
    /// Approve every complete frame in the scratch bytes beyond the already approved prefix.
    /// `capacity` is the client receive buffer size: a frame that can never fit is a violation.
    pub fn inspect_client(
        &mut self,
        capacity: usize,
        policy: &DomainPolicy,
    ) -> Result<(), Violation> {
        let mut at = self.approved;
        while let Some(rest) = self.scratch.get(at..) {
            let head = rest
                .get(..2)
                .map(|b| usize::from(u16::from_be_bytes([b[0], b[1]])));
            if matches!(head, Some(len) if len == 0 || len > MAX_MESSAGE || 2 + len > capacity) {
                return Err(Violation::BadFrame);
            }
            let Some(len) = frame_len(rest)? else { break };
            let query = parse_query(&rest[2..2 + len]).map_err(|_| Violation::Malformed)?;
            if policy.decide(&query.question.name).action == Action::Deny {
                return Err(Violation::DomainDenied);
            }
            if !self.pending.contains(&query) {
                if self.pending.len() >= MAX_PENDING {
                    return Err(Violation::Busy);
                }
                self.pending.push(query);
            }
            at += 2 + len;
        }
        self.approved = at;
        Ok(())
    }
    /// Client bytes that may be written to the upstream now.
    pub fn approved(&self) -> usize {
        self.approved
    }
    pub fn written(&mut self, count: usize) {
        self.approved -= count.min(self.approved);
    }
    /// How many more upstream bytes may be staged.
    pub fn stage_room(&self) -> usize {
        STAGE_MAX - self.staged.len()
    }
    /// Stage upstream bytes and validate every newly completed frame.
    pub fn absorb(&mut self, bytes: &[u8], policy: &DomainPolicy) -> Result<(), Violation> {
        debug_assert!(bytes.len() <= self.stage_room());
        self.staged.extend_from_slice(bytes);
        while let Some(len) = frame_len(&self.staged[self.validated..])? {
            let body = &self.staged[self.validated + 2..self.validated + 2 + len];
            let response = parse_response(body).map_err(|_| Violation::Malformed)?;
            let position = self
                .pending
                .iter()
                .position(|q| q.id == response.id && q.question == response.question)
                .ok_or(Violation::Unsolicited)?;
            if policy.decide(&response.question.name).action == Action::Deny {
                return Err(Violation::DomainDenied);
            }
            self.pending.remove(position);
            self.validated += 2 + len;
        }
        Ok(())
    }
    /// Validated frames ready for the client.
    pub fn deliverable(&self) -> &[u8] {
        &self.staged[..self.validated]
    }
    pub fn delivered(&mut self, count: usize) {
        let count = count.min(self.validated);
        self.staged.drain(..count);
        self.validated -= count;
    }
    /// Upstream bytes of an incomplete frame are staged.
    pub fn has_partial(&self) -> bool {
        self.staged.len() > self.validated
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use netscope_dns::{DomainName, Match, Rule};

    fn policy() -> DomainPolicy {
        DomainPolicy::new(
            vec![Rule {
                name: DomainName::new("blocked.example").unwrap(),
                kind: Match::Exact,
                priority: 0,
                action: Action::Deny,
            }],
            Action::Allow,
        )
        .unwrap()
    }
    fn dns(name: &str, id: u16, response: bool) -> Vec<u8> {
        let mut b = vec![0; 12];
        b[..2].copy_from_slice(&id.to_be_bytes());
        b[2] = if response { 0x81 } else { 1 };
        b[3] = if response { 0x80 } else { 0 };
        b[5] = 1;
        for label in name.split('.') {
            b.push(label.len() as u8);
            b.extend_from_slice(label.as_bytes());
        }
        b.extend_from_slice(&[0, 0, 1, 0, 1]);
        b
    }
    fn frame(message: &[u8]) -> Vec<u8> {
        let mut out = (message.len() as u16).to_be_bytes().to_vec();
        out.extend_from_slice(message);
        out
    }
    fn inspect(s: &mut DnsStream, bytes: &[u8]) -> Result<(), Violation> {
        s.scratch(bytes.len()).copy_from_slice(bytes);
        s.inspect_client(65536, &policy())
    }

    #[test]
    fn complete_frames_are_approved_and_partial_ones_wait() {
        let mut s = DnsStream::new();
        let one = frame(&dns("ok.example", 1, false));
        let two = frame(&dns("ok.example", 2, false));
        // Half of the first frame: nothing approved yet, not even the length-only prefix.
        inspect(&mut s, &one[..5]).unwrap();
        assert_eq!(s.approved(), 0);
        inspect(&mut s, &one[..1]).unwrap();
        assert_eq!(s.approved(), 0);
        // The rest of it plus a pipelined second frame and a partial third.
        let mut bytes = one.clone();
        bytes.extend_from_slice(&two);
        bytes.extend_from_slice(&two[..3]);
        inspect(&mut s, &bytes).unwrap();
        assert_eq!(s.approved(), one.len() + two.len());
        // Written bytes advance the approved prefix without re-parsing them.
        s.written(one.len());
        assert_eq!(s.approved(), two.len());
    }
    #[test]
    fn denied_malformed_oversized_and_busy_frames_are_violations() {
        let mut s = DnsStream::new();
        assert_eq!(
            inspect(&mut s, &frame(&dns("blocked.example", 1, false))),
            Err(Violation::DomainDenied)
        );
        assert_eq!(
            inspect(&mut DnsStream::new(), &frame(b"short")),
            Err(Violation::Malformed)
        );
        for head in [[0u8, 0], [0x10, 0x01]] {
            assert_eq!(
                inspect(&mut DnsStream::new(), &head),
                Err(Violation::BadFrame)
            );
        }
        // A frame that cannot fit the receive buffer can never be inspected.
        let big = frame(&dns("ok.example", 1, false));
        let mut small = DnsStream::new();
        small.scratch(big.len()).copy_from_slice(&big);
        assert_eq!(
            small.inspect_client(big.len() - 1, &policy()),
            Err(Violation::BadFrame)
        );
        let mut many = DnsStream::new();
        let mut bytes = Vec::new();
        for id in 0..=MAX_PENDING as u16 {
            bytes.extend_from_slice(&frame(&dns("ok.example", id, false)));
        }
        assert_eq!(inspect(&mut many, &bytes), Err(Violation::Busy));
    }
    #[test]
    fn responses_match_outstanding_questions_in_any_order_and_split_arbitrarily() {
        let mut s = DnsStream::new();
        let mut bytes = frame(&dns("ok.example", 1, false));
        bytes.extend_from_slice(&frame(&dns("ok.example", 2, false)));
        inspect(&mut s, &bytes).unwrap();
        let second = frame(&dns("ok.example", 2, true));
        let first = frame(&dns("ok.example", 1, true));
        let mut wire = second.clone();
        wire.extend_from_slice(&first);
        // Feed one byte at a time: nothing is deliverable before a frame is complete.
        let mut seen = 0;
        for byte in &wire {
            s.absorb(std::slice::from_ref(byte), &policy()).unwrap();
            assert!(
                s.deliverable().is_empty()
                    || s.deliverable().len() == second.len()
                    || s.deliverable().len() == wire.len()
            );
            seen = seen.max(s.deliverable().len());
        }
        assert_eq!(seen, wire.len());
        assert_eq!(s.deliverable(), &wire[..]);
        s.delivered(second.len());
        assert_eq!(s.deliverable(), &first[..]);
        assert!(!s.has_partial());
    }
    #[test]
    fn unsolicited_mismatched_malformed_and_truncated_responses_are_violations() {
        let outstanding = |s: &mut DnsStream| {
            inspect(s, &frame(&dns("ok.example", 1, false))).unwrap();
        };
        let mut s = DnsStream::new();
        assert_eq!(
            s.absorb(&frame(&dns("ok.example", 1, true)), &policy()),
            Err(Violation::Unsolicited)
        );
        for answer in [dns("ok.example", 9, true), dns("other.example", 1, true)] {
            let mut s = DnsStream::new();
            outstanding(&mut s);
            assert_eq!(
                s.absorb(&frame(&answer), &policy()),
                Err(Violation::Unsolicited)
            );
        }
        let mut s = DnsStream::new();
        outstanding(&mut s);
        assert_eq!(
            s.absorb(&frame(b"junk"), &policy()),
            Err(Violation::Malformed)
        );
        // Domain policy is re-checked on the answer.
        let mut s = DnsStream::new();
        inspect(&mut s, &frame(&dns("ok.example", 1, false))).unwrap();
        s.pending[0].question.name = DomainName::new("blocked.example").unwrap();
        assert_eq!(
            s.absorb(&frame(&dns("blocked.example", 1, true)), &policy()),
            Err(Violation::DomainDenied)
        );
        // A partial frame is reported so an upstream EOF can be treated as truncation.
        let mut s = DnsStream::new();
        outstanding(&mut s);
        let answer = frame(&dns("ok.example", 1, true));
        s.absorb(&answer[..answer.len() - 1], &policy()).unwrap();
        assert!(s.has_partial());
        assert!(s.deliverable().is_empty());
    }
}
