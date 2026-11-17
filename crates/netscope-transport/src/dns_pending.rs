//! One fixed-age expiry record per pending transaction; no stale retry records.
use crate::{DnsError, DnsLimits};
use netscope_conntrack::FlowId;
use netscope_dns::Message;
use std::collections::{BTreeSet, HashMap};

struct Pending {
    query: Message,
    sent_at: u64,
}
pub(crate) struct PendingQueries {
    flows: HashMap<FlowId, HashMap<u16, Pending>>,
    order: BTreeSet<(u64, FlowId, u16)>,
    limits: DnsLimits,
}
impl PendingQueries {
    pub(crate) fn new(limits: DnsLimits) -> Self {
        Self {
            flows: HashMap::new(),
            order: BTreeSet::new(),
            limits,
        }
    }
    pub(crate) fn len(&self) -> usize {
        self.order.len()
    }
    pub(crate) fn check(&self, flow: &FlowId, query: &Message) -> Result<(), DnsError> {
        let queries = self.flows.get(flow);
        if let Some(existing) = queries.and_then(|q| q.get(&query.id)) {
            return if existing.query == *query {
                Ok(())
            } else {
                Err(DnsError::Busy)
            };
        }
        if self.len() >= self.limits.max_pending_total
            || queries.is_some_and(|q| q.len() >= self.limits.max_pending_per_flow)
        {
            return Err(DnsError::Capacity);
        }
        Ok(())
    }
    /// Only after successful send and check(), without intervening table mutation.
    /// Retries keep the original age, so retries cannot retain a slot forever.
    pub(crate) fn record(&mut self, flow: FlowId, query: Message, now: u64) {
        debug_assert!(self.check(&flow, &query).is_ok());
        let queries = self.flows.entry(flow).or_default();
        if queries.contains_key(&query.id) {
            return;
        }
        self.order.insert((now, flow, query.id));
        queries.insert(
            query.id,
            Pending {
                query,
                sent_at: now,
            },
        );
    }
    pub(crate) fn matches(&self, flow: &FlowId, response: &Message) -> Result<(), DnsError> {
        let queries = self.flows.get(flow).ok_or(DnsError::Unsolicited)?;
        let pending = queries.get(&response.id).ok_or(DnsError::Unsolicited)?;
        if pending.query.question != response.question {
            return Err(DnsError::Mismatched);
        }
        Ok(())
    }
    pub(crate) fn remove_query(&mut self, flow: &FlowId, id: u16) {
        if let Some(queries) = self.flows.get_mut(flow) {
            if let Some(pending) = queries.remove(&id) {
                self.order.remove(&(pending.sent_at, *flow, id));
            }
            if queries.is_empty() {
                self.flows.remove(flow);
            }
        }
    }
    pub(crate) fn remove_flow(&mut self, flow: &FlowId) {
        if let Some(queries) = self.flows.remove(flow) {
            for (id, pending) in queries {
                self.order.remove(&(pending.sent_at, *flow, id));
            }
        }
    }
    /// Caller first validates the monotonic clock through Engine::expire_with.
    pub(crate) fn expire(&mut self, now: u64) {
        while let Some(&(sent_at, flow, id)) = self.order.first() {
            if now - sent_at < self.limits.query_timeout {
                break;
            }
            self.remove_query(&flow, id);
        }
    }
    pub(crate) fn clear(&mut self) {
        self.flows.clear();
        self.order.clear();
    }
}

/// Pure state-machine oracle shared by unit regression and sanitizer fuzzing.
#[cfg(any(test, feature = "fuzzing"))]
pub(crate) fn exercise(bytes: &[u8]) {
    use netscope_dns::{DomainName, Question};
    use netscope_packet::Protocol;
    let limits = DnsLimits {
        max_pending_per_flow: 4,
        max_pending_total: 16,
        query_timeout: 10,
    };
    let mut table = PendingQueries::new(limits);
    let mut reference: Vec<(FlowId, Message, u64)> = Vec::new();
    let mut now = 0u64;
    for op in bytes.chunks_exact(4).take(4096) {
        now += u64::from(op[3] & 3);
        table.expire(now);
        reference.retain(|(_, _, sent)| now - sent < limits.query_timeout);
        let flow = FlowId {
            source: "192.0.2.1".parse().unwrap(),
            destination: "127.0.0.1".parse().unwrap(),
            source_port: 1000 + u16::from(op[1] & 7),
            destination_port: 53,
            protocol: Protocol::Udp,
        };
        let query = Message {
            id: u16::from(op[2] & 7),
            question: Question {
                name: DomainName::new(if op[2] & 8 == 0 {
                    "one.example"
                } else {
                    "two.example"
                })
                .unwrap(),
                qtype: if op[2] & 16 == 0 { 1 } else { 28 },
                qclass: 1,
            },
            truncated: false,
        };
        match op[0] % 6 {
            0 | 1 => {
                let existing = reference
                    .iter()
                    .find(|(f, q, _)| *f == flow && q.id == query.id);
                let expected = if let Some((_, old, _)) = existing {
                    if *old == query {
                        Ok(())
                    } else {
                        Err(DnsError::Busy)
                    }
                } else if reference.len() >= limits.max_pending_total
                    || reference.iter().filter(|(f, _, _)| *f == flow).count()
                        >= limits.max_pending_per_flow
                {
                    Err(DnsError::Capacity)
                } else {
                    Ok(())
                };
                assert_eq!(table.check(&flow, &query), expected);
                if expected.is_ok() {
                    if existing.is_none() {
                        reference.push((flow, query.clone(), now));
                    }
                    table.record(flow, query, now);
                }
            }
            2 => {
                let expected = match reference
                    .iter()
                    .find(|(f, q, _)| *f == flow && q.id == query.id)
                {
                    None => Err(DnsError::Unsolicited),
                    Some((_, old, _)) if old.question != query.question => {
                        Err(DnsError::Mismatched)
                    }
                    Some(_) => Ok(()),
                };
                assert_eq!(table.matches(&flow, &query), expected);
                if expected.is_ok() {
                    table.remove_query(&flow, query.id);
                    reference.retain(|(f, q, _)| *f != flow || q.id != query.id);
                }
            }
            3 => {
                table.remove_flow(&flow);
                reference.retain(|(f, _, _)| *f != flow);
            }
            4 if op[3] == 255 => {
                table.clear();
                reference.clear();
            }
            _ => (),
        }
        assert_eq!(table.len(), reference.len());
        assert_eq!(
            table.flows.values().map(HashMap::len).sum::<usize>(),
            reference.len()
        );
        assert!(table
            .flows
            .values()
            .all(|q| !q.is_empty() && q.len() <= limits.max_pending_per_flow));
        for (f, q, sent) in &reference {
            assert!(table.order.contains(&(*sent, *f, q.id)));
            assert_eq!(table.matches(f, q), Ok(()));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use netscope_dns::{DomainName, Question};
    use netscope_packet::Protocol;
    #[test]
    fn mixed_operations_match_linear_reference() {
        let mut seed = 42u64;
        let bytes: Vec<_> = (0..16384)
            .map(|_| {
                seed ^= seed << 13;
                seed ^= seed >> 7;
                seed ^= seed << 17;
                seed as u8
            })
            .collect();
        exercise(&bytes);
    }
    #[test]
    fn retries_do_not_grow_index_or_extend_age_near_clock_limit() {
        let limits = DnsLimits {
            max_pending_per_flow: 1,
            max_pending_total: 1,
            query_timeout: 3,
        };
        let mut table = PendingQueries::new(limits);
        let flow = FlowId {
            source: "192.0.2.1".parse().unwrap(),
            destination: "127.0.0.1".parse().unwrap(),
            source_port: 1000,
            destination_port: 53,
            protocol: Protocol::Udp,
        };
        let query = Message {
            id: 65535,
            question: Question {
                name: DomainName::new("example.com").unwrap(),
                qtype: 1,
                qclass: 1,
            },
            truncated: false,
        };
        table.record(flow, query.clone(), u64::MAX - 3);
        for _ in 0..10000 {
            table.record(flow, query.clone(), u64::MAX - 1);
        }
        assert_eq!(table.len(), 1);
        table.expire(u64::MAX - 1);
        assert_eq!(table.len(), 1);
        table.expire(u64::MAX);
        assert_eq!(table.len(), 0);
        assert!(table.flows.is_empty());
    }
}
