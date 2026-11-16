//! Bounded directional flow observations, not a TCP state machine or authorization cache.
use netscope_packet::{Packet, Protocol};
use std::{
    collections::{BTreeSet, HashMap},
    net::IpAddr,
};
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct FlowId {
    pub source: IpAddr,
    pub destination: IpAddr,
    pub source_port: u16,
    pub destination_port: u16,
    pub protocol: Protocol,
}
impl From<&Packet> for FlowId {
    fn from(p: &Packet) -> Self {
        Self {
            source: p.source,
            destination: p.destination,
            source_port: p.source_port,
            destination_port: p.destination_port,
            protocol: p.protocol,
        }
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Observation {
    pub created_at: u64,
    pub last_seen: u64,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TrackError {
    Capacity,
    ClockReversed,
}
pub struct Tracker {
    flows: HashMap<FlowId, Observation>,
    order: BTreeSet<(u64, FlowId)>,
    capacity: usize,
    timeout: u64,
    clock: u64,
}
impl Tracker {
    /// Time is caller-provided monotonic ticks. Expiration occurs at age >= timeout.
    /// Zero capacity or timeout deliberately retains no new flows.
    pub fn new(capacity: usize, timeout: u64) -> Self {
        Self {
            flows: HashMap::new(),
            order: BTreeSet::new(),
            capacity,
            timeout,
            clock: 0,
        }
    }
    pub fn expire(&mut self, now: u64) -> Result<usize, TrackError> {
        self.expire_with(now, |_| {})
    }
    /// Synchronous removal callback; no retained event queue or stale expiry records.
    pub fn expire_with(
        &mut self,
        now: u64,
        mut removed: impl FnMut(FlowId),
    ) -> Result<usize, TrackError> {
        if now < self.clock {
            return Err(TrackError::ClockReversed);
        }
        self.clock = now;
        let before = self.flows.len();
        if self
            .order
            .first()
            .is_some_and(|(seen, _)| now - *seen >= self.timeout)
            && self
                .order
                .last()
                .is_some_and(|(seen, _)| now - *seen >= self.timeout)
        {
            // Every entry is due: avoid F tree removals and hash lookups.
            // Clear the index before callbacks so a callback unwind cannot leave stale records.
            self.order.clear();
            for (id, _) in self.flows.drain() {
                removed(id);
            }
            return Ok(before);
        }
        while let Some((seen, id)) = self.order.first().copied() {
            if now - seen < self.timeout {
                break;
            }
            self.order.pop_first();
            self.flows.remove(&id);
            removed(id);
        }
        Ok(before - self.flows.len())
    }
    pub fn observe(&mut self, id: FlowId, now: u64) -> Result<Observation, TrackError> {
        self.expire(now)?;
        if let Some(flow) = self.flows.get_mut(&id) {
            if flow.last_seen != now {
                self.order.remove(&(flow.last_seen, id));
                flow.last_seen = now;
                self.order.insert((now, id));
            }
            return Ok(*flow);
        }
        if self.flows.len() >= self.capacity || self.timeout == 0 {
            return Err(TrackError::Capacity);
        }
        let flow = Observation {
            created_at: now,
            last_seen: now,
        };
        self.flows.insert(id, flow);
        self.order.insert((now, id));
        Ok(flow)
    }
    /// Remove an observation and its one expiry-index entry.
    pub fn remove(&mut self, id: &FlowId) -> Option<Observation> {
        let flow = self.flows.remove(id)?;
        self.order.remove(&(flow.last_seen, *id));
        Some(flow)
    }
    /// Clears observations while preserving monotonic clock validation.
    pub fn clear(&mut self) -> usize {
        let count = self.flows.len();
        self.flows.clear();
        self.order.clear();
        count
    }
    pub fn get(&self, id: &FlowId) -> Option<&Observation> {
        self.flows.get(id)
    }
    pub fn len(&self) -> usize {
        self.flows.len()
    }
    pub fn is_empty(&self) -> bool {
        self.flows.is_empty()
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn flow(port: u16) -> FlowId {
        FlowId {
            source: "::1".parse().unwrap(),
            destination: "::2".parse().unwrap(),
            source_port: port,
            destination_port: 443,
            protocol: Protocol::Tcp,
        }
    }
    #[test]
    fn refresh_expire_and_bound_capacity() {
        let mut t = Tracker::new(1, 10);
        assert_eq!(
            t.observe(flow(1), 1).unwrap(),
            Observation {
                created_at: 1,
                last_seen: 1
            }
        );
        assert_eq!(t.observe(flow(2), 2), Err(TrackError::Capacity));
        assert_eq!(
            t.observe(flow(1), 5).unwrap(),
            Observation {
                created_at: 1,
                last_seen: 5
            }
        );
        assert_eq!(t.expire(14), Ok(0));
        assert_eq!(t.expire(15), Ok(1));
        assert!(t.observe(flow(2), 15).is_ok());
        assert_eq!(t.len(), 1);
        assert_eq!(t.observe(flow(1), 14), Err(TrackError::ClockReversed));
        assert_eq!(t.get(&flow(2)).unwrap().last_seen, 15);
    }
    #[test]
    fn zero_limits_and_large_timestamps() {
        assert_eq!(
            Tracker::new(0, 10).observe(flow(1), 0),
            Err(TrackError::Capacity)
        );
        assert_eq!(
            Tracker::new(1, 0).observe(flow(1), 0),
            Err(TrackError::Capacity)
        );
        let mut t = Tracker::new(1, 1);
        t.observe(flow(1), u64::MAX - 1).unwrap();
        assert_eq!(t.expire(u64::MAX), Ok(1));
        assert!(t.is_empty());
    }
    #[test]
    fn reverse_direction_and_protocol_are_distinct() {
        let a = flow(1);
        let b = FlowId {
            source: a.destination,
            destination: a.source,
            source_port: a.destination_port,
            destination_port: a.source_port,
            ..a
        };
        let c = FlowId {
            protocol: Protocol::Udp,
            ..a
        };
        let mut t = Tracker::new(3, 10);
        for f in [a, b, c] {
            t.observe(f, 0).unwrap();
        }
        assert_eq!(t.len(), 3);
    }
    #[test]
    fn expiry_index_stays_bounded_and_removes_only_due_flows() {
        let mut t = Tracker::new(3, 10);
        t.observe(flow(1), 0).unwrap();
        t.observe(flow(2), 1).unwrap();
        for now in 2..1000 {
            t.observe(flow(1), now).unwrap();
            assert_eq!(t.order.len(), t.flows.len());
        }
        assert_eq!(t.len(), 1);
        assert_eq!(t.expire(1008), Ok(0));
        assert_eq!(t.expire(1009), Ok(1));
        t.observe(flow(2), 1009).unwrap();
        assert!(t.remove(&flow(2)).is_some());
        assert!(t.order.is_empty());
        t.observe(flow(1), 1010).unwrap();
        assert_eq!(t.clear(), 1);
        assert!(t.order.is_empty());
        assert_eq!(t.observe(flow(1), 0), Err(TrackError::ClockReversed));
    }
    #[test]
    fn indexed_tracker_matches_linear_reference_over_mixed_operations() {
        let mut t = Tracker::new(8, 7);
        let mut reference: HashMap<FlowId, Observation> = HashMap::new();
        let mut clock = 0u64;
        let mut seed = 0x123456789u64;
        for _ in 0..20_000 {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            let now = if seed & 31 == 0 {
                clock.saturating_sub(1)
            } else {
                clock + (seed % 3)
            };
            let id = flow((seed % 16) as u16);
            match (seed >> 8) % 4 {
                0 => {
                    assert_eq!(t.remove(&id), reference.remove(&id));
                }
                1 => {
                    assert_eq!(t.clear(), reference.len());
                    reference.clear();
                }
                operation => {
                    let expected = if now < clock {
                        Err(TrackError::ClockReversed)
                    } else {
                        clock = now;
                        let before = reference.len();
                        reference.retain(|_, v| now - v.last_seen < 7);
                        if operation == 2 {
                            Ok((before - reference.len()) as u64)
                        } else if let Some(v) = reference.get_mut(&id) {
                            v.last_seen = now;
                            Ok(v.created_at)
                        } else if reference.len() == 8 {
                            Err(TrackError::Capacity)
                        } else {
                            reference.insert(
                                id,
                                Observation {
                                    created_at: now,
                                    last_seen: now,
                                },
                            );
                            Ok(now)
                        }
                    };
                    let actual = if operation == 2 {
                        t.expire(now).map(|v| v as u64)
                    } else {
                        t.observe(id, now).map(|v| v.created_at)
                    };
                    assert_eq!(actual, expected);
                }
            }
            assert_eq!(t.flows, reference);
            assert_eq!(t.order.len(), reference.len());
            for (id, v) in &reference {
                assert!(t.order.contains(&(v.last_seen, *id)));
            }
        }
    }
    #[test]
    fn expiry_callbacks_report_each_due_id_once_in_partial_and_full_batches() {
        let mut t = Tracker::new(3, 10);
        for i in 0..3 {
            t.observe(flow(i), u64::from(i)).unwrap();
        }
        let mut removed = BTreeSet::new();
        assert_eq!(
            t.expire_with(10, |id| {
                assert!(removed.insert(id));
            }),
            Ok(1)
        );
        assert_eq!(removed, BTreeSet::from([flow(0)]));
        assert_eq!(
            t.expire_with(12, |id| {
                assert!(removed.insert(id));
            }),
            Ok(2)
        );
        assert_eq!(removed, BTreeSet::from([flow(0), flow(1), flow(2)]));
        assert!(t.order.is_empty());
        assert!(t.flows.is_empty());
        assert_eq!(
            t.expire_with(11, |_| panic!("reversed clock cannot emit removals")),
            Err(TrackError::ClockReversed)
        );
    }
}
