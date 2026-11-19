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
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Observation {
    pub created_at: u64,
    pub last_seen: u64,
    /// Accounting by the caller via [`Tracker::account`]; saturating, informational only.
    /// `outbound` is the flow's own direction, `inbound` is replies attributed to it.
    pub outbound: Counters,
    pub inbound: Counters,
    /// Most recent owning uid the caller resolved; never an authorization input.
    pub uid: Option<u32>,
}
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Counters {
    pub packets: u64,
    pub bytes: u64,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Direction {
    Outbound,
    Inbound,
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
            outbound: Counters::default(),
            inbound: Counters::default(),
            uid: None,
        };
        self.flows.insert(id, flow);
        self.order.insert((now, id));
        Ok(flow)
    }
    /// Tick at which the oldest observation expires, or None when no flow is tracked.
    pub fn next_expiry(&self) -> Option<u64> {
        self.order
            .first()
            .map(|(seen, _)| seen.saturating_add(self.timeout))
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
    /// Adds one packet of `bytes` to an existing flow's counters (saturating) and remembers a
    /// resolved `uid`. Never creates a flow, refreshes its lease or changes expiry order.
    /// Returns false when the flow is not tracked.
    pub fn account(
        &mut self,
        id: &FlowId,
        direction: Direction,
        bytes: u64,
        uid: Option<u32>,
    ) -> bool {
        let Some(flow) = self.flows.get_mut(id) else {
            return false;
        };
        let counters = match direction {
            Direction::Outbound => &mut flow.outbound,
            Direction::Inbound => &mut flow.inbound,
        };
        counters.packets = counters.packets.saturating_add(1);
        counters.bytes = counters.bytes.saturating_add(bytes);
        if uid.is_some() {
            flow.uid = uid;
        }
        true
    }
    /// Remembers a resolved owner uid for an existing flow without counting a packet, refreshing
    /// its lease or touching expiry order. Returns false when the flow is not tracked.
    pub fn set_uid(&mut self, id: &FlowId, uid: Option<u32>) -> bool {
        match self.flows.get_mut(id) {
            Some(flow) => {
                flow.uid = uid;
                true
            }
            None => false,
        }
    }
    /// Copies at most `limit` observations, most recently seen first (ties in `FlowId` order, so
    /// the result is deterministic). Read-only: O(limit) time and allocation, no state change.
    /// Entries past their timeout stay listed until `expire` or `observe` sweeps them.
    pub fn snapshot(&self, limit: usize) -> Vec<(FlowId, Observation)> {
        self.order
            .iter()
            .rev()
            .filter_map(|(_, id)| self.flows.get(id).map(|flow| (*id, *flow)))
            .take(limit)
            .collect()
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
                last_seen: 1,
                ..Observation::default()
            }
        );
        assert_eq!(t.observe(flow(2), 2), Err(TrackError::Capacity));
        assert_eq!(
            t.observe(flow(1), 5).unwrap(),
            Observation {
                created_at: 1,
                last_seen: 5,
                ..Observation::default()
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
    fn next_expiry_tracks_the_oldest_observation() {
        let mut t = Tracker::new(2, 10);
        assert_eq!(t.next_expiry(), None);
        t.observe(flow(1), 3).unwrap();
        t.observe(flow(2), 5).unwrap();
        assert_eq!(t.next_expiry(), Some(13));
        t.observe(flow(1), 8).unwrap(); // refresh moves flow 1 behind flow 2
        assert_eq!(t.next_expiry(), Some(15));
        t.remove(&flow(2));
        assert_eq!(t.next_expiry(), Some(18));
        t.clear();
        assert_eq!(t.next_expiry(), None);
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
                                    ..Observation::default()
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
    #[test]
    fn snapshot_is_newest_first_bounded_and_read_only() {
        let mut t = Tracker::new(8, 100);
        t.observe(flow(1), 1).unwrap();
        t.observe(flow(2), 2).unwrap();
        t.observe(flow(3), 3).unwrap();
        t.observe(flow(1), 4).unwrap(); // refresh moves flow 1 to the front
        let all = t.snapshot(10);
        let ports: Vec<u16> = all.iter().map(|(id, _)| id.source_port).collect();
        assert_eq!(ports, [1, 3, 2]);
        assert_eq!(all[0].1.created_at, 1);
        assert_eq!(all[0].1.last_seen, 4);
        assert_eq!(t.snapshot(2).len(), 2);
        assert!(t.snapshot(0).is_empty());
        assert_eq!(t.len(), 3);
        assert_eq!(t.snapshot(10), all, "snapshot must not change state");
    }
    #[test]
    fn snapshot_ties_are_deterministic_and_removed_flows_disappear() {
        let mut t = Tracker::new(8, 100);
        t.observe(flow(9), 5).unwrap();
        t.observe(flow(3), 5).unwrap();
        let ports: Vec<u16> = t.snapshot(8).iter().map(|(id, _)| id.source_port).collect();
        assert_eq!(ports, [9, 3]);
        t.remove(&flow(9));
        assert_eq!(t.snapshot(8).len(), 1);
        t.clear();
        assert!(t.snapshot(8).is_empty());
    }
    #[test]
    fn accounting_is_saturating_directional_and_never_refreshes() {
        let mut t = Tracker::new(4, 100);
        assert!(!t.account(&flow(1), Direction::Outbound, 10, Some(7)));
        assert_eq!(t.len(), 0, "account must not create a flow");
        t.observe(flow(1), 5).unwrap();
        assert!(t.account(&flow(1), Direction::Outbound, 100, Some(10_001)));
        assert!(t.account(&flow(1), Direction::Outbound, 50, None));
        assert!(t.account(&flow(1), Direction::Inbound, 1_500, None));
        let o = *t.get(&flow(1)).unwrap();
        assert_eq!(
            o.outbound,
            Counters {
                packets: 2,
                bytes: 150
            }
        );
        assert_eq!(
            o.inbound,
            Counters {
                packets: 1,
                bytes: 1_500
            }
        );
        assert_eq!(o.uid, Some(10_001), "None keeps the last resolved uid");
        assert_eq!(o.last_seen, 5, "accounting must not refresh the lease");
        assert_eq!(t.next_expiry(), Some(105));
        assert!(t.account(&flow(1), Direction::Inbound, u64::MAX, None));
        assert!(t.account(&flow(1), Direction::Inbound, 1, None));
        assert_eq!(t.get(&flow(1)).unwrap().inbound.bytes, u64::MAX);
    }
    #[test]
    fn set_uid_only_updates_an_existing_flow() {
        let mut t = Tracker::new(4, 100);
        assert!(!t.set_uid(&flow(1), Some(1)));
        assert_eq!(t.len(), 0, "set_uid must not create a flow");
        t.observe(flow(1), 7).unwrap();
        assert!(t.set_uid(&flow(1), Some(10_001)));
        let o = *t.get(&flow(1)).unwrap();
        assert_eq!(o.uid, Some(10_001));
        assert_eq!(
            (o.last_seen, o.outbound, o.inbound),
            (7, Counters::default(), Counters::default())
        );
        assert_eq!(t.next_expiry(), Some(107));
        assert!(t.set_uid(&flow(1), None));
        assert_eq!(t.get(&flow(1)).unwrap().uid, None);
    }
}
