//! Bounded directional flow observations, not a TCP state machine or authorization cache.
use netscope_packet::{Packet, Protocol};
use std::{collections::HashMap, net::IpAddr};
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
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
            capacity,
            timeout,
            clock: 0,
        }
    }
    pub fn expire(&mut self, now: u64) -> Result<usize, TrackError> {
        if now < self.clock {
            return Err(TrackError::ClockReversed);
        }
        self.clock = now;
        let before = self.flows.len();
        self.flows.retain(|_, v| now - v.last_seen < self.timeout);
        Ok(before - self.flows.len())
    }
    pub fn observe(&mut self, id: FlowId, now: u64) -> Result<Observation, TrackError> {
        self.expire(now)?;
        if let Some(flow) = self.flows.get_mut(&id) {
            flow.last_seen = now;
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
        Ok(flow)
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
}
