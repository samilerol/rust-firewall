//! Platform-independent checked packet admission. Admission does not implement TCP state or I/O.
use netscope_conntrack::{FlowId, Observation, TrackError, Tracker};
use netscope_packet::{parse_checked, ChecksumPolicy, Packet, ParseError};
use netscope_policy::{Action, Context, ContextRule, Decision, Policy, PolicyError, Rule};

pub const MAX_FLOWS: usize = 65_536;
#[derive(Clone, Copy, Debug)]
pub struct Config {
    pub max_flows: usize,
    pub timeout: u64,
    pub checksums: ChecksumPolicy,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConfigError {
    TooManyFlows,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DropReason {
    Packet(ParseError),
    Policy { rule_index: Option<usize> },
    FlowCapacity,
    ClockReversed,
    UnmatchedResponse,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Outcome {
    Accepted { packet: Packet, decision: Decision },
    Dropped(DropReason),
}
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Stats {
    pub accepted: u64,
    pub malformed: u64,
    pub policy_denied: u64,
    pub capacity_denied: u64,
    pub clock_denied: u64,
    pub unmatched_responses: u64,
}
pub struct Engine {
    policy: Policy,
    flows: Tracker,
    checksums: ChecksumPolicy,
    stats: Stats,
}
impl Engine {
    pub fn new(policy: Policy, config: Config) -> Result<Self, ConfigError> {
        if config.max_flows > MAX_FLOWS {
            return Err(ConfigError::TooManyFlows);
        }
        Ok(Self {
            policy,
            flows: Tracker::new(config.max_flows, config.timeout),
            checksums: config.checksums,
            stats: Stats::default(),
        })
    }
    /// Every datagram is parsed and re-evaluated, even for an already observed flow.
    pub fn process(&mut self, bytes: &[u8], now: u64) -> Outcome {
        self.process_in(bytes, now, &Context::default())
    }
    /// Like [`Engine::process`] for a flow whose uid/network the caller resolved. The caller must
    /// pass the same context for every packet of a flow and again to `authorize_response_in`.
    pub fn process_in(&mut self, bytes: &[u8], now: u64, context: &Context) -> Outcome {
        if self.flows.expire(now).is_err() {
            return self.drop_packet(DropReason::ClockReversed);
        }
        let packet = match parse_checked(bytes, self.checksums) {
            Ok(v) => v.packet,
            Err(e) => return self.drop_packet(DropReason::Packet(e)),
        };
        let decision = self.policy.decide_in(&packet, context);
        if decision.action == Action::Deny {
            return self.drop_packet(DropReason::Policy {
                rule_index: decision.rule_index,
            });
        }
        if let Err(error) = self.flows.observe(FlowId::from(&packet), now) {
            return self.drop_packet(match error {
                TrackError::Capacity => DropReason::FlowCapacity,
                TrackError::ClockReversed => DropReason::ClockReversed,
            });
        }
        self.stats.accepted = self.stats.accepted.saturating_add(1);
        Outcome::Accepted { packet, decision }
    }
    fn drop_packet(&mut self, reason: DropReason) -> Outcome {
        let count = match reason {
            DropReason::Packet(_) => &mut self.stats.malformed,
            DropReason::Policy { .. } => &mut self.stats.policy_denied,
            DropReason::FlowCapacity => &mut self.stats.capacity_denied,
            DropReason::ClockReversed => &mut self.stats.clock_denied,
            DropReason::UnmatchedResponse => &mut self.stats.unmatched_responses,
        };
        *count = count.saturating_add(1);
        Outcome::Dropped(reason)
    }
    /// Validate a whole replacement before mutation. A failed update keeps the active policy.
    pub fn update_policy(&mut self, rules: Vec<Rule>, default: Action) -> Result<(), PolicyError> {
        self.replace_policy(Policy::new(rules, default)?);
        Ok(())
    }
    /// [`Engine::update_policy`] for rules with uid/network constraints.
    pub fn update_context_policy(
        &mut self,
        rules: Vec<ContextRule>,
        default: Action,
    ) -> Result<(), PolicyError> {
        self.replace_policy(Policy::with_context_rules(rules, default)?);
        Ok(())
    }
    fn replace_policy(&mut self, candidate: Policy) {
        self.policy = candidate;
        self.flows.clear();
    }
    /// Response authorization only: checks integrity, current policy and monotonic time,
    /// but does not create or refresh a reverse flow observation.
    pub fn authorize_response(&mut self, bytes: &[u8], original: &FlowId, now: u64) -> Outcome {
        self.authorize_response_in(bytes, original, now, &Context::default())
    }
    /// [`Engine::authorize_response`] evaluated with the original flow's context.
    pub fn authorize_response_in(
        &mut self,
        bytes: &[u8],
        original: &FlowId,
        now: u64,
        context: &Context,
    ) -> Outcome {
        if self.flows.expire(now).is_err() {
            return self.drop_packet(DropReason::ClockReversed);
        }
        let packet = match parse_checked(bytes, self.checksums) {
            Ok(v) => v.packet,
            Err(e) => return self.drop_packet(DropReason::Packet(e)),
        };
        if self.flows.get(original).is_none()
            || packet.source != original.destination
            || packet.destination != original.source
            || packet.source_port != original.destination_port
            || packet.destination_port != original.source_port
            || packet.protocol != original.protocol
        {
            return self.drop_packet(DropReason::UnmatchedResponse);
        }
        let decision = self.policy.decide_in(&packet, context);
        if decision.action == Action::Deny {
            return self.drop_packet(DropReason::Policy {
                rule_index: decision.rule_index,
            });
        }
        self.stats.accepted = self.stats.accepted.saturating_add(1);
        Outcome::Accepted { packet, decision }
    }
    pub fn expire(&mut self, now: u64) -> Result<usize, TrackError> {
        self.flows.expire(now)
    }
    pub fn expire_with(
        &mut self,
        now: u64,
        removed: impl FnMut(FlowId),
    ) -> Result<usize, TrackError> {
        self.flows.expire_with(now, removed)
    }
    /// Extend an existing flow's idle lease after the caller accepted traffic for it (for
    /// example an authorized UDP reply). Never creates a flow and never authorizes anything.
    pub fn refresh_flow(&mut self, id: &FlowId, now: u64) {
        if self.flows.get(id).is_some() {
            let _ = self.flows.observe(*id, now);
        }
    }
    /// Tick at which the oldest tracked flow expires; lets a caller sleep until then.
    pub fn next_expiry(&self) -> Option<u64> {
        self.flows.next_expiry()
    }
    /// Bounded copy of the tracked flows, newest first; see `Tracker::snapshot`.
    pub fn flow_snapshot(&self, limit: usize) -> Vec<(FlowId, Observation)> {
        self.flows.snapshot(limit)
    }
    pub fn flow_count(&self) -> usize {
        self.flows.len()
    }
    pub fn contains_flow(&self, id: &FlowId) -> bool {
        self.flows.get(id).is_some()
    }
    pub fn forget_flow(&mut self, id: &FlowId) {
        self.flows.remove(id);
    }
    pub fn reset_network(&mut self) -> usize {
        self.flows.clear()
    }
    pub fn stats(&self) -> Stats {
        self.stats
    }
}
