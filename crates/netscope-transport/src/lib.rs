//! Bounded nonblocking UDP relay. No TCP stack or Android socket protection implementation.
use netscope_conntrack::{FlowId, Observation};
use netscope_dns::{parse_query, parse_response, DomainPolicy};
use netscope_engine::{Config, DropReason, Engine, Outcome, Stats};
use netscope_packet::{parse, udp, Protocol};
use netscope_policy::{Action, Context, Policy, PolicyError, Rule};
use std::{
    collections::{BTreeSet, HashMap, VecDeque},
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket},
    time::Duration,
};

pub const MAX_UDP_FLOWS: usize = 1024;
pub const MAX_DNS_PENDING_PER_FLOW: usize = 64;
pub const MAX_DNS_PENDING_TOTAL: usize = 4096;
/// DNS transaction budgets. Timeout uses the same caller-supplied ticks as Engine.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DnsLimits {
    pub max_pending_per_flow: usize,
    pub max_pending_total: usize,
    pub query_timeout: u64,
}
impl DnsLimits {
    fn valid(self) -> bool {
        (1..=MAX_DNS_PENDING_PER_FLOW).contains(&self.max_pending_per_flow)
            && (1..=MAX_DNS_PENDING_TOTAL).contains(&self.max_pending_total)
            && self.query_timeout > 0
    }
}
mod dns_pending;
use dns_pending::PendingQueries;
/// Required platform hook. Called on a fresh bound socket BEFORE connect or send.
/// Android implementations must call VpnService.protect and reject false/errors.
/// No default/no-op implementation is provided by this crate.
pub trait SocketProtector {
    fn protect(&self, socket: &UdpSocket) -> io::Result<()>;
}
#[derive(Debug)]
pub enum RelayError {
    Config,
    UnsupportedProtocol,
    UnsupportedAddress,
    MtuExceeded,
    UnknownFlow,
    Dropped(DropReason),
    Io(io::Error),
    Encode(udp::EncodeError),
    Dns(DnsError),
}
impl From<io::Error> for RelayError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DnsError {
    Malformed(netscope_dns::ParseError),
    DomainDenied {
        rule_index: Option<usize>,
    },
    /// The same transaction ID is already waiting for a different question.
    Busy,
    Capacity,
    /// Invalid TCP DNS two-byte message length.
    FrameLength,
    /// A TCP half-close interrupted a DNS frame.
    IncompleteFrame,
    Unsolicited,
    Mismatched,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Sent {
    pub flow: FlowId,
    pub payload_bytes: usize,
}
#[derive(Debug)]
pub struct UdpReply {
    pub flow: FlowId,
    pub result: Result<Vec<u8>, RelayError>,
}
/// One upstream socket and the uid/network context its flow was admitted with.
struct UdpFlow {
    socket: UdpSocket,
    context: Context,
}
pub struct UdpRelay<P> {
    engine: Engine,
    sockets: HashMap<FlowId, UdpFlow>,
    receive_order: VecDeque<FlowId>,
    protector: P,
    mtu: usize,
    receive_buffer: Box<[u8]>,
    dns_policy: Option<DomainPolicy>,
    dns_ports: BTreeSet<u16>,
    dns_pending: PendingQueries,
}
impl<P: SocketProtector> UdpRelay<P> {
    pub fn new(
        policy: Policy,
        config: Config,
        mtu: usize,
        protector: P,
    ) -> Result<Self, RelayError> {
        if config.max_flows > MAX_UDP_FLOWS || !(1280..=65575).contains(&mtu) {
            return Err(RelayError::Config);
        }
        let engine = Engine::new(policy, config).map_err(|_| RelayError::Config)?;
        Ok(Self {
            engine,
            sockets: HashMap::new(),
            receive_order: VecDeque::new(),
            protector,
            mtu,
            receive_buffer: vec![0; 65528].into_boxed_slice(),
            dns_policy: None,
            dns_ports: BTreeSet::new(),
            dns_pending: PendingQueries::new(DnsLimits {
                max_pending_per_flow: 8,
                max_pending_total: MAX_DNS_PENDING_TOTAL,
                query_timeout: config.timeout.max(1),
            }),
        })
    }
    /// Call periodically when idle as well as on send/receive to release expired sockets.
    pub fn expire(&mut self, now: u64) -> Result<usize, RelayError> {
        let sockets = &mut self.sockets;
        let pending = &mut self.dns_pending;
        let expired = self
            .engine
            .expire_with(now, |id| {
                sockets.remove(&id);
                pending.remove_flow(&id);
            })
            .map_err(|_| RelayError::Dropped(DropReason::ClockReversed))?;
        if expired != 0 {
            self.receive_order
                .retain(|id| self.sockets.contains_key(id));
        }
        self.dns_pending.expire(now);
        Ok(expired)
    }
    fn forget(&mut self, id: &FlowId) {
        self.sockets.remove(id);
        self.receive_order.retain(|flow| flow != id);
        self.dns_pending.remove_flow(id);
        self.engine.forget_flow(id);
    }
    /// Validate/admit a full IP/UDP datagram, then send its payload using one protected socket per flow.
    /// WouldBlock/error is returned; there is no hidden retry queue or background task.
    pub fn send(&mut self, bytes: &[u8], now: u64) -> Result<Sent, RelayError> {
        self.send_in(bytes, now, &Context::default())
    }
    /// [`UdpRelay::send`] for a flow whose uid/network the caller resolved. The context is
    /// recorded when the flow is created and reused for every later packet and reply of that
    /// flow; a different context passed for an existing flow is ignored. A network change should
    /// go through `reset_network`.
    pub fn send_in(
        &mut self,
        bytes: &[u8],
        now: u64,
        context: &Context,
    ) -> Result<Sent, RelayError> {
        self.expire(now)?;
        if bytes.len() > self.mtu {
            return Err(RelayError::MtuExceeded);
        }
        let metadata = parse(bytes).map_err(|e| RelayError::Dropped(DropReason::Packet(e)))?;
        if metadata.protocol != Protocol::Udp {
            return Err(RelayError::UnsupportedProtocol);
        }
        let unsupported = unsupported_endpoint(&metadata);
        if unsupported {
            return Err(RelayError::UnsupportedAddress);
        }
        let candidate_id = FlowId::from(&metadata);
        let context = self
            .sockets
            .get(&candidate_id)
            .map_or(*context, |flow| flow.context);
        let dns_query = if let Some(policy) = self
            .dns_policy
            .as_ref()
            .filter(|_| self.dns_ports.contains(&metadata.destination_port))
        {
            let offset = if metadata.source.is_ipv4() { 28 } else { 48 };
            let query = parse_query(&bytes[offset..])
                .map_err(|e| RelayError::Dns(DnsError::Malformed(e)))?;
            let decision = policy.decide(&query.question.name);
            if decision.action == Action::Deny {
                return Err(RelayError::Dns(DnsError::DomainDenied {
                    rule_index: decision.rule_index,
                }));
            }
            self.dns_pending
                .check(&candidate_id, &query)
                .map_err(RelayError::Dns)?;
            Some(query)
        } else {
            None
        };
        let packet = match self.engine.process_in(bytes, now, &context) {
            Outcome::Accepted { packet, .. } => packet,
            Outcome::Dropped(reason) => return Err(RelayError::Dropped(reason)),
        };
        let id = FlowId::from(&packet);
        if !self.sockets.contains_key(&id) {
            let opened = (|| -> io::Result<UdpSocket> {
                let local = match packet.source {
                    IpAddr::V4(_) => SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 0),
                    IpAddr::V6(_) => SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), 0),
                };
                let socket = UdpSocket::bind(local)?;
                self.protector.protect(&socket)?;
                socket.connect(SocketAddr::new(packet.destination, packet.destination_port))?;
                socket.set_nonblocking(true)?;
                Ok(socket)
            })();
            match opened {
                Ok(socket) => {
                    self.sockets.insert(id, UdpFlow { socket, context });
                    self.receive_order.push_back(id);
                }
                Err(error) => {
                    self.forget(&id);
                    return Err(RelayError::Io(error));
                }
            }
        }
        let offset = if packet.source.is_ipv4() { 28 } else { 48 };
        let result = self.sockets[&id].socket.send(&bytes[offset..]);
        match result {
            Ok(count) if count == bytes.len() - offset => {
                if let Some(query) = dns_query {
                    self.dns_pending.record(id, query, now);
                }
                Ok(Sent {
                    flow: id,
                    payload_bytes: count,
                })
            }
            Ok(_) => {
                self.forget(&id);
                Err(RelayError::Io(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "partial UDP send",
                )))
            }
            // A full send buffer loses this datagram only; the flow and its socket stay.
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => Err(RelayError::Io(error)),
            Err(error) => {
                self.forget(&id);
                Err(RelayError::Io(error))
            }
        }
    }
    /// Nonblocking receive for a known flow. Connected sockets restrict the peer.
    /// Responses require their own CURRENT directional policy decision; outbound allow is not inbound allow.
    pub fn receive(&mut self, id: FlowId, now: u64) -> Result<Vec<u8>, RelayError> {
        self.expire(now)?;
        self.receive_live(id, now)
    }

    /// Inspect at most `flow_budget` sockets in round-robin order and return the first reply.
    /// Per-flow failures identify the affected flow. A zero budget still runs expiry.
    pub fn receive_next(
        &mut self,
        now: u64,
        flow_budget: usize,
    ) -> Result<Option<UdpReply>, RelayError> {
        self.expire(now)?;
        for _ in 0..flow_budget.min(self.receive_order.len()) {
            let Some(flow) = self.receive_order.pop_front() else {
                break;
            };
            self.receive_order.push_back(flow);
            match self.receive_live(flow, now) {
                Err(RelayError::Io(e)) if e.kind() == io::ErrorKind::WouldBlock => continue,
                result => return Ok(Some(UdpReply { flow, result })),
            }
        }
        Ok(None)
    }

    fn receive_live(&mut self, id: FlowId, now: u64) -> Result<Vec<u8>, RelayError> {
        let flow = self.sockets.get(&id).ok_or(RelayError::UnknownFlow)?;
        let context = flow.context;
        let count = match flow.socket.recv(&mut self.receive_buffer) {
            Ok(count) => count,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                return Err(RelayError::Io(error))
            }
            Err(error) => {
                self.forget(&id);
                return Err(RelayError::Io(error));
            }
        };
        let header = if id.source.is_ipv4() { 28 } else { 48 };
        if count + header > self.mtu {
            // Only this datagram is discarded; the peer cannot tear down the flow with one packet.
            return Err(RelayError::MtuExceeded);
        }
        let mut answered_id = None;
        if let Some(policy) = self
            .dns_policy
            .as_ref()
            .filter(|_| self.dns_ports.contains(&id.destination_port))
        {
            let checked = (|| -> Result<(), DnsError> {
                let response =
                    parse_response(&self.receive_buffer[..count]).map_err(DnsError::Malformed)?;
                self.dns_pending.matches(&id, &response)?;
                let decision = policy.decide(&response.question.name);
                if decision.action == Action::Deny {
                    return Err(DnsError::DomainDenied {
                        rule_index: decision.rule_index,
                    });
                }
                answered_id = Some(response.id);
                Ok(())
            })();
            if let Err(error) = checked {
                return Err(RelayError::Dns(error));
            }
        }
        let response = udp::encode(
            SocketAddr::new(id.destination, id.destination_port),
            SocketAddr::new(id.source, id.source_port),
            &self.receive_buffer[..count],
        )
        .map_err(RelayError::Encode)?;
        match self
            .engine
            .authorize_response_in(&response, &id, now, &context)
        {
            Outcome::Accepted { .. } => {
                if let Some(query_id) = answered_id {
                    self.dns_pending.remove_query(&id, query_id);
                }
                self.engine.refresh_flow(&id, now);
                Ok(response)
            }
            Outcome::Dropped(reason) => {
                self.forget(&id);
                Err(RelayError::Dropped(reason))
            }
        }
    }
    /// A valid policy update closes ALL existing UDP sockets/observations; invalid input changes nothing.
    pub fn update_policy(&mut self, rules: Vec<Rule>, default: Action) -> Result<(), PolicyError> {
        self.engine.update_policy(rules, default)?;
        self.reset_network();
        Ok(())
    }
    /// [`UdpRelay::update_policy`] for rules with uid/network constraints.
    pub fn update_context_policy(
        &mut self,
        rules: Vec<netscope_policy::ContextRule>,
        default: Action,
    ) -> Result<(), PolicyError> {
        self.engine.update_context_policy(rules, default)?;
        self.reset_network();
        Ok(())
    }
    /// Block up to `max_wait` until an upstream socket has a datagram to `receive`, or until the
    /// oldest flow's idle deadline (so expired sockets are released on time), then return the
    /// ready flows. Call `receive` on each until it reports `WouldBlock`. `now` and the engine
    /// timeout are interpreted as milliseconds here. An empty list means timeout or a signal.
    /// Uses level-triggered `poll(2)` through a safe wrapper: cost is linear in open flows.
    /// To wait on TCP and UDP together use `event::wait_ready`.
    #[cfg(unix)]
    pub fn wait_ready(&mut self, now: u64, max_wait: Duration) -> Result<Vec<FlowId>, RelayError> {
        self.expire(now)?;
        let wait = event::bounded_wait(now, max_wait, &[self.next_wakeup()]);
        let entries = self.poll_entries();
        let ready = event::poll_entries(&entries, wait)?;
        Ok(entries
            .iter()
            .zip(ready)
            .filter(|(_, ready)| *ready)
            .map(|((id, _, _), _)| *id)
            .collect())
    }
    /// Earliest tick at which the oldest flow's idle lease ends (milliseconds for the wait APIs).
    #[cfg(unix)]
    pub fn next_wakeup(&self) -> Option<u64> {
        self.engine.next_expiry()
    }
    #[cfg(unix)]
    pub(crate) fn poll_entries(&self) -> Vec<event::Entry<'_>> {
        use std::os::fd::AsFd;
        self.sockets
            .iter()
            .map(|(id, flow)| (*id, flow.socket.as_fd(), rustix::event::PollFlags::IN))
            .collect()
    }
    /// Caller must invoke on upstream-network change. No OS network observer is implemented here.
    pub fn reset_network(&mut self) {
        self.sockets.clear();
        self.receive_order.clear();
        self.dns_pending.clear();
        self.engine.reset_network();
    }
    /// Enable question-based filtering only on the explicit destination ports. No global DNS guarantee.
    /// Bounded concurrent IDs per flow; identical retries keep their original deadline.
    /// A valid change revokes mappings and preserves configured DNS limits.
    pub fn set_dns_filter(
        &mut self,
        policy: Option<DomainPolicy>,
        ports: Vec<u16>,
    ) -> Result<(), RelayError> {
        if ports.len() > 32 || ports.contains(&0) || policy.is_some() == ports.is_empty() {
            return Err(RelayError::Config);
        }
        let count = ports.len();
        let ports: BTreeSet<_> = ports.into_iter().collect();
        if ports.len() != count {
            return Err(RelayError::Config);
        }
        self.dns_policy = policy;
        self.dns_ports = ports;
        self.reset_network();
        Ok(())
    }
    /// Set nonzero bounded DNS budgets. Valid changes revoke all mappings; invalid input changes nothing.
    /// Constructor defaults: 8 per flow, 4096 total, timeout equal to Engine's timeout (at least 1 tick).
    /// Expiration is measured from first successful send, independent of other traffic/retries.
    pub fn set_dns_limits(&mut self, limits: DnsLimits) -> Result<(), RelayError> {
        if !limits.valid() {
            return Err(RelayError::Config);
        }
        self.reset_network();
        self.dns_pending = PendingQueries::new(limits);
        Ok(())
    }
    pub fn pending_dns_count(&self) -> usize {
        self.dns_pending.len()
    }
    pub fn flow_count(&self) -> usize {
        self.sockets.len()
    }
    /// Records the platform-resolved owner uid of an existing flow (informational only).
    pub fn note_owner(&mut self, id: &FlowId, uid: Option<u32>) -> bool {
        self.engine.note_owner(id, uid)
    }
    /// Bounded copy of the engine's tracked flows, newest first. Read-only.
    pub fn flow_snapshot(&self, limit: usize) -> Vec<(FlowId, Observation)> {
        self.engine.flow_snapshot(limit)
    }
    pub fn stats(&self) -> Stats {
        self.engine.stats()
    }
}

/// Safe `poll(2)` readiness wait shared by the TCP and UDP relays.
#[cfg(unix)]
pub mod event;
/// Unix/Android bridge for protecting the actual native sockets owned by Rust.
#[cfg(unix)]
pub mod fd_protection;
/// Packet-oriented TCP proxy using a bounded userspace TCP stack and protected upstream streams.
pub mod tcp;

fn unsupported_endpoint(metadata: &netscope_packet::Packet) -> bool {
    let destination = match metadata.destination {
        IpAddr::V4(ip) => ip.is_unspecified() || ip.is_broadcast() || ip.is_multicast(),
        IpAddr::V6(ip) => {
            ip.is_unspecified()
                || ip.is_multicast()
                || ip.is_unicast_link_local()
                || ip.to_ipv4_mapped().is_some()
        }
    };
    let source = match metadata.source {
        IpAddr::V4(ip) => ip.is_unspecified() || ip.is_broadcast() || ip.is_multicast(),
        IpAddr::V6(ip) => ip.is_unspecified() || ip.is_multicast() || ip.to_ipv4_mapped().is_some(),
    };
    destination || source || metadata.source_port == 0 || metadata.destination_port == 0
}

/// Development-only pure DNS transaction state oracle; performs no network I/O.
#[cfg(feature = "fuzzing")]
#[doc(hidden)]
pub fn exercise_dns_transactions(bytes: &[u8]) {
    dns_pending::exercise(bytes);
}
