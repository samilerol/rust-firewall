//! Bounded nonblocking UDP relay. No TCP stack or Android socket protection implementation.
use netscope_conntrack::FlowId;
use netscope_dns::{parse_query, parse_response, DomainPolicy, Message};
use netscope_engine::{Config, DropReason, Engine, Outcome, Stats};
use netscope_packet::{parse, udp, Protocol};
use netscope_policy::{Action, Context, Policy, PolicyError, Rule};
use std::{
    collections::{BTreeSet, HashMap},
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket},
    time::Duration,
};

pub const MAX_UDP_FLOWS: usize = 1024;
/// Most outstanding DNS questions per flow. Resolvers often send A and AAAA concurrently from one
/// socket; each is matched by (id, question) and expires independently.
pub const MAX_DNS_PENDING: usize = 8;
/// An outstanding DNS question and when it was last sent (retransmissions refresh it).
struct PendingDns {
    query: Message,
    sent_at: u64,
}
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
    DomainDenied { rule_index: Option<usize> },
    Busy,
    Unsolicited,
    Mismatched,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Sent {
    pub flow: FlowId,
    pub payload_bytes: usize,
}
/// One upstream socket and the uid/network context its flow was admitted with.
struct UdpFlow {
    socket: UdpSocket,
    context: Context,
}
pub struct UdpRelay<P> {
    engine: Engine,
    sockets: HashMap<FlowId, UdpFlow>,
    protector: P,
    mtu: usize,
    receive_buffer: Box<[u8]>,
    dns_policy: Option<DomainPolicy>,
    dns_ports: BTreeSet<u16>,
    dns_pending: HashMap<FlowId, Vec<PendingDns>>,
    /// Lifetime of an unanswered question: the engine idle timeout.
    dns_ttl: u64,
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
            protector,
            mtu,
            receive_buffer: vec![0; 65528].into_boxed_slice(),
            dns_policy: None,
            dns_ports: BTreeSet::new(),
            dns_pending: HashMap::new(),
            dns_ttl: config.timeout,
        })
    }
    /// Call periodically when idle as well as on send/receive to release expired sockets.
    pub fn expire(&mut self, now: u64) -> Result<usize, RelayError> {
        let sockets = &mut self.sockets;
        let pending = &mut self.dns_pending;
        self.engine
            .expire_with(now, |id| {
                sockets.remove(&id);
                pending.remove(&id);
            })
            .map_err(|_| RelayError::Dropped(DropReason::ClockReversed))
    }
    /// Drop questions older than the DNS lifetime so one stale query cannot hold a slot forever.
    fn prune_pending(&mut self, id: &FlowId, now: u64) {
        let ttl = self.dns_ttl;
        if let Some(list) = self.dns_pending.get_mut(id) {
            list.retain(|p| now.saturating_sub(p.sent_at) < ttl);
            if list.is_empty() {
                self.dns_pending.remove(id);
            }
        }
    }
    fn forget(&mut self, id: &FlowId) {
        self.sockets.remove(id);
        self.dns_pending.remove(id);
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
            self.prune_pending(&candidate_id, now);
            let outstanding = self.dns_pending.get(&candidate_id);
            if outstanding.is_some_and(|list| {
                list.len() >= MAX_DNS_PENDING && !list.iter().any(|p| p.query == query)
            }) {
                return Err(RelayError::Dns(DnsError::Busy));
            }
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
                    let list = self.dns_pending.entry(id).or_default();
                    match list.iter_mut().find(|p| p.query == query) {
                        Some(existing) => existing.sent_at = now, // retransmission
                        None => list.push(PendingDns {
                            query,
                            sent_at: now,
                        }),
                    }
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
        let mut answered = None;
        if self.dns_policy.is_some() && self.dns_ports.contains(&id.destination_port) {
            self.prune_pending(&id, now);
        }
        if let Some(policy) = self
            .dns_policy
            .as_ref()
            .filter(|_| self.dns_ports.contains(&id.destination_port))
        {
            let checked = (|| -> Result<usize, DnsError> {
                let outstanding = self.dns_pending.get(&id).ok_or(DnsError::Unsolicited)?;
                let response =
                    parse_response(&self.receive_buffer[..count]).map_err(DnsError::Malformed)?;
                let position = outstanding
                    .iter()
                    .position(|p| {
                        p.query.id == response.id && p.query.question == response.question
                    })
                    .ok_or(DnsError::Mismatched)?;
                let decision = policy.decide(&response.question.name);
                if decision.action == Action::Deny {
                    return Err(DnsError::DomainDenied {
                        rule_index: decision.rule_index,
                    });
                }
                Ok(position)
            })();
            match checked {
                Ok(position) => answered = Some(position),
                Err(error) => {
                    // A duplicate or late answer is just discarded; other failures revoke the flow.
                    if error != DnsError::Unsolicited {
                        self.forget(&id);
                    }
                    return Err(RelayError::Dns(error));
                }
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
                if let Some(position) = answered {
                    // Consume only the answered question; others stay outstanding.
                    if let Some(list) = self.dns_pending.get_mut(&id) {
                        list.remove(position);
                        if list.is_empty() {
                            self.dns_pending.remove(&id);
                        }
                    }
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
    /// Caller must invoke on upstream-network change. No OS network observer is implemented here.
    pub fn reset_network(&mut self) {
        self.sockets.clear();
        self.dns_pending.clear();
        self.engine.reset_network();
    }
    /// Enable question-based filtering only on the explicit destination ports. No global DNS guarantee.
    /// One pending question per flow; identical retransmissions are allowed. A valid change revokes mappings.
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
    /// Outstanding DNS questions across all flows.
    pub fn pending_dns_count(&self) -> usize {
        self.dns_pending.values().map(Vec::len).sum()
    }
    pub fn flow_count(&self) -> usize {
        self.sockets.len()
    }
    pub fn stats(&self) -> Stats {
        self.engine.stats()
    }
}

/// Unix/Android bridge for protecting the actual native sockets owned by Rust.
#[cfg(unix)]
pub mod event;
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
