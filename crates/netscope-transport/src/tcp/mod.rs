//! Experimental bounded raw-IP TCP proxy. Caller drives ingress, polling and output draining.
mod device;
use self::device::Device;
use netscope_conntrack::FlowId;
use netscope_engine::{Config as EngineConfig, DropReason, Engine, Outcome};
use netscope_packet::{parse_checked, ChecksumPolicy, Protocol};
use netscope_policy::{Action, Policy, PolicyError, Rule};
use smoltcp::{
    iface::{Config as IfaceConfig, Interface, SocketHandle, SocketSet},
    phy::ChecksumCapabilities,
    socket::tcp::{Socket as StackSocket, SocketBuffer, State},
    time::{Duration as StackDuration, Instant},
    wire::{HardwareAddress, IpAddress, IpCidr, TcpPacket, TcpRepr},
};
use socket2::{Domain, Protocol as OsProtocol, SockRef, Socket, Type};
use std::{
    collections::{HashMap, VecDeque},
    io::{self, Read, Write},
    net::{Shutdown, SocketAddr, TcpStream},
    time::Duration,
};

pub const MAX_FLOWS: usize = 64;
/// smoltcp stores microseconds in i64; retain two days for configured timers.
pub const MAX_TIME_MS: u64 = (i64::MAX as u64) / 1000 - 172_800_000;
pub const MAX_BUFFER_BUDGET: usize = 16 * 1024 * 1024;
pub trait TcpSocketProtector {
    /// Called on an unconnected socket before connect (and therefore before the first SYN).
    /// Trusted platform hook; must protect successfully or return an error. Do not retain clones.
    fn protect(&self, socket: &Socket) -> io::Result<()>;
}
#[derive(Clone, Copy, Debug)]
pub struct Config {
    pub max_flows: usize,
    pub mtu: usize,
    pub buffer_bytes: usize,
    pub output_slots: usize,
    pub buffer_budget: usize,
    pub idle_timeout_ms: u64,
    pub connect_timeout_ms: u64,
}
#[derive(Debug)]
pub enum Error {
    Config,
    Clock,
    Packet(netscope_packet::ParseError),
    Unsupported,
    InitialSynRequired,
    Endpoint,
    Capacity,
    Backpressure,
    Terminated,
    Dropped(DropReason),
    Io(io::Error),
    Entropy,
    Stack,
}
impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PollReport {
    pub io_failures: usize,
    pub connect_timeouts: usize,
    pub closed: usize,
}
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Buffers {
    pub stream_bytes: usize,
    pub queued_packets: usize,
    pub queued_packet_bytes: usize,
    pub reserved_payload_bytes: usize,
}
struct Flow {
    iface: Interface,
    device: Device,
    sockets: SocketSet<'static>,
    handle: SocketHandle,
    upstream: Option<TcpStream>,
    connecting: bool,
    created: u64,
    up_eof: bool,
    write_shutdown: bool,
    failed: bool,
    graceful: bool,
}
impl Drop for Flow {
    fn drop(&mut self) {
        if !self.graceful {
            if let Some(stream) = &self.upstream {
                let _ = SockRef::from(stream).set_linger(Some(Duration::ZERO));
            }
        }
    }
}
impl Flow {
    fn new(id: FlowId, config: Config, now: u64) -> Result<Self, Error> {
        let mut seed = [0; 8];
        getrandom::getrandom(&mut seed).map_err(|_| Error::Entropy)?;
        Self::with_seed(id, config, now, u64::from_ne_bytes(seed))
    }
    fn with_seed(id: FlowId, config: Config, now: u64, seed: u64) -> Result<Self, Error> {
        let mut device = Device::new(config.mtu, config.output_slots);
        let mut cfg = IfaceConfig::new(HardwareAddress::Ip);
        cfg.random_seed = seed;
        let mut iface = Interface::new(cfg, &mut device, Instant::from_millis(now as i64));
        let address = IpAddress::from(id.destination);
        let mut address_added = false;
        iface.update_ip_addrs(|addresses| {
            address_added = addresses
                .push(IpCidr::new(
                    address,
                    if id.destination.is_ipv4() { 32 } else { 128 },
                ))
                .is_ok();
        });
        if !address_added {
            return Err(Error::Stack);
        }
        match id.source {
            std::net::IpAddr::V4(ip) => {
                iface
                    .routes_mut()
                    .add_default_ipv4_route(ip)
                    .map_err(|_| Error::Stack)?;
            }
            std::net::IpAddr::V6(ip) => {
                iface
                    .routes_mut()
                    .add_default_ipv6_route(ip)
                    .map_err(|_| Error::Stack)?;
            }
        }
        let mut socket = StackSocket::new(
            SocketBuffer::new(vec![0; config.buffer_bytes]),
            SocketBuffer::new(vec![0; config.buffer_bytes]),
        );
        socket.set_timeout(Some(StackDuration::from_millis(config.idle_timeout_ms)));
        socket.set_ack_delay(None);
        socket
            .listen((address, id.destination_port))
            .map_err(|_| Error::Stack)?;
        let mut sockets = SocketSet::new(vec![]);
        let handle = sockets.add(socket);
        Ok(Self {
            iface,
            device,
            sockets,
            handle,
            upstream: None,
            connecting: false,
            created: now,
            up_eof: false,
            write_shutdown: false,
            failed: false,
            graceful: false,
        })
    }
    fn stack_poll(&mut self, now: u64) {
        self.iface.poll(
            Instant::from_millis(now as i64),
            &mut self.device,
            &mut self.sockets,
        );
    }
    fn abort(&mut self, now: u64) {
        if let Some(stream) = self.upstream.take() {
            let _ = SockRef::from(&stream).set_linger(Some(Duration::ZERO));
        }
        self.device.rx = None;
        self.device.tx.clear();
        self.sockets.get_mut::<StackSocket>(self.handle).abort();
        self.failed = true;
        self.stack_poll(now);
    }
    /// Abortive close of a flow the relay is discarding: returns the RST the client needs,
    /// or None when the stack socket is not an active connection (nothing to reset).
    fn reset_packet(&mut self, now: u64) -> Option<Vec<u8>> {
        if !self.sockets.get::<StackSocket>(self.handle).is_active() {
            return None;
        }
        self.abort(now);
        self.device.tx.pop_front()
    }
    fn pump(&mut self) -> io::Result<()> {
        let Some(upstream) = self.upstream.as_mut() else {
            return Ok(());
        };
        if self.connecting {
            if let Some(error) = upstream.take_error()? {
                return Err(error);
            }
            match upstream.peer_addr() {
                Ok(_) => self.connecting = false,
                Err(error) if error.kind() == io::ErrorKind::NotConnected => return Ok(()),
                Err(error) => return Err(error),
            }
        }
        let socket = self.sockets.get_mut::<StackSocket>(self.handle);
        if socket.can_recv() {
            let result = socket.recv(|bytes| match upstream.write(bytes) {
                Ok(0) => (
                    0,
                    Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "upstream accepted zero bytes",
                    )),
                ),
                Ok(n) => (n, Ok(())),
                Err(e) if retry(&e) => (0, Ok(())),
                Err(e) => (0, Err(e)),
            });
            if let Ok(result) = result {
                result?;
            }
        }
        if socket.can_send() && !self.up_eof {
            let result = socket.send(|bytes| match upstream.read(bytes) {
                Ok(n) => (n, Ok(n == 0)),
                Err(e) if retry(&e) => (0, Ok(false)),
                Err(e) => (0, Err(e)),
            });
            if let Ok(result) = result {
                if result? {
                    self.up_eof = true;
                    socket.close();
                }
            }
        }
        if !self.write_shutdown
            && socket.recv_queue() == 0
            && matches!(
                socket.state(),
                State::CloseWait | State::LastAck | State::Closing | State::TimeWait
            )
        {
            upstream.shutdown(Shutdown::Write)?;
            self.write_shutdown = true;
        }
        if self.up_eof
            && self.write_shutdown
            && matches!(socket.state(), State::TimeWait | State::Closed)
        {
            self.graceful = true;
            self.upstream.take();
        }
        Ok(())
    }
}
fn retry(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
    )
}
fn pending_connect(error: &io::Error) -> bool {
    if error.kind() == io::ErrorKind::WouldBlock {
        return true;
    }
    #[cfg(unix)]
    if error.raw_os_error() == Some(libc::EINPROGRESS) {
        return true;
    }
    false
}
/// Queue a RST for a discarded flow. At most `limit` are held; overflow is dropped and that
/// client falls back to its own timeout.
fn queue_reset(resets: &mut VecDeque<Vec<u8>>, limit: usize, packet: Option<Vec<u8>>) {
    if let Some(packet) = packet {
        if resets.len() < limit {
            resets.push_back(packet);
        }
    }
}
pub struct TcpRelay<P> {
    config: Config,
    engine: Engine,
    flows: HashMap<FlowId, Flow>,
    round_robin: VecDeque<FlowId>,
    /// RSTs synthesized for flows discarded without a normal close; drained by `next_packet`.
    resets: VecDeque<Vec<u8>>,
    /// Last accepted clock value, for teardown paths that take no `now`.
    clock: u64,
    protector: P,
}
impl<P: TcpSocketProtector> TcpRelay<P> {
    pub fn new(policy: Policy, config: Config, protector: P) -> Result<Self, Error> {
        if config.max_flows > MAX_FLOWS
            || !(1280..=1500).contains(&config.mtu)
            || !(1024..=65536).contains(&config.buffer_bytes)
            || !(1..=16).contains(&config.output_slots)
            || config.buffer_budget > MAX_BUFFER_BUDGET
            || !(1..=86_400_000).contains(&config.idle_timeout_ms)
            || !(1..=30_000).contains(&config.connect_timeout_ms)
            || config.connect_timeout_ms > config.idle_timeout_ms
        {
            return Err(Error::Config);
        }
        let required = config
            .max_flows
            .checked_mul(config.buffer_bytes * 2 + (config.output_slots + 1) * config.mtu)
            .ok_or(Error::Config)?;
        if required > config.buffer_budget {
            return Err(Error::Config);
        }
        let engine = Engine::new(
            policy,
            EngineConfig {
                max_flows: config.max_flows,
                timeout: config.idle_timeout_ms,
                checksums: ChecksumPolicy::Require,
            },
        )
        .map_err(|_| Error::Config)?;
        Ok(Self {
            config,
            engine,
            flows: HashMap::new(),
            round_robin: VecDeque::new(),
            resets: VecDeque::new(),
            clock: 0,
            protector,
        })
    }
    fn reset_limit(&self) -> usize {
        self.config.max_flows * 2
    }
    fn maintain(&mut self, now: u64) -> Result<(), Error> {
        if now > MAX_TIME_MS {
            return Err(Error::Clock);
        }
        let flows = &mut self.flows;
        let resets = &mut self.resets;
        let limit = self.config.max_flows * 2;
        self.engine
            .expire_with(now, |id| {
                if let Some(mut flow) = flows.remove(&id) {
                    queue_reset(resets, limit, flow.reset_packet(now));
                }
            })
            .map_err(|_| Error::Clock)?;
        self.clock = now;
        self.round_robin.retain(|id| self.flows.contains_key(id));
        Ok(())
    }
    /// Drop a flow; an active client connection receives a RST instead of silence.
    fn forget(&mut self, id: &FlowId) {
        if let Some(mut flow) = self.flows.remove(id) {
            let packet = flow.reset_packet(self.clock);
            queue_reset(&mut self.resets, self.config.max_flows * 2, packet);
        }
        self.engine.forget_flow(id);
        self.round_robin.retain(|v| v != id);
    }
    /// Open the protected upstream stream; returns it and whether the connect is still pending.
    fn connect_upstream(&self, id: FlowId) -> Result<(TcpStream, bool), Error> {
        let socket = Socket::new(
            if id.source.is_ipv4() {
                Domain::IPV4
            } else {
                Domain::IPV6
            },
            Type::STREAM,
            Some(OsProtocol::TCP),
        )?;
        socket.set_nonblocking(true)?;
        socket.set_tcp_nodelay(true)?;
        socket.set_recv_buffer_size(self.config.buffer_bytes)?;
        socket.set_send_buffer_size(self.config.buffer_bytes)?;
        self.protector.protect(&socket)?;
        let connecting =
            match socket.connect(&SocketAddr::new(id.destination, id.destination_port).into()) {
                Ok(()) => false,
                Err(error) if pending_connect(&error) => true,
                Err(error) => return Err(Error::Io(error)),
            };
        Ok((socket.into(), connecting))
    }
    /// Feed the initial SYN to a new stack flow and connect upstream. If the upstream cannot be
    /// opened, the client's SYN is answered with a RST instead of being left to time out.
    fn open_flow(&mut self, id: FlowId, bytes: &[u8], now: u64) -> Result<Flow, Error> {
        let mut flow = Flow::new(id, self.config, now)?;
        flow.device.rx = Some(bytes.to_vec());
        flow.stack_poll(now);
        if flow.sockets.get::<StackSocket>(flow.handle).state() != State::SynReceived {
            return Err(Error::Stack);
        }
        match self.connect_upstream(id) {
            Ok((stream, connecting)) => {
                flow.upstream = Some(stream);
                flow.connecting = connecting;
                Ok(flow)
            }
            Err(error) => {
                let limit = self.reset_limit();
                queue_reset(&mut self.resets, limit, flow.reset_packet(now));
                Err(error)
            }
        }
    }
    /// Feed a complete checksummed IP/TCP datagram. A new flow must start with a payload-free SYN.
    pub fn ingest(&mut self, bytes: &[u8], now: u64) -> Result<FlowId, Error> {
        self.maintain(now)?;
        if bytes.len() > self.config.mtu {
            return Err(Error::Unsupported);
        }
        let packet = parse_checked(bytes, ChecksumPolicy::Require)
            .map_err(Error::Packet)?
            .packet;
        if packet.protocol != Protocol::Tcp {
            return Err(Error::Unsupported);
        }
        if super::unsupported_endpoint(&packet) {
            return Err(Error::Endpoint);
        }
        let id = FlowId::from(&packet);
        let offset = if packet.source.is_ipv4() { 20 } else { 40 };
        if bytes[offset + 12] & 0x0f != 0 {
            return Err(Error::Unsupported);
        }
        let tcp = TcpPacket::new_checked(&bytes[offset..]).map_err(|_| Error::Stack)?;
        let repr = TcpRepr::parse(
            &tcp,
            &IpAddress::from(packet.source),
            &IpAddress::from(packet.destination),
            &ChecksumCapabilities::default(),
        )
        .map_err(|_| Error::Stack)?;
        if !self.flows.contains_key(&id) && (bytes[offset + 13] != 2 || !repr.payload.is_empty()) {
            return Err(Error::InitialSynRequired);
        }
        if self.flows.get(&id).is_some_and(|f| f.failed) {
            return Err(Error::Terminated);
        }
        if self.flows.get(&id).is_some_and(|f| f.device.rx.is_some()) {
            return Err(Error::Backpressure);
        }
        match self.engine.process(bytes, now) {
            Outcome::Dropped(reason) => return Err(Error::Dropped(reason)),
            Outcome::Accepted { .. } => {}
        }
        if !self.flows.contains_key(&id) {
            match self.open_flow(id, bytes, now) {
                Ok(flow) => {
                    self.flows.insert(id, flow);
                    self.round_robin.push_back(id);
                    return Ok(id);
                }
                Err(error) => {
                    self.forget(&id);
                    return Err(error);
                }
            }
        }
        let flow = self.flows.get_mut(&id).ok_or(Error::Capacity)?;
        flow.device.rx = Some(bytes.to_vec());
        flow.stack_poll(now);
        let state = flow.sockets.get::<StackSocket>(flow.handle).state();
        if matches!(state, State::Listen | State::Closed) {
            flow.graceful = !tcp.rst() && flow.up_eof && flow.write_shutdown;
            self.forget(&id);
        }
        Ok(id)
    }
    /// One bounded pump pass: at most one upstream read/write per flow; no background thread.
    pub fn poll(&mut self, now: u64) -> Result<PollReport, Error> {
        self.maintain(now)?;
        let mut report = PollReport::default();
        let mut closed = Vec::new();
        for (id, flow) in &mut self.flows {
            if !flow.failed {
                if flow.connecting && now - flow.created >= self.config.connect_timeout_ms {
                    flow.abort(now);
                    report.connect_timeouts += 1;
                } else if flow.pump().is_err() {
                    flow.abort(now);
                    report.io_failures += 1;
                }
            }
            flow.stack_poll(now);
            if flow.sockets.get::<StackSocket>(flow.handle).state() == State::Closed
                && flow.device.tx.is_empty()
            {
                closed.push(*id);
            }
        }
        for id in closed {
            self.forget(&id);
            report.closed += 1;
        }
        Ok(report)
    }
    /// Drain round-robin output; every packet must pass current inbound policy and reverse-flow association.
    pub fn next_packet(&mut self, now: u64) -> Result<Option<Vec<u8>>, Error> {
        self.maintain(now)?;
        if let Some(reset) = self.resets.pop_front() {
            return Ok(Some(reset));
        }
        for _ in 0..self.round_robin.len() {
            let Some(id) = self.round_robin.pop_front() else {
                break;
            };
            self.round_robin.push_back(id);
            let Some(flow) = self.flows.get_mut(&id) else {
                continue;
            };
            let Some(bytes) = flow.device.tx.pop_front() else {
                continue;
            };
            match self.engine.authorize_response(&bytes, &id, now) {
                Outcome::Accepted { .. } => return Ok(Some(bytes)),
                Outcome::Dropped(reason) => {
                    self.forget(&id);
                    return Err(Error::Dropped(reason));
                }
            }
        }
        Ok(None)
    }
    pub fn update_policy(&mut self, rules: Vec<Rule>, default: Action) -> Result<(), PolicyError> {
        self.engine.update_policy(rules, default)?;
        self.reset_network();
        Ok(())
    }
    pub fn reset_network(&mut self) {
        let limit = self.reset_limit();
        for (_, mut flow) in self.flows.drain() {
            queue_reset(&mut self.resets, limit, flow.reset_packet(self.clock));
        }
        self.round_robin.clear();
        self.engine.reset_network();
    }
    pub fn flow_count(&self) -> usize {
        self.flows.len()
    }
    pub fn buffers(&self) -> Buffers {
        let mut used = Buffers::default();
        for flow in self.flows.values() {
            let socket = flow.sockets.get::<StackSocket>(flow.handle);
            used.stream_bytes += socket.send_queue() + socket.recv_queue();
            used.queued_packets += flow.device.tx.len() + usize::from(flow.device.rx.is_some());
            used.queued_packet_bytes += flow.device.tx.iter().map(Vec::len).sum::<usize>()
                + flow.device.rx.as_ref().map_or(0, Vec::len);
        }
        used.reserved_payload_bytes = self.flows.len()
            * (self.config.buffer_bytes * 2 + (self.config.output_slots + 1) * self.config.mtu);
        used
    }
}

#[cfg(test)]
mod tests;

/// Deterministic in-memory stack harness; no OS sockets, only enabled in fuzz builds.
#[cfg(feature = "fuzzing")]
pub fn exercise_stack(input: &[u8]) {
    fuzz_support::exercise(input);
}
#[cfg(feature = "fuzzing")]
mod fuzz_support;
