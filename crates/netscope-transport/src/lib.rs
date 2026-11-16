//! Bounded nonblocking UDP relay. No TCP stack or Android socket protection implementation.
use netscope_conntrack::FlowId;
use netscope_engine::{Config, DropReason, Engine, Outcome, Stats};
use netscope_packet::{parse, udp, Protocol};
use netscope_policy::{Action, Policy, PolicyError, Rule};
use std::{
    collections::HashMap,
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket},
};

pub const MAX_UDP_FLOWS: usize = 1024;
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
}
impl From<io::Error> for RelayError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Sent {
    pub flow: FlowId,
    pub payload_bytes: usize,
}
pub struct UdpRelay<P> {
    engine: Engine,
    sockets: HashMap<FlowId, UdpSocket>,
    protector: P,
    mtu: usize,
    receive_buffer: Box<[u8]>,
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
        })
    }
    /// Call periodically when idle as well as on send/receive to release expired sockets.
    pub fn expire(&mut self, now: u64) -> Result<usize, RelayError> {
        let sockets = &mut self.sockets;
        self.engine
            .expire_with(now, |id| {
                sockets.remove(&id);
            })
            .map_err(|_| RelayError::Dropped(DropReason::ClockReversed))
    }
    fn forget(&mut self, id: &FlowId) {
        self.sockets.remove(id);
        self.engine.forget_flow(id);
    }
    /// Validate/admit a full IP/UDP datagram, then send its payload using one protected socket per flow.
    /// WouldBlock/error is returned; there is no hidden retry queue or background task.
    pub fn send(&mut self, bytes: &[u8], now: u64) -> Result<Sent, RelayError> {
        self.expire(now)?;
        if bytes.len() > self.mtu {
            return Err(RelayError::MtuExceeded);
        }
        let metadata = parse(bytes).map_err(|e| RelayError::Dropped(DropReason::Packet(e)))?;
        if metadata.protocol != Protocol::Udp {
            return Err(RelayError::UnsupportedProtocol);
        }
        let unsupported = match metadata.destination {
            IpAddr::V4(ip) => ip.is_unspecified() || ip.is_broadcast() || ip.is_multicast(),
            IpAddr::V6(ip) => {
                ip.is_unspecified()
                    || ip.is_multicast()
                    || ip.is_unicast_link_local()
                    || ip.to_ipv4_mapped().is_some()
            }
        } || matches!(metadata.source,IpAddr::V6(ip) if ip.to_ipv4_mapped().is_some())
            || metadata.source_port == 0
            || metadata.destination_port == 0;
        if unsupported {
            return Err(RelayError::UnsupportedAddress);
        }
        let packet = match self.engine.process(bytes, now) {
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
                    self.sockets.insert(id, socket);
                }
                Err(error) => {
                    self.forget(&id);
                    return Err(RelayError::Io(error));
                }
            }
        }
        let offset = if packet.source.is_ipv4() { 28 } else { 48 };
        let result = self.sockets[&id].send(&bytes[offset..]);
        match result {
            Ok(count) if count == bytes.len() - offset => Ok(Sent {
                flow: id,
                payload_bytes: count,
            }),
            Ok(_) => {
                self.forget(&id);
                Err(RelayError::Io(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "partial UDP send",
                )))
            }
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
        let socket = self.sockets.get(&id).ok_or(RelayError::UnknownFlow)?;
        let count = match socket.recv(&mut self.receive_buffer) {
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
            self.forget(&id);
            return Err(RelayError::MtuExceeded);
        }
        let response = udp::encode(
            SocketAddr::new(id.destination, id.destination_port),
            SocketAddr::new(id.source, id.source_port),
            &self.receive_buffer[..count],
        )
        .map_err(RelayError::Encode)?;
        match self.engine.authorize_response(&response, &id, now) {
            Outcome::Accepted { .. } => Ok(response),
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
    /// Caller must invoke on upstream-network change. No OS network observer is implemented here.
    pub fn reset_network(&mut self) {
        self.sockets.clear();
        self.engine.reset_network();
    }
    pub fn flow_count(&self) -> usize {
        self.sockets.len()
    }
    pub fn stats(&self) -> Stats {
        self.engine.stats()
    }
}
