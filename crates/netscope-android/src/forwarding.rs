//! Opt-in Android forwarding preview. Java owns the TUN and drives bounded polling.
use crate::vpn_protector::AndroidVpnProtector;
use jni::{
    objects::{JByteArray, JClass, JObject},
    sys::{jint, jlong},
    JNIEnv,
};
use netscope_packet::{parse_checked, ChecksumPolicy, Packet, Protocol};
use netscope_policy::{Action, Policy, Rule};
use netscope_transport::{tcp, SocketProtector, UdpRelay};
use std::{
    io,
    net::UdpSocket,
    panic::{catch_unwind, AssertUnwindSafe},
    sync::{Arc, Mutex},
    time::Instant,
};

const MTU: usize = 1500;
const OBSERVATION_BYTES: usize = 38;

// Only checked header metadata crosses to Android's socket owner lookup.
fn observation(packet: &Packet) -> [i8; OBSERVATION_BYTES] {
    let mut bytes = [0u8; OBSERVATION_BYTES];
    bytes[0] = match packet.protocol {
        Protocol::Tcp => 6,
        Protocol::Udp => 17,
    };
    bytes[2..4].copy_from_slice(&packet.source_port.to_be_bytes());
    bytes[4..6].copy_from_slice(&packet.destination_port.to_be_bytes());
    match (packet.source, packet.destination) {
        (std::net::IpAddr::V4(source), std::net::IpAddr::V4(destination)) => {
            bytes[1] = 4;
            bytes[6..10].copy_from_slice(&source.octets());
            bytes[22..26].copy_from_slice(&destination.octets());
        }
        (std::net::IpAddr::V6(source), std::net::IpAddr::V6(destination)) => {
            bytes[1] = 16;
            bytes[6..22].copy_from_slice(&source.octets());
            bytes[22..38].copy_from_slice(&destination.octets());
        }
        _ => unreachable!("checked packets have one address family"),
    }
    bytes.map(|byte| byte as i8)
}

struct Protector(Arc<AndroidVpnProtector>);
impl SocketProtector for Protector {
    fn protect(&self, socket: &UdpSocket) -> io::Result<()> {
        SocketProtector::protect(self.0.as_ref(), socket)
    }
}
impl tcp::TcpSocketProtector for Protector {
    fn protect(&self, socket: &socket2::Socket) -> io::Result<()> {
        tcp::TcpSocketProtector::protect(self.0.as_ref(), socket)
    }
}

fn profile(include_replies: bool) -> Policy {
    let mut rules = Vec::new();
    for (protocol, port, endpoint) in [
        (Protocol::Tcp, 80, None),
        (Protocol::Tcp, 443, None),
        (Protocol::Tcp, 53, Some("1.1.1.1/32")),
        (Protocol::Udp, 53, Some("1.1.1.1/32")),
    ] {
        let endpoint = endpoint.map(|text| text.parse().expect("static CIDR"));
        for reverse in [false, true]
            .into_iter()
            .filter(|reverse| !reverse || include_replies)
        {
            rules.push(Rule {
                priority: 0,
                action: Action::Allow,
                protocol: Some(protocol),
                source: if reverse { endpoint } else { None },
                destination: if reverse { None } else { endpoint },
                source_port: reverse.then_some(port..=port),
                destination_port: (!reverse).then_some(port..=port),
            });
        }
    }
    Policy::new(rules, Action::Deny).expect("static preview policy")
}

struct Session {
    token: jlong,
    start: Instant,
    protector: Arc<AndroidVpnProtector>,
    tcp: tcp::TcpRelay<Protector>,
    udp: UdpRelay<Protector>,
    prefer_tcp: bool,
    outbound: Policy,
}
impl Session {
    fn now(&self) -> u64 {
        self.start
            .elapsed()
            .as_millis()
            .min(u128::from(tcp::MAX_TIME_MS)) as u64
    }
    fn ingress(&mut self, packet: &[u8], metadata: &Packet) -> bool {
        if self.outbound.decide(metadata).action != Action::Allow {
            return false;
        }
        let now = self.now();
        match metadata.protocol {
            Protocol::Tcp => {
                let _ = self.tcp.ingest(packet, now);
            }
            Protocol::Udp => {
                let _ = self.udp.send(packet, now);
            }
        }
        true
    }
    fn next(&mut self) -> Result<Option<Vec<u8>>, ()> {
        let now = self.now();
        self.tcp.poll_with_budget(now, 8).map_err(|_| ())?;
        self.prefer_tcp = !self.prefer_tcp;
        for tcp_first in [self.prefer_tcp, !self.prefer_tcp] {
            let packet = if tcp_first {
                match self.tcp.next_packet(now) {
                    Ok(packet) => packet,
                    Err(tcp::Error::Dropped(_)) => None,
                    Err(_) => return Err(()),
                }
            } else {
                self.udp
                    .receive_next(now, 8)
                    .map_err(|_| ())?
                    .and_then(|reply| reply.result.ok())
            };
            if packet.is_some() {
                return Ok(packet);
            }
        }
        Ok(None)
    }
}
impl Drop for Session {
    fn drop(&mut self) {
        self.protector.revoke();
    }
}

static SESSION: Mutex<(jlong, Option<Session>)> = Mutex::new((1, None));

fn with_session(token: jlong, operation: impl FnOnce(&mut Session) -> Option<jint>) -> jint {
    catch_unwind(AssertUnwindSafe(|| {
        let mut registry = SESSION.lock().ok()?;
        let session = registry
            .1
            .as_mut()
            .filter(|session| session.token == token)?;
        operation(session)
    }))
    .ok()
    .flatten()
    .unwrap_or(-1)
}

// JNI exports only. jni validates Java references and manages array copies.
#[allow(unsafe_code)]
#[no_mangle]
pub extern "system" fn Java_org_netscope_ngfw_NativeCore_startForwarding(
    mut env: JNIEnv<'_>,
    _: JClass<'_>,
    service: JObject<'_>,
) -> jlong {
    catch_unwind(AssertUnwindSafe(|| {
        let mut registry = SESSION.lock().ok()?;
        if service.is_null() || registry.1.is_some() {
            return None;
        }
        let token = registry.0;
        let next = token.checked_add(1)?;
        let protector = Arc::new(AndroidVpnProtector::new(&mut env, &service).ok()?);
        let udp = UdpRelay::new(
            profile(true),
            netscope_engine::Config {
                max_flows: 64,
                timeout: 30_000,
                checksums: ChecksumPolicy::Require,
            },
            MTU,
            Protector(protector.clone()),
        )
        .ok()?;
        let tcp = tcp::TcpRelay::new(
            profile(true),
            tcp::Config {
                max_flows: 32,
                mtu: MTU,
                buffer_bytes: 8192,
                output_slots: 4,
                buffer_budget: 1024 * 1024,
                idle_timeout_ms: 120_000,
                connect_timeout_ms: 10_000,
            },
            Protector(protector.clone()),
        )
        .ok()?;
        *registry = (
            next,
            Some(Session {
                token,
                start: Instant::now(),
                protector,
                tcp,
                udp,
                prefer_tcp: false,
                outbound: profile(false),
            }),
        );
        Some(token)
    }))
    .ok()
    .flatten()
    .unwrap_or(0)
}

#[allow(unsafe_code)]
#[no_mangle]
pub extern "system" fn Java_org_netscope_ngfw_NativeCore_forwardPacket(
    env: JNIEnv<'_>,
    _: JClass<'_>,
    token: jlong,
    bytes: JByteArray<'_>,
    count: jint,
    observed: JByteArray<'_>,
) -> jint {
    with_session(token, |session| {
        if bytes.is_null()
            || observed.is_null()
            || !(1..=MTU as jint).contains(&count)
            || env.get_array_length(&bytes).ok()? != MTU as jint
            || env.get_array_length(&observed).ok()? != OBSERVATION_BYTES as jint
        {
            return None;
        }
        let owned = env.convert_byte_array(&bytes).ok()?;
        let packet = &owned[..count as usize];
        let Ok(checked) = parse_checked(packet, ChecksumPolicy::Require) else {
            return Some(0);
        };
        let metadata = checked.packet;
        env.set_byte_array_region(&observed, 0, &observation(&metadata))
            .ok()?;
        // Report only the fixed profile's decision, never upstream delivery.
        Some(if session.ingress(packet, &metadata) {
            1
        } else {
            2
        })
    })
}

#[allow(unsafe_code)]
#[no_mangle]
pub extern "system" fn Java_org_netscope_ngfw_NativeCore_pollForwarding(
    env: JNIEnv<'_>,
    _: JClass<'_>,
    token: jlong,
    destination: JByteArray<'_>,
) -> jint {
    with_session(token, |session| {
        if destination.is_null() || env.get_array_length(&destination).ok()? != MTU as jint {
            return None;
        }
        let Some(packet) = session.next().ok()? else {
            return Some(0);
        };
        let mut output = [0i8; MTU];
        for (slot, byte) in output.iter_mut().zip(&packet) {
            *slot = *byte as i8;
        }
        env.set_byte_array_region(&destination, 0, output.get(..packet.len())?)
            .ok()?;
        Some(packet.len() as jint)
    })
}

#[allow(unsafe_code)]
#[no_mangle]
pub extern "system" fn Java_org_netscope_ngfw_NativeCore_stopForwarding(
    _: JNIEnv<'_>,
    _: JClass<'_>,
    token: jlong,
) -> jint {
    catch_unwind(AssertUnwindSafe(|| {
        let Ok(mut registry) = SESSION.lock() else {
            return -1;
        };
        if registry.1.as_ref().map(|session| session.token) != Some(token) {
            return -1;
        }
        registry.1 = None;
        0
    }))
    .unwrap_or(-1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use netscope_packet::Packet;

    #[test]
    fn preview_requires_an_outbound_rule_even_when_a_reply_rule_matches() {
        let mut packet = Packet {
            source: "10.111.0.1".parse().unwrap(),
            destination: "192.0.2.1".parse().unwrap(),
            source_port: 443,
            destination_port: 12345,
            protocol: Protocol::Tcp,
            length: 40,
        };
        assert_eq!(profile(true).decide(&packet).action, Action::Allow);
        let outbound = profile(false);
        assert_eq!(outbound.decide(&packet).action, Action::Deny);
        packet.destination_port = 443;
        assert_eq!(outbound.decide(&packet).action, Action::Allow);
        packet.protocol = Protocol::Udp;
        assert_eq!(outbound.decide(&packet).action, Action::Deny);
        packet.destination_port = 53;
        assert_eq!(outbound.decide(&packet).action, Action::Deny);
        packet.destination = "1.1.1.1".parse().unwrap();
        assert_eq!(outbound.decide(&packet).action, Action::Allow);
    }
}
