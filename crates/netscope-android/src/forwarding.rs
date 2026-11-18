//! Opt-in Android forwarding preview. Java owns the TUN and drives bounded polling.
use crate::vpn_protector::AndroidVpnProtector;
use jni::{
    objects::{GlobalRef, JByteArray, JClass, JObject, JValue},
    sys::{jint, jlong},
    JNIEnv,
};
use netscope_conntrack::{FlowId, Observation};
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
/// Active-flow snapshot handed to Java as one fixed-size, bounded byte block.
pub const SNAPSHOT_RECORD_BYTES: usize = 96;
pub const SNAPSHOT_MAX_FLOWS: usize = 64;

/// Inverse of [`observation`]: rebuilds the flow id from the 38-byte metadata block.
fn flow_from_observation(bytes: &[u8]) -> Option<FlowId> {
    if bytes.len() != OBSERVATION_BYTES {
        return None;
    }
    let protocol = match bytes[0] {
        6 => Protocol::Tcp,
        17 => Protocol::Udp,
        _ => return None,
    };
    let (source, destination): (std::net::IpAddr, std::net::IpAddr) = match bytes[1] {
        4 => (
            std::net::Ipv4Addr::from(<[u8; 4]>::try_from(&bytes[6..10]).ok()?).into(),
            std::net::Ipv4Addr::from(<[u8; 4]>::try_from(&bytes[22..26]).ok()?).into(),
        ),
        16 => (
            std::net::Ipv6Addr::from(<[u8; 16]>::try_from(&bytes[6..22]).ok()?).into(),
            std::net::Ipv6Addr::from(<[u8; 16]>::try_from(&bytes[22..38]).ok()?).into(),
        ),
        _ => return None,
    };
    Some(FlowId {
        source,
        destination,
        source_port: u16::from_be_bytes([bytes[2], bytes[3]]),
        destination_port: u16::from_be_bytes([bytes[4], bytes[5]]),
        protocol,
    })
}

/// Big-endian record: 0 protocol (6/17), 1 address family (4/16), 2..4 source port,
/// 4..6 destination port, 6..22 source address, 22..38 destination address (IPv4 uses the first
/// four bytes), 38..42 uid as i32 (-1 unknown), 42..44 zero, 44..52 outbound packets,
/// 52..60 outbound bytes, 60..68 inbound packets, 68..76 inbound bytes, 76..84 created_at ms,
/// 84..92 last_seen ms, 92..96 zero. Informational only; never an authorization input.
fn encode_flow(id: &FlowId, flow: &Observation) -> [u8; SNAPSHOT_RECORD_BYTES] {
    let mut out = [0u8; SNAPSHOT_RECORD_BYTES];
    out[0] = match id.protocol {
        Protocol::Tcp => 6,
        Protocol::Udp => 17,
    };
    out[2..4].copy_from_slice(&id.source_port.to_be_bytes());
    out[4..6].copy_from_slice(&id.destination_port.to_be_bytes());
    match (id.source, id.destination) {
        (std::net::IpAddr::V4(s), std::net::IpAddr::V4(d)) => {
            out[1] = 4;
            out[6..10].copy_from_slice(&s.octets());
            out[22..26].copy_from_slice(&d.octets());
        }
        (std::net::IpAddr::V6(s), std::net::IpAddr::V6(d)) => {
            out[1] = 16;
            out[6..22].copy_from_slice(&s.octets());
            out[22..38].copy_from_slice(&d.octets());
        }
        // Checked packets have one address family; a mixed id is never recorded.
        _ => return [0u8; SNAPSHOT_RECORD_BYTES],
    }
    let uid = flow
        .uid
        .and_then(|uid| i32::try_from(uid).ok())
        .unwrap_or(-1);
    out[38..42].copy_from_slice(&uid.to_be_bytes());
    out[44..52].copy_from_slice(&flow.outbound.packets.to_be_bytes());
    out[52..60].copy_from_slice(&flow.outbound.bytes.to_be_bytes());
    out[60..68].copy_from_slice(&flow.inbound.packets.to_be_bytes());
    out[68..76].copy_from_slice(&flow.inbound.bytes.to_be_bytes());
    out[76..84].copy_from_slice(&flow.created_at.to_be_bytes());
    out[84..92].copy_from_slice(&flow.last_seen.to_be_bytes());
    out
}

/// Newest-first merge of two already newest-first lists, at most `limit` records.
fn merge_newest(
    mut first: Vec<(FlowId, Observation)>,
    mut second: Vec<(FlowId, Observation)>,
    limit: usize,
) -> Vec<(FlowId, Observation)> {
    first.append(&mut second);
    first.sort_by(|a, b| {
        b.1.last_seen
            .cmp(&a.1.last_seen)
            .then_with(|| a.0.cmp(&b.0))
    });
    first.truncate(limit);
    first
}

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
    app_policy: Option<GlobalRef>,
}
impl Session {
    fn now(&self) -> u64 {
        self.start
            .elapsed()
            .as_millis()
            .min(u128::from(tcp::MAX_TIME_MS)) as u64
    }
    fn forward_allowed(&mut self, packet: &[u8], metadata: &Packet) {
        let now = self.now();
        match metadata.protocol {
            Protocol::Tcp => {
                let _ = self.tcp.ingest(packet, now);
            }
            Protocol::Udp => {
                let _ = self.udp.send(packet, now);
            }
        }
    }
    fn note_owner(&mut self, id: &FlowId, uid: Option<u32>) -> bool {
        match id.protocol {
            Protocol::Tcp => self.tcp.note_owner(id, uid),
            Protocol::Udp => self.udp.note_owner(id, uid),
        }
    }
    fn snapshot(&self) -> Vec<(FlowId, Observation)> {
        merge_newest(
            self.tcp.flow_snapshot(SNAPSHOT_MAX_FLOWS),
            self.udp.flow_snapshot(SNAPSHOT_MAX_FLOWS),
            SNAPSHOT_MAX_FLOWS,
        )
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
    app_policy: JObject<'_>,
) -> jlong {
    catch_unwind(AssertUnwindSafe(|| {
        let mut registry = SESSION.lock().ok()?;
        if service.is_null() || registry.1.is_some() {
            return None;
        }
        let token = registry.0;
        let next = token.checked_add(1)?;
        let protector = Arc::new(AndroidVpnProtector::new(&mut env, &service).ok()?);
        let app_policy = if app_policy.is_null() {
            None
        } else {
            Some(env.new_global_ref(&app_policy).ok()?)
        };
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
                app_policy,
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
    mut env: JNIEnv<'_>,
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
        if session.outbound.decide(&metadata).action != Action::Allow {
            return Some(2);
        }
        if let Some(policy) = &session.app_policy {
            let observation_object = observed.as_ref();
            let allowed = env.call_method(
                policy.as_obj(),
                "allows",
                "([B)Z",
                &[JValue::Object(observation_object)],
            );
            match allowed.and_then(|value| value.z()) {
                Ok(true) => {}
                Ok(false) => return Some(3),
                Err(_) => {
                    if env.exception_check().unwrap_or(false) {
                        let _ = env.exception_clear();
                    }
                    return Some(3);
                }
            }
        }
        session.forward_allowed(packet, &metadata);
        // This is an admission decision, not upstream delivery.
        Some(1)
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

/// Tells the session which uid owns the flow described by a 38-byte observation block. Returns 1
/// when an existing flow was updated, 0 when the block is malformed, the uid is negative or the
/// flow is not tracked, -1 for a stale token or wrong array size. Informational only.
// SAFETY REVIEW: same pattern as the other exports: unique ABI symbol, no raw pointers, no unsafe
// blocks; jni validates the array and the copy is bounded by the checked length.
#[allow(unsafe_code)]
#[no_mangle]
pub extern "system" fn Java_org_netscope_ngfw_NativeCore_noteOwner(
    env: JNIEnv<'_>,
    _: JClass<'_>,
    token: jlong,
    observed: JByteArray<'_>,
    uid: jint,
) -> jint {
    with_session(token, |session| {
        if observed.is_null() || env.get_array_length(&observed).ok()? != OBSERVATION_BYTES as jint
        {
            return None;
        }
        let bytes = env.convert_byte_array(&observed).ok()?;
        let (Some(id), Ok(uid)) = (flow_from_observation(&bytes), u32::try_from(uid)) else {
            return Some(0);
        };
        Some(jint::from(session.note_owner(&id, Some(uid))))
    })
}

/// Writes up to `SNAPSHOT_MAX_FLOWS` fixed-size records (newest first) into `destination`, which
/// must be exactly `SNAPSHOT_MAX_FLOWS * SNAPSHOT_RECORD_BYTES` long. Returns the record count,
/// or -1 for a stale token, a wrong-size array or a bridge failure. Read-only.
// SAFETY REVIEW: same pattern as the other exports: unique ABI symbol, no raw pointers, no unsafe
// blocks; jni validates the array and the copy is bounded by the checked length.
#[allow(unsafe_code)]
#[no_mangle]
pub extern "system" fn Java_org_netscope_ngfw_NativeCore_snapshotForwarding(
    env: JNIEnv<'_>,
    _: JClass<'_>,
    token: jlong,
    destination: JByteArray<'_>,
) -> jint {
    with_session(token, |session| {
        let expected = SNAPSHOT_MAX_FLOWS * SNAPSHOT_RECORD_BYTES;
        if destination.is_null() || env.get_array_length(&destination).ok()? != expected as jint {
            return None;
        }
        let flows = session.snapshot();
        let mut block = vec![0i8; flows.len() * SNAPSHOT_RECORD_BYTES];
        for ((id, flow), slot) in flows
            .iter()
            .zip(block.chunks_exact_mut(SNAPSHOT_RECORD_BYTES))
        {
            for (dst, byte) in slot.iter_mut().zip(encode_flow(id, flow)) {
                *dst = byte as i8;
            }
        }
        env.set_byte_array_region(&destination, 0, &block).ok()?;
        Some(flows.len() as jint)
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

    fn flow(port: u16, v6: bool) -> FlowId {
        let (source, destination): (std::net::IpAddr, std::net::IpAddr) = if v6 {
            (
                "2001:db8::1".parse().unwrap(),
                "2001:db8::2".parse().unwrap(),
            )
        } else {
            (
                "10.0.0.2".parse().unwrap(),
                "93.184.216.34".parse().unwrap(),
            )
        };
        FlowId {
            source,
            destination,
            source_port: port,
            destination_port: 443,
            protocol: Protocol::Tcp,
        }
    }
    #[test]
    fn snapshot_record_layout_is_fixed_big_endian_for_both_families() {
        let mut obs = Observation {
            created_at: 5,
            last_seen: 9,
            uid: Some(10_042),
            ..Observation::default()
        };
        obs.outbound.packets = 2;
        obs.outbound.bytes = 300;
        obs.inbound.packets = 1;
        obs.inbound.bytes = 1_500;
        let r = encode_flow(&flow(40_000, false), &obs);
        assert_eq!((r[0], r[1]), (6, 4));
        assert_eq!(u16::from_be_bytes([r[2], r[3]]), 40_000);
        assert_eq!(u16::from_be_bytes([r[4], r[5]]), 443);
        assert_eq!(&r[6..10], &[10, 0, 0, 2]);
        assert_eq!(&r[10..22], &[0u8; 12], "unused IPv4 tail stays zero");
        assert_eq!(&r[22..26], &[93, 184, 216, 34]);
        assert_eq!(i32::from_be_bytes(r[38..42].try_into().unwrap()), 10_042);
        assert_eq!(u64::from_be_bytes(r[44..52].try_into().unwrap()), 2);
        assert_eq!(u64::from_be_bytes(r[52..60].try_into().unwrap()), 300);
        assert_eq!(u64::from_be_bytes(r[60..68].try_into().unwrap()), 1);
        assert_eq!(u64::from_be_bytes(r[68..76].try_into().unwrap()), 1_500);
        assert_eq!(u64::from_be_bytes(r[76..84].try_into().unwrap()), 5);
        assert_eq!(u64::from_be_bytes(r[84..92].try_into().unwrap()), 9);
        assert_eq!(&r[92..], &[0u8; 4]);
        let v6 = encode_flow(&flow(1, true), &Observation::default());
        assert_eq!(v6[1], 16);
        assert_eq!(
            &v6[6..22],
            &"2001:db8::1"
                .parse::<std::net::Ipv6Addr>()
                .unwrap()
                .octets()
        );
        assert_eq!(i32::from_be_bytes(v6[38..42].try_into().unwrap()), -1);
        let big = Observation {
            uid: Some(u32::MAX),
            ..Observation::default()
        };
        let big = encode_flow(&flow(1, false), &big);
        assert_eq!(i32::from_be_bytes(big[38..42].try_into().unwrap()), -1);
        let mixed = FlowId {
            destination: "2001:db8::2".parse().unwrap(),
            ..flow(1, false)
        };
        assert_eq!(encode_flow(&mixed, &obs), [0u8; SNAPSHOT_RECORD_BYTES]);
    }
    #[test]
    fn observation_block_round_trips_to_the_flow_id() {
        for v6 in [false, true] {
            let id = flow(4242, v6);
            let packet = Packet {
                source: id.source,
                destination: id.destination,
                source_port: id.source_port,
                destination_port: id.destination_port,
                protocol: id.protocol,
                length: 40,
            };
            let bytes: Vec<u8> = observation(&packet).iter().map(|b| *b as u8).collect();
            assert_eq!(flow_from_observation(&bytes), Some(id));
        }
        assert_eq!(flow_from_observation(&[0u8; 37]), None);
        let mut bad = vec![0u8; OBSERVATION_BYTES];
        assert_eq!(flow_from_observation(&bad), None, "unknown protocol");
        bad[0] = 6;
        assert_eq!(flow_from_observation(&bad), None, "unknown family");
    }
    #[test]
    fn merge_is_newest_first_bounded_and_deterministic() {
        let at = |seen| Observation {
            last_seen: seen,
            ..Observation::default()
        };
        let merged = merge_newest(
            vec![(flow(1, false), at(9)), (flow(2, false), at(3))],
            vec![(flow(3, false), at(9)), (flow(4, false), at(5))],
            3,
        );
        let ports: Vec<u16> = merged.iter().map(|(id, _)| id.source_port).collect();
        assert_eq!(ports, [1, 3, 4]);
        assert!(merge_newest(vec![], vec![], 3).is_empty());
        assert!(merge_newest(vec![(flow(1, false), at(1))], vec![], 0).is_empty());
    }
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
