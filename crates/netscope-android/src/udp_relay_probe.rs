//! Host-JVM integration probe: actual bounded Rust UDP relay -> JNI -> Java queue.
//! Only localhost is reachable and only a synthetic test datagram is generated.
//! Never invoked by DiagnosticVpnService; this is NOT Android VPN forwarding.
use crate::vpn_protector::AndroidVpnProtector;
use jni::{
    objects::{JClass, JObject, JValue},
    sys::jint,
    JNIEnv,
};
use netscope_engine::Config;
use netscope_packet::{udp, ChecksumPolicy, Protocol};
use netscope_policy::{Action, Cidr, Policy, Rule};
use netscope_transport::{RelayError, UdpRelay};
use std::{
    io,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    panic::{catch_unwind, AssertUnwindSafe},
    thread,
    time::Duration,
};

const FAILED: jint = -1;
const OK: jint = 0;
const CLIENT_PORT: u16 = 41_234;
const MAX_POLLS: u64 = 80;
const POLL_DELAY_MS: u64 = 10;

fn allow_rule(source: Ipv4Addr, destination: Ipv4Addr, from: u16, to: u16) -> Rule {
    Rule {
        priority: 0,
        action: Action::Allow,
        source: Some(Cidr::new(IpAddr::V4(source), 32).expect("valid IPv4 CIDR")),
        destination: Some(Cidr::new(IpAddr::V4(destination), 32).expect("valid IPv4 CIDR")),
        protocol: Some(Protocol::Udp),
        source_port: Some(from..=from),
        destination_port: Some(to..=to),
    }
}

/// Run one real localhost UDP roundtrip with explicit forward and reverse
/// rules; the reverse rule is omitted to prove a response cannot reach Java.
fn probe(
    env: &mut JNIEnv<'_>,
    service: JObject<'_>,
    queue: JObject<'_>,
    destination_port: jint,
    allow_inbound: bool,
) -> jint {
    if service.is_null() || queue.is_null() || !(1..=65535).contains(&destination_port) {
        return FAILED;
    }
    let Ok(destination_port) = u16::try_from(destination_port) else {
        return FAILED;
    };
    let client = Ipv4Addr::new(10, 111, 0, 2);
    let localhost = Ipv4Addr::LOCALHOST;
    let mut rules = vec![allow_rule(client, localhost, CLIENT_PORT, destination_port)];
    if allow_inbound {
        rules.push(allow_rule(localhost, client, destination_port, CLIENT_PORT));
    }
    let Ok(policy) = Policy::new(rules, Action::Deny) else {
        return FAILED;
    };
    let Ok(protector) = AndroidVpnProtector::new(env, &service) else {
        return FAILED;
    };
    let Ok(mut relay) = UdpRelay::new(
        policy,
        Config {
            max_flows: 2,
            timeout: 10_000,
            checksums: ChecksumPolicy::Require,
        },
        1280,
        protector,
    ) else {
        return FAILED;
    };
    let source = SocketAddr::new(IpAddr::V4(client), CLIENT_PORT);
    let destination = SocketAddr::new(IpAddr::V4(localhost), destination_port);
    let Ok(datagram) = udp::encode(source, destination, b"netscope-udp-loopback") else {
        return FAILED;
    };
    let Ok(sent) = relay.send(&datagram, 1) else {
        // An Android protector refusal must never lead to a fallback send.
        return FAILED;
    };

    for poll in 0..MAX_POLLS {
        let now = poll + 2;
        match relay.receive(sent.flow, now) {
            Ok(response) => {
                if response.len() > 1280 {
                    return FAILED;
                }
                let Ok(array) = env.byte_array_from_slice(&response) else {
                    return FAILED;
                };
                let array_object = JObject::from(array);
                let result = env.call_method(
                    &queue,
                    "offer",
                    "([BI)Z",
                    &[
                        JValue::Object(&array_object),
                        JValue::Int(response.len() as jint),
                    ],
                );
                match result {
                    Ok(value) if matches!(value.z(), Ok(true)) => return OK,
                    _ => {
                        if env.exception_check().unwrap_or(false) {
                            let _ = env.exception_clear();
                        }
                        return FAILED;
                    }
                }
            }
            Err(RelayError::Io(error)) if error.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(POLL_DELAY_MS));
            }
            Err(_) => return FAILED,
        }
    }
    FAILED
}

// SAFETY REVIEW: JNI symbol export only, no manual pointer dereference or
// native FD ownership transfer. The test has a strict bounded timeout.
// No app TUN FD or production VPN path is touched.
#[allow(unsafe_code)]
#[no_mangle]
pub extern "system" fn Java_org_netscope_ngfw_NativeCore_probeUdpRelayLoopback(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    service: JObject<'_>,
    queue: JObject<'_>,
    destination_port: jint,
    allow_inbound: jni::sys::jboolean,
) -> jint {
    catch_unwind(AssertUnwindSafe(|| {
        probe(
            &mut env,
            service,
            queue,
            destination_port,
            allow_inbound != 0,
        )
    }))
    .unwrap_or(FAILED)
}
