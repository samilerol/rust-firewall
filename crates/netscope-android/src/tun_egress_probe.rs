//! Test-only Rust -> JNI -> Java TUN queue data-path probe.
//! No raw network sockets, no Android VPN FD and no runtime forwarding.
use jni::{
    objects::{JClass, JObject, JValue},
    sys::{jboolean, jint},
    JNIEnv,
};
use netscope_packet::{parse_checked, udp, ChecksumPolicy};
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    panic::{catch_unwind, AssertUnwindSafe},
};

const FAILED: jint = -1;
const OK: jint = 0;

fn probe(env: &mut JNIEnv<'_>, queue: JObject<'_>, ipv6: bool) -> jint {
    if queue.is_null() {
        return FAILED;
    }

    // Synthetic documentation addresses. Packet construction does not touch
    // the network; the probe is never invoked by DiagnosticVpnService.
    let (source, destination) = if ipv6 {
        (
            SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 53),
            SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 53000),
        )
    } else {
        (
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 53),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 53000),
        )
    };
    let Ok(bytes) = udp::encode(source, destination, b"netscope-probe") else {
        return FAILED;
    };
    if bytes.len() > 1500 || parse_checked(&bytes, ChecksumPolicy::Require).is_err() {
        return FAILED;
    }
    let Ok(array) = env.byte_array_from_slice(&bytes) else {
        return FAILED;
    };
    let array_object = JObject::from(array);
    let result = env.call_method(
        queue,
        "offer",
        "([BI)Z",
        &[
            JValue::Object(&array_object),
            JValue::Int(bytes.len() as jint),
        ],
    );
    match result {
        Ok(value) if value.z() == Ok(true) => OK,
        _ => {
            if env.exception_check().unwrap_or(false) {
                let _ = env.exception_clear();
            }
            FAILED
        }
    }
}

/// Probe only: test a synthetic Rust-produced IP/UDP datagram entering the
/// bounded Java output queue. No upstream relay is created or authorized.
// SAFETY REVIEW: JNI symbol export only; no handwritten unsafe operations.
#[allow(unsafe_code)]
#[no_mangle]
pub extern "system" fn Java_org_netscope_ngfw_NativeCore_probeTunEgressQueue(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    queue: JObject<'_>,
    ipv6: jboolean,
) -> jint {
    catch_unwind(AssertUnwindSafe(|| probe(&mut env, queue, ipv6 != 0))).unwrap_or(FAILED)
}
