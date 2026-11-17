//! JNI adapter for a diagnostic drop-all VPN. No TUN FD, socket or forwarding ownership.
use jni::{
    objects::{JByteArray, JClass},
    sys::jint,
    JNIEnv,
};
use netscope_packet::{parse_checked, ChecksumPolicy};
use netscope_policy::{Action, Policy};
use std::{
    panic::{catch_unwind, AssertUnwindSafe},
    sync::LazyLock,
};

pub const MAX_DATAGRAM: usize = 65_575;
pub const BRIDGE_ERROR: jint = -1;
pub const INVALID_PACKET: jint = 0;
pub const DENIED_PACKET: jint = 1;
static POLICY: LazyLock<Policy> =
    LazyLock::new(|| Policy::new(vec![], Action::Deny).expect("empty deny policy"));

/// Diagnostic codes describe discarded input, never permission to forward.
pub fn inspect(bytes: &[u8]) -> jint {
    if bytes.is_empty() || bytes.len() > MAX_DATAGRAM {
        return BRIDGE_ERROR;
    }
    match parse_checked(bytes, ChecksumPolicy::Require) {
        Ok(packet) if POLICY.decide(&packet.packet).action == Action::Deny => DENIED_PACKET,
        _ => INVALID_PACKET,
    }
}

// SAFETY REVIEW: the only unsafe-code lint exception is the unique ABI symbol export.
// Signature matches NativeCore.inspect(byte[], int); jni owns pointer/array validation.
// No raw pointers, unsafe blocks, global JVM references or FDs cross this implementation.
// Reject lengths before copying; catch Rust unwinding before it can reach Java.
#[allow(unsafe_code)]
#[no_mangle]
pub extern "system" fn Java_org_netscope_ngfw_NativeCore_inspect(
    env: JNIEnv<'_>,
    _class: JClass<'_>,
    bytes: JByteArray<'_>,
    length: jint,
) -> jint {
    catch_unwind(AssertUnwindSafe(|| {
        let Ok(length) = usize::try_from(length) else {
            return BRIDGE_ERROR;
        };
        if length == 0 || length > MAX_DATAGRAM {
            return BRIDGE_ERROR;
        }
        let Ok(array_length) = env.get_array_length(&bytes) else {
            return BRIDGE_ERROR;
        };
        let Ok(array_length) = usize::try_from(array_length) else {
            return BRIDGE_ERROR;
        };
        if array_length > MAX_DATAGRAM || length > array_length {
            return BRIDGE_ERROR;
        }
        // One bounded owned copy; no JNI pin or Java buffer reference survives this call.
        let Ok(mut owned) = env.convert_byte_array(&bytes) else {
            return BRIDGE_ERROR;
        };
        owned.truncate(length);
        inspect(&owned)
    }))
    .unwrap_or(BRIDGE_ERROR)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn diagnostic_core_never_returns_allow() {
        assert_eq!(inspect(&[]), BRIDGE_ERROR);
        assert_eq!(inspect(&[0x45; 3]), INVALID_PACKET);
        assert_eq!(inspect(&vec![0; MAX_DATAGRAM + 1]), BRIDGE_ERROR);
        let text = include_str!("../../netscope-packet/tests/fixtures/v4-tcp-odd.hex").trim();
        let bytes: Vec<_> = text
            .as_bytes()
            .chunks_exact(2)
            .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap())
            .collect();
        assert_eq!(inspect(&bytes), DENIED_PACKET);
    }
}

#[cfg(all(unix, not(target_os = "android")))]
mod socket_protection;

#[cfg(unix)]
mod vpn_protector;

#[cfg(all(unix, not(target_os = "android")))]
mod udp_relay_probe;

#[cfg(not(target_os = "android"))]
mod tun_egress_probe;

/// Bounded default-deny UDP session kernel; not connected to the diagnostic VPN.
pub mod udp_session;

#[cfg(unix)]
mod udp_session_jni;
