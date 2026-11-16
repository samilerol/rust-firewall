//! Isolated synchronous JNI bridge to native Rust UDP/TCP socket protection.
//! Never called from the existing drop-all diagnostic. No TUN, connect, send or
//! routing operation is performed by this probe.
use jni::{
    objects::{JClass, JObject, JValue},
    sys::jint,
    JNIEnv,
};
use netscope_transport::{
    fd_protection::FdProtector, tcp::TcpSocketProtector, SocketProtector,
};
use socket2::{Domain, Protocol, Socket, Type};
use std::{
    cell::RefCell,
    io,
    net::{Ipv4Addr, UdpSocket},
    panic::{catch_unwind, AssertUnwindSafe},
    os::fd::RawFd,
};

const PROTECTION_OK: jint = 0;
const PROTECTION_REFUSED: jint = -1;

/// Borrowed JNI environment and Java object are kept only for this synchronous call.
/// A future transport integration must independently design thread attachment and
/// service lifetime; this probe does not retain or export native descriptors.
fn probe(env: &mut JNIEnv<'_>, service: JObject<'_>) -> jint {
    if service.is_null() {
        return PROTECTION_REFUSED;
    }
    let cell = RefCell::new(env);
    let callback = |fd: RawFd| -> io::Result<bool> {
        let mut env = cell.borrow_mut();
        let result = env.call_method(
            &service,
            "protect",
            "(I)Z",
            &[JValue::Int(fd)],
        );
        match result {
            Ok(value) => value
                .z()
                .map_err(|_| io::Error::other("invalid protect return type")),
            Err(_) => {
                // A Java exception must never be allowed to become approval.
                if env.exception_check().unwrap_or(false) {
                    let _ = env.exception_clear();
                }
                Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "VpnService.protect failed",
                ))
            }
        }
    };
    let protector = FdProtector::new(callback);
    // Ephemeral local bind only; no connect/send/receive to an outside endpoint.
    let udp = match UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)) {
        Ok(udp) => udp,
        Err(_) => return PROTECTION_REFUSED,
    };
    if SocketProtector::protect(&protector, &udp).is_err() {
        return PROTECTION_REFUSED;
    }
    // TCP is still unconnected when the platform protection callback runs.
    let tcp = match Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP)) {
        Ok(tcp) => tcp,
        Err(_) => return PROTECTION_REFUSED,
    };
    if TcpSocketProtector::protect(&protector, &tcp).is_err() {
        return PROTECTION_REFUSED;
    }
    PROTECTION_OK
}

// SAFETY REVIEW: JNI symbol export only. No manual pointer dereference or raw
// unsafe blocks. This method is an opt-in protection probe, NOT forwarding.
// JNI local object and descriptor lifetimes end before the method returns.
#[allow(unsafe_code)]
#[no_mangle]
pub extern "system" fn Java_org_netscope_ngfw_NativeCore_probeProtectedSockets(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    service: JObject<'_>,
) -> jint {
    catch_unwind(AssertUnwindSafe(|| probe(&mut env, service)))
        .unwrap_or(PROTECTION_REFUSED)
}
