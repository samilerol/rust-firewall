//! Fail-closed JNI lifecycle for a single dormant Android UDP session.
//!
//! No packet ingress, rule loading, upstream traffic, or TUN writing is exposed.
//! The session exists to bind Rust resource lifetime to VpnService teardown.
use crate::{udp_session::UdpSession, vpn_protector::AndroidVpnProtector};
use jni::{
    objects::{JClass, JObject},
    sys::{jint, jlong},
    JNIEnv,
};
use netscope_transport::SocketProtector;
use std::{
    io,
    net::UdpSocket,
    panic::{catch_unwind, AssertUnwindSafe},
    sync::{Arc, Mutex},
};

const FAILURE: jint = -1;
const SUCCESS: jint = 0;
const INVALID_HANDLE: jlong = 0;

struct SharedProtector(Arc<AndroidVpnProtector>);

impl SocketProtector for SharedProtector {
    fn protect(&self, socket: &UdpSocket) -> io::Result<()> {
        SocketProtector::protect(self.0.as_ref(), socket)
    }
}

struct Session {
    id: jlong,
    protector: Arc<AndroidVpnProtector>,
    relay: UdpSession<SharedProtector>,
}

struct Registry {
    next_id: jlong,
    session: Option<Session>,
}

static REGISTRY: Mutex<Registry> = Mutex::new(Registry {
    next_id: 1,
    session: None,
});

fn start(env: &mut JNIEnv<'_>, service: JObject<'_>) -> jlong {
    if service.is_null() {
        return INVALID_HANDLE;
    }
    let Ok(mut registry) = REGISTRY.lock() else {
        return INVALID_HANDLE;
    };
    // Only one VPN can own the native session. Never replace an active owner.
    if registry.session.is_some() || registry.next_id <= 0 {
        return INVALID_HANDLE;
    }
    let Ok(protector) = AndroidVpnProtector::new(env, &service) else {
        return INVALID_HANDLE;
    };
    let protector = Arc::new(protector);
    let Ok(relay) = UdpSession::new(SharedProtector(Arc::clone(&protector))) else {
        protector.revoke();
        return INVALID_HANDLE;
    };
    let id = registry.next_id;
    // Never recycle a token. If the sequence overflows, permanently deny.
    registry.next_id = registry.next_id.checked_add(1).unwrap_or(0);
    registry.session = Some(Session {
        id,
        protector,
        relay,
    });
    id
}

fn stop(id: jlong) -> jint {
    if id <= 0 {
        return FAILURE;
    }
    let Ok(mut registry) = REGISTRY.lock() else {
        return FAILURE;
    };
    if registry.session.as_ref().map(|s| s.id) != Some(id) {
        return FAILURE;
    }
    if let Some(mut session) = registry.session.take() {
        session.protector.revoke();
        session.relay.revoke();
    }
    SUCCESS
}

fn reset(id: jlong) -> jint {
    if id <= 0 {
        return FAILURE;
    }
    let Ok(mut registry) = REGISTRY.lock() else {
        return FAILURE;
    };
    let Some(session) = registry.session.as_mut().filter(|s| s.id == id) else {
        return FAILURE;
    };
    match session.relay.reset_network() {
        Ok(()) => SUCCESS,
        Err(_) => FAILURE,
    }
}

// SAFETY REVIEW: JNI exported symbols only. No pointer handling, no native
// descriptor ownership and no packet operations. JVM object held as GlobalRef
// by AndroidVpnProtector while this dormant session exists.
#[allow(unsafe_code)]
#[no_mangle]
pub extern "system" fn Java_org_netscope_ngfw_NativeCore_startUdpSession(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    service: JObject<'_>,
) -> jlong {
    catch_unwind(AssertUnwindSafe(|| start(&mut env, service))).unwrap_or(INVALID_HANDLE)
}

#[allow(unsafe_code)]
#[no_mangle]
pub extern "system" fn Java_org_netscope_ngfw_NativeCore_stopUdpSession(
    _env: JNIEnv<'_>,
    _class: JClass<'_>,
    id: jlong,
) -> jint {
    catch_unwind(AssertUnwindSafe(|| stop(id))).unwrap_or(FAILURE)
}

#[allow(unsafe_code)]
#[no_mangle]
pub extern "system" fn Java_org_netscope_ngfw_NativeCore_resetUdpSessionNetwork(
    _env: JNIEnv<'_>,
    _class: JClass<'_>,
    id: jlong,
) -> jint {
    catch_unwind(AssertUnwindSafe(|| reset(id))).unwrap_or(FAILURE)
}
