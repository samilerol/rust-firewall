//! Lifecycle-scoped JavaVM/GlobalRef adapter for Android VPN socket protection.
//! This only protects Rust-created sockets; it does not drive TUN traffic.
use jni::{objects::{GlobalRef, JObject, JValue}, JNIEnv, JavaVM};
use netscope_transport::{
    fd_protection::FdProtector, tcp::TcpSocketProtector, SocketProtector,
};
use socket2::Socket;
use std::{
    io,
    net::UdpSocket,
    os::fd::RawFd,
    sync::atomic::{AtomicBool, Ordering},
};

pub struct AndroidVpnProtector {
    vm: JavaVM,
    service: GlobalRef,
    active: AtomicBool,
}

impl AndroidVpnProtector {
    pub fn new(env: &mut JNIEnv<'_>, service: &JObject<'_>) -> jni::errors::Result<Self> {
        Ok(Self {
            vm: env.get_java_vm()?,
            service: env.new_global_ref(service)?,
            active: AtomicBool::new(true),
        })
    }

    /// Caller must revoke on VPN shutdown/network-policy teardown and stop its workers.
    /// An in-flight protection call can race with revoke: this flag is not itself
    /// an Android traffic kill switch or authorization to connect afterwards.
    pub fn revoke(&self) {
        self.active.store(false, Ordering::SeqCst);
    }

    pub fn protect_fd(&self, fd: RawFd) -> io::Result<bool> {
        if fd < 0 || !self.active.load(Ordering::SeqCst) {
            return Ok(false);
        }
        let mut env = self.vm.attach_current_thread().map_err(|_| {
            io::Error::other("unable to attach socket protector to Java VM")
        })?;
        let result = env.call_method(
            self.service.as_obj(),
            "protect",
            "(I)Z",
            &[JValue::Int(fd)],
        );
        let approved = match result {
            Ok(value) => value.z().unwrap_or(false),
            Err(_) => {
                if env.exception_check().unwrap_or(false) {
                    let _ = env.exception_clear();
                }
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "Android VPN socket protection failed",
                ));
            }
        };
        // Re-check prevents approval if revocation was observed during callback.
        // It does not replace a transport/worker lifecycle barrier.
        Ok(approved && self.active.load(Ordering::SeqCst))
    }
}

impl SocketProtector for AndroidVpnProtector {
    fn protect(&self, socket: &UdpSocket) -> io::Result<()> {
        SocketProtector::protect(&FdProtector::new(|fd| self.protect_fd(fd)), socket)
    }
}

impl TcpSocketProtector for AndroidVpnProtector {
    fn protect(&self, socket: &Socket) -> io::Result<()> {
        TcpSocketProtector::protect(&FdProtector::new(|fd| self.protect_fd(fd)), socket)
    }
}
