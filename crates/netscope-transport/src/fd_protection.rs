//! Unix/Android native-FD protection hook for sockets opened by the Rust relays.
//!
//! This is an adapter for a trusted caller-provided platform callback, NOT a
//! VpnService implementation. On Android the callback MUST call
//! VpnService.protect(fd) and return false/error when protection cannot be proved.
//! Never pass a no-op or unconditional-true callback in a shipping VPN.
use crate::{tcp::TcpSocketProtector, SocketProtector};
use socket2::Socket;
use std::{
    io,
    net::UdpSocket,
    os::fd::{AsRawFd, RawFd},
};

/// Converts platform protection refusal into an I/O error before a Rust relay
/// can connect or transmit through its newly opened socket.
pub struct FdProtector<F> {
    protect: F,
}

impl<F> FdProtector<F>
where
    F: Fn(RawFd) -> io::Result<bool>,
{
    pub fn new(protect: F) -> Self {
        Self { protect }
    }

    fn apply(&self, fd: RawFd) -> io::Result<()> {
        if fd < 0 {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid socket fd"));
        }
        match (self.protect)(fd)? {
            true => Ok(()),
            false => Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "VPN protection refused",
            )),
        }
    }
}

impl<F> SocketProtector for FdProtector<F>
where
    F: Fn(RawFd) -> io::Result<bool>,
{
    fn protect(&self, socket: &UdpSocket) -> io::Result<()> {
        self.apply(socket.as_raw_fd())
    }
}

impl<F> TcpSocketProtector for FdProtector<F>
where
    F: Fn(RawFd) -> io::Result<bool>,
{
    fn protect(&self, socket: &Socket) -> io::Result<()> {
        self.apply(socket.as_raw_fd())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use socket2::{Domain, Protocol, Type};
    use std::{cell::Cell, net::Ipv4Addr};

    #[test]
    fn refusal_is_fail_closed_for_udp_and_tcp() {
        let udp = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let tcp = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP)).unwrap();
        let calls = Cell::new(0);
        let protection = FdProtector::new(|fd| {
            assert!(fd >= 0);
            calls.set(calls.get() + 1);
            Ok(false)
        });
        assert_eq!(
            SocketProtector::protect(&protection, &udp).unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
        assert_eq!(
            TcpSocketProtector::protect(&protection, &tcp).unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
        assert_eq!(calls.get(), 2);
    }

    #[test]
    fn errors_propagate_and_success_passes_exact_fds() {
        let udp = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let tcp = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP)).unwrap();
        let failure = FdProtector::new(|fd| {
            assert!(fd >= 0);
            Err(io::Error::other("platform unavailable"))
        });
        assert_eq!(
            SocketProtector::protect(&failure, &udp).unwrap_err().kind(),
            io::ErrorKind::Other
        );
        assert_eq!(
            TcpSocketProtector::protect(&failure, &tcp).unwrap_err().kind(),
            io::ErrorKind::Other
        );

        let success = FdProtector::new(|fd| {
            assert!(fd == udp.as_raw_fd() || fd == tcp.as_raw_fd());
            Ok(true)
        });
        SocketProtector::protect(&success, &udp).unwrap();
        TcpSocketProtector::protect(&success, &tcp).unwrap();
    }

    #[test]
    fn invalid_descriptor_never_calls_platform() {
        let protection = FdProtector::new(|_| -> io::Result<bool> {
            panic!("invalid fd must fail before callback")
        });
        assert_eq!(
            protection.apply(-1).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
    }
}
