# Protected Android UDP socket construction — development boundary

The Java `ProtectedUdpSocketFactory` returns an **already protected** connected DatagramSocket only when the caller-supplied protector returns true. The Android-only `AndroidProtectedUdpSocket.open(vpnService, remote)` adapter passes `VpnService.protect(DatagramSocket)` to this boundary. The caller must close the returned socket; protection rejection, exception or connect failure closes it before return. The destination must be an already resolved unicast address and a nonzero port; this prevents hostname-resolution side effects at this boundary.

The factory has no fallback, does not send an upstream datagram before `protect`, and does not contain background threads or retain sockets. A JVM-hosted loopback contract test covers protection-before-bind/connect, refusal, thrown exceptions, destination validation and a protected-callback send. It **does not prove** that Android `VpnService.protect` works on a physical device.

**Not integrated:** This Java factory and its Android adapter are not used by `DiagnosticVpnService`, `netscope-transport`, or the Rust JNI bridge. The diagnostic still drops all routed packets. A separate Rust/Android bridge must solve protection of the native sockets used by Rust UDP and TCP transports without leaking FD ownership. Do not treat this helper as a functional firewall or claim network isolation, leak prevention or per-app policy from its presence.

Next: implement a minimal, bounded socket-protection invocation across JNI, reject protection failure, and test its sequencing on an Android emulator/physical device before integrating either transport with TUN. Keep the default diagnostic and explicit opt-in forwarding separate.
