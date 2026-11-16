# Android native socket protection: synchronous JNI probe

This milestone implements `NativeCore.probeProtectedSockets(Object)`, backed by Rust-created IPv4 UDP and TCP sockets. Rust's `FdProtector` hands the **actual borrowed native file descriptor** to a synchronous Java `protect(int): boolean` method. Android's `VpnService.protect(int)` matches this method. Both sockets are dropped when the probe ends; no external destination is connected and no traffic is sent.

**Strict outcomes:** 0 means both protection callbacks returned true in this invocation, -1 means refusal, null service, Java exception, invalid descriptor, or socket creation failure. Exceptions are cleared at the JNI boundary and do not authorize protection. The Java object/VM environment and FDs are never retained; no background thread is created.

Host-JVM tests use a fake service to verify both callbacks, first/second denial, exception handling, and successful callback invocation. These tests establish the **JNI calling contract only**. They do not verify Android OS VPN routing or that a fake callback actually protects a socket.

**Not implemented:** This probe is deliberately disconnected from `DiagnosticVpnService`; the running APK remains drop-all. Neither `UdpRelay` nor `TcpRelay` is yet driven from TUN. A future Android worker needs a thread-safe JavaVM/global-ref lifecycle, VPN revocation barriers, transport reset, network-change support, bounded packet queues, explicit forwarder consent, and independent IPv4/IPv6/DNS device leak testing. Do not use this probe result as a runtime security guarantee or silently activate a forwarder.

## Review gates

- Rust and Android CI (including real host JVM/JNI smoke) must pass.
- A failing callback must never be converted to implicit allow.
- Android VPN app must remain diagnostic-only until end-to-end tests.
- Full physical-device tests are needed before any claims about leak-free operation, fail-closed shutdown or always-on/lockdown.
