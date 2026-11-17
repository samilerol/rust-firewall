# IPv4/IPv6 Rust UDP relay → JNI → bounded Java TUN queue regression

This regression extends the existing host-only UDP loopback smoke test with an **IPv6** path. Java starts an echo server bound to `::1`, and Rust constructs a checksummed IPv6 UDP packet sourced from the test ULA `fd12:3456:789a::2`, sends via `UdpRelay` with a fake host JVM protection callback, receives an actual echo response, applies the reverse-direction allow rule, and offers the authorized datagram through JNI into the bounded Java queue. The Java owner drains the queue and checks IPv6 framing, length, next-header and reply payload.

A negative test omits the reverse-direction policy rule: the response must **not** reach the queue. The existing IPv4 positive/negative tests and protection refusal/exception checks remain.

**Scope and release gate:** this is a host-JVM, local-loopback test and **not** a physical Android, IPv6 WAN, routing, DNS leak, always-on/lockdown or fail-closed test. The test intentionally supplies a fake protector, never a production bypass callback; no Android TUN FD is attached. The existing `DiagnosticVpnService` remains drop-all. A production VPN must use real `VpnService.protect`, enforce current per-direction policy and lifecycle revocation, and prove behavior on real devices. Do not expose this probe as a production forwarding API. See issue #9.
