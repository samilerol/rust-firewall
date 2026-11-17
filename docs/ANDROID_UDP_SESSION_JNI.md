# Dormant Android UDP session lifecycle bridge

The diagnostic VPN now opens a **default-deny, dormant** Rust `UdpSession` through `NativeCore.startUdpSession(this)` after VPN consent. `shutdown()` revokes it through `stopUdpSession`, including stop, revoke, service teardown and startup failures. A handle is a monotonically increasing positive token, **not** a native pointer/FD. Zero indicates start failure; stop/reset return 0 on success and -1 otherwise.

The Rust registry owns **at most one** session. It refuses a second start, stale/wrong handles and use after stop. Stop revokes `AndroidVpnProtector` and terminally revokes `UdpSession`, dropping any Rust UDP flows and native sockets. Reset clears UDP flow/socket state, but is not yet hooked to Android ConnectivityManager. The global mutex serializes handle operations; on poisoning the interface refuses further actions. Token exhaustion permanently rejects new sessions rather than recycling handles.

The JNI API **does not expose policy updates, send, receive, or a TUN output method**. No UDP flow is authorized or created by the diagnostic. Existing TUN reader still calls `inspect` and discards all packets. Host JVM tests assert one-owner exclusivity, monotonic tokens, stale token rejection, stop/reset behavior and **zero** fake socket-protection invocations. Android CI checks JNI symbols on arm64-v8a and x86_64.

## Remaining production gates

Before enabling forwarding: design explicit policy serialization/admission, an authorized session-controlled TUN event loop, protected socket scheduling, fair bounded output, network transition observer, robust thread lifecycle barriers, per-app identity policy, and physical Android IPv4/IPv6/DNS/lockdown tests. Race-free revocation under concurrent `send` and `protect` is not established; the current JNI interface deliberately exposes neither send nor rule installation. Stopping a VPN without OS lockdown restores ordinary Android networking. No device leak-free claim is made. See issue #9.
