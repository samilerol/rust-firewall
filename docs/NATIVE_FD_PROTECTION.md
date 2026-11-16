# Native socket protection boundary (Unix / Android)

`netscope_transport::fd_protection::FdProtector` implements **both** the Rust UDP `SocketProtector` and TCP `TcpSocketProtector` traits using the actual file descriptor of the socket created by the Rust transport. It accepts a trusted `Fn(RawFd) -> io::Result<bool>` callback and maps platform refusal to `PermissionDenied` and errors to I/O failures. No fallback socket or default no-op callback is supplied.

## Limits / next integration step

This is a **portable boundary**, not an Android integration. The callback is injected by the embedding application; **there is no JNI callback, Android VpnService instance or live TUN forwarder yet**. A shipping Android adapter must call `VpnService.protect(int)` on the supplied fd synchronously and treat false/exception/permission failures as denial. The fd is borrowed; the callback must not close, duplicate, retain or asynchronously operate on it. Avoid Java-side DNS resolution and all traffic before protection. Android network-binding and VPN lifecycle guarantees require separate design and physical-device verification.

The existing UDP relay binds an ephemeral local socket before invoking its protection callback, but never connects or transmits before successful protection. The TCP relay protects the newly created unconnected socket before sending an upstream SYN. These are transport-specific pre-existing sequencing contracts, not network leak evidence. Host tests check callback invocation, correct fd identity, rejection and error propagation for both kinds of sockets; they do not test Android's actual protection API.

Never inject an unconditional-true callback in a real VPN. Existing diagnostic Android application remains **drop-all**, without native forwarding. Integration tracked by issue #9.
