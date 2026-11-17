# Session-scoped UDP TUN ingress dry-run

The diagnostic Android VPN reader now passes each **already-discarded** TUN input datagram to `NativeCore.inspectUdpSession(sessionId, packet, length)` after the original deny-only `inspect` check. This exercises a real JNI input path associated with the current default-deny Rust UDP session. The diagnostic still has **no packet forwarding**, no allow-rule JNI API, no upstream send, and no TUN output writer.

## Return contract

- `1`: well-formed, checksum-verified UDP datagram was inspected and **dropped**.
- `0`: unsupported, non-UDP or malformed datagram was **dropped**.
- `-1`: stale/invalid session ID, null array, invalid/oversized dimensions, allocation/JNI failure or unwinding. Diagnostic reader stops on `-1`.

Every return value means **never forward this packet**. In particular `1` is not an allow decision. There are no flow associations or policy mutations from inspection. JNI caps arrays at 65,575 bytes and validates the requested prefix before making one owned copy; it checks the session under the same mutex as revoke/stop before classifying. Stop invalidates the session token and closes Rust-owned sockets (there are none in this mode). Java keeps the session ID `volatile` across reader/shutdown threads.

Host-JVM tests check valid IPv4/IPv6 UDP, TCP exclusion, mutated checksums, lengths, null arrays, stale tokens, network reset and zero socket-protection invocations. CI cross-compiles ARM64/x86_64 and checks the native symbol. **These are not Android-device validation results.**

## Gates before usable forwarding

An actual forwarding mode needs bounded scheduling of `UdpSession::send/receive`, current two-direction policy and DNS protection, TUN return queue ownership, permission/cancellation barriers, network transition handling, UID policy, Android 14+ foreground restrictions and physical-device IPv4/IPv6/DNS leak tests. This dry-run deliberately leaves all forwarding functionality disabled. See issue #9.
