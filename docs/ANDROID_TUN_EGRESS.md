# Android TUN egress contract (development-only)

`TunPacketWriter` is a **package-private, currently unused** Java output boundary for future TUN response datagrams. It accepts an explicitly supplied owned OutputStream, binds to its creating thread, allows MTU 1280–1500, verifies complete IPv4/IPv6 wire-length framing, and fails closed on write errors. Closing the writer closes the underlying stream; do not wrap the existing reader-owned TUN FD or share ownership without redesign.

## Security boundaries

- This is **not** a packet firewall, cryptographic integrity checker, transport engine, permission decision or independently sufficient protection. It does not validate checksums, IPv4 fragments, IPv6 extension chains or whether a response was authorized; **the Rust relay and current inbound policy must handle those before calling it**.
- Never use this class to echo ingress TUN packets or forward untrusted arbitrary bytes. No automatic fallthrough, bypass, transport opening or return path is wired into `DiagnosticVpnService`. Existing diagnostic continues dropping all packets.
- The writer accepts full IP datagrams only and rejects mismatched length, jumbo/empty IPv6 payload, MTU overflow, invalid v4 header length, wrong thread and writes after close. It doesn't retry a failing OutputStream because partial writes cannot safely be replayed.
- No device/emulator evidence exists. Physical-device validation must cover both IP families, TUN output ownership, blocked packet paths, service shutdown, revoke, native crash, loss of VPN or lockdown, DNS leaks and independent packet capture.

Host JVM smoke is executed by Android CI. Next: implement a **separate explicitly opt-in forwarding session** with a single FD owner coordinating Rust-relay output and TUN write, bounded queues, cancellation and fail-stop. Integrate UDP first; TCP later. Do not activate in diagnostic or advertise the APK as a working firewall.
