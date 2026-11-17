# Security model

## Current assets and adversary

Protect parser availability, deterministic decisions and bounded flow state against attacker-controlled packet bytes. Metadata is not authenticated. This library alone enforces nothing. Trusted callers supply preallocated rule lists, capacity, timeout and monotonic time; there is no external configuration parser yet.

## Active boundaries

- Byte slice -> parser: validate version, minimum header sizes and exact datagram lengths before offsets. Reject unknown protocols, IPv4 options/fragments/reserved fragment bit, IPv6 extension headers and jumbograms. TCP data offset and UDP length must fit. `parse` is metadata-only. The opt-in `parse_checked` verifies IPv4 header plus TCP/UDP checksums including IP pseudo-headers; its explicit policy either requires IPv4 UDP checksums or returns a distinct omitted status. IPv6 UDP omission is never accepted (special tunnel exceptions are unsupported). TCP flag combinations/options and payload semantics are not validated. Malformed input produces an error; integration must map errors to drop, never bypass.
- Metadata -> policy: explicit default action, conjunctive filters, lowest priority then input order. Default-deny recommended. Policy construction rejects oversized lists and inverted port ranges atomically; it does not cap the memory used before construction. A caller must never turn a configuration error into an allow-all fallback. Public Packet can be manually constructed, so integration must only use successfully parsed datagrams.
- Policy -> observation table: only caller-approved traffic should be recorded. Reverse directions are distinct. No TCP handshake/sequence/state validation, no implicit established-flow allow. Capacity rejection is explicit. Out-of-order clocks are rejected without mutation; expiry runs at age >= timeout.

The parser/policy/conntrack/admission crates have no network I/O, persistent logs, secrets, update downloads or unsafe code; the portable UDP transport explicitly uses caller-protected OS sockets; the separate JNI adapter has one documented symbol-export exception and an upstream FFI dependency. The portable libraries use only Rust std/workspace dependencies; the separate Android adapter has locked JNI dependencies. Panic-on-allocation-failure and process resource limits remain host concerns. Random-input regression tests are not exhaustive fuzzing or a security proof.

## Future boundaries and limits

Android apps -> VPNService: attribution may be unknown; explicit configurable policy required. Kotlin/JNI -> Rust: define buffer/FD ownership, error propagation and lifecycle cancellation. TUN -> parser -> policy -> forwarding -> sockets: drop invalid packets, bound queues and buffers, protect sockets before connecting. Rule updates -> configuration: authenticate/integrity-check updates, limit sizes and replace atomically. Privileged adapter -> kernel: verify privilege/support, transactional rules, rollback and recovery.

Rootless fail-closed enforcement outside a running service requires Android-supported always-on VPN and Block connections without VPN settings. The app alone cannot guarantee enforcement after VPN loss. Other VPNs can conflict; Android versions restrict attribution/background services. Encrypted payloads, DoH, DoT, ECH and QUIC limit visibility. No TLS interception or disabled certificate validation. None of these Android properties has been device-tested here.

## Fuzz boundary

The isolated fuzz workspace uses development-only libfuzzer-sys and its locked C/C++ build dependencies; these are not linked into production core crates. Its macro/runtime uses upstream unsafe instrumentation, outside the core's unsafe-forbid boundary. Nightly and a C++ compiler are needed for sanitizer fuzzing. CI runs unprivileged on standard hosted runners with 30-second fuzz budget, 5-second per-input timeout, 1024 MiB RSS limit, two build workers and 15-minute job timeout. Reproducers are retained for seven days on failure; locally generated corpus/artifacts are ignored. No production traffic is used in the seed corpus. Time limits do not prove absence of vulnerabilities.

## Checksum boundary

Structure is validated before any checksum offsets are used. IPv4 header failure, transport failure and missing UDP checksum have distinct errors. End-around carry is folded on each word to bound arithmetic; odd payload tails are padded on the right as specified by RFC 1071. IPv4 pseudo-headers use 16-bit segment lengths; IPv6 uses 32-bit lengths with zero padding. TCP checksum value zero may be valid; UDP calculated zero is encoded as 0xffff and must not be confused with omission. IPv6 has no IP header checksum, so fields outside its transport pseudo-header are not protected by this check.

Checksums are corruption detection, not cryptographic authentication; an attacker can recompute them. Strict validation scans payload bytes (O(datagram length)), without allocation or unsafe. The platform must distinguish on-wire packets from offload buffers; this code never silently assumes offload or bypasses failure. VPN/TUN checksum behavior has not been device-tested. Existing metadata-only fixtures and microbenchmarks continue using parse; their passing results do not prove checked-path enforcement.

## Android diagnostic boundary

See ANDROID_INTEGRATION.md for the current VPNService/JNI boundary, bounded buffers, single reader FD ownership, cancellation, denial-only return codes and unsupported forwarding/always-on behavior. App launch alone does not establish VPN; explicit Android consent is needed. All read traffic is discarded in diagnostic mode. No device leak/foreground/lifecycle claim is made from cross-compilation or JVM tests. Closing/crashing the VPN restores ordinary OS routing; the app cannot enforce external fail-closed behavior.

## Engine and transport boundaries

ENGINE_TRANSPORT.md specifies checked admission, atomic policy changes/revocation, bounded index/socket state, response flow association, explicit inbound allow and upstream protection before connect/send. Transport prechecks reject address aliases/unsupported scopes before opening sockets. Protection is a trusted platform callback, not proof that Android protect() ran. No transport socket is connected by the Android app in this milestone. Externally retained replies and OS socket buffers need a platform byte-budget; packet/flow count bounds are not a universal memory guarantee. Periodic expiry and network-change reset are caller obligations.

## DNS question boundary

DNS_POLICY.md specifies message/name/record/compression/EDNS budgets and the ASCII profile, explicit port activation, label-boundary rules and transaction correlation. Malformed/blocked selected-port queries are not sent. The guard does not validate every RR semantic, DNSSEC/TSIG/AD/Cookies, aliases, rebinding, direct IP access, DNS on other ports or encrypted DNS. Pending questions are ephemeral local state, bounded by per-flow and global budgets with independent first-send expiry; invalid/late DNS replies cannot cancel unrelated requests. Reusing the same ID and question cannot distinguish a delayed old answer; correlation is not replay protection. Outbound/inbound packet policy and socket protection remain required; a domain allow is never network authorization.

## TCP proxy boundary

TCP_TRANSPORT.md defines accepted-SYN/protection ordering, bounded stream/packet budgets, explicit scheduling/deadline rules, current inbound authorization and best-effort abortive teardown. TCP state processing is delegated to a pinned smoltcp dependency; new source code retains unsafe-forbid but dependency internals are not claimed unsafe-free. Source/destination validation and checksums precede opening sockets. Generic TCP now exists, so UDP-only DNS rules must never be marketed as blocking TCP DNS or encrypted DNS. Host/cross-target evidence is not Android runtime or WAN security validation.
