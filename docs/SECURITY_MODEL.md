# Security model

## Current assets and adversary

Protect parser availability, deterministic decisions and bounded flow state against attacker-controlled packet bytes. Metadata is not authenticated. This library alone enforces nothing. Trusted callers supply preallocated rule lists, capacity, timeout and monotonic time; there is no external configuration parser yet.

## Active boundaries

- Byte slice -> parser: validate version, minimum header sizes and exact datagram lengths before offsets. Reject unknown protocols, IPv4 options/fragments/reserved fragment bit, IPv6 extension headers and jumbograms. TCP data offset and UDP length must fit. Checksums, TCP flag combinations/options and payload semantics are not validated. Malformed input produces an error; integration must map errors to drop, never bypass.
- Metadata -> policy: explicit default action, conjunctive filters, lowest priority then input order. Default-deny recommended. Policy construction rejects oversized lists and inverted port ranges atomically; it does not cap the memory used before construction. A caller must never turn a configuration error into an allow-all fallback. Public Packet can be manually constructed, so integration must only use successfully parsed datagrams.
- Policy -> observation table: only caller-approved traffic should be recorded. Reverse directions are distinct. No TCP handshake/sequence/state validation, no implicit established-flow allow. Capacity rejection is explicit. Out-of-order clocks are rejected without mutation; expiry runs at age >= timeout.

The core has no networking, persistent logs, secrets, update downloads or unsafe code. Dependency audit/license surface currently consists of workspace crates and Rust std only. Panic-on-allocation-failure and process resource limits remain host concerns. Random-input regression tests are not exhaustive fuzzing or a security proof.

## Future boundaries and limits

Android apps -> VPNService: attribution may be unknown; explicit configurable policy required. Kotlin/JNI -> Rust: define buffer/FD ownership, error propagation and lifecycle cancellation. TUN -> parser -> policy -> forwarding -> sockets: drop invalid packets, bound queues and buffers, protect sockets before connecting. Rule updates -> configuration: authenticate/integrity-check updates, limit sizes and replace atomically. Privileged adapter -> kernel: verify privilege/support, transactional rules, rollback and recovery.

Rootless fail-closed enforcement outside a running service requires Android-supported always-on VPN and Block connections without VPN settings. The app alone cannot guarantee enforcement after VPN loss. Other VPNs can conflict; Android versions restrict attribution/background services. Encrypted payloads, DoH, DoT, ECH and QUIC limit visibility. No TLS interception or disabled certificate validation. None of these Android properties has been device-tested here.

## Fuzz boundary

The isolated fuzz workspace uses development-only libfuzzer-sys and its locked C/C++ build dependencies; these are not linked into production core crates. Its macro/runtime uses upstream unsafe instrumentation, outside the core's unsafe-forbid boundary. Nightly and a C++ compiler are needed for sanitizer fuzzing. CI runs unprivileged on standard hosted runners with 30-second fuzz budget, 5-second per-input timeout, 1024 MiB RSS limit, two build workers and 15-minute job timeout. Reproducers are retained for seven days on failure; locally generated corpus/artifacts are ignored. No production traffic is used in the seed corpus. Time limits do not prove absence of vulnerabilities.
