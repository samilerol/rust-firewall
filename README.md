# NetScope Rust NGFW

An independent, privacy-first, offline-first Android firewall project, Apache-2.0 licensed. The portable Rust core is accompanied by an experimental Android **drop-all diagnostic VPN**, not a forwarding firewall. Android behavior has not been device-tested.

## Implemented

- `netscope-packet`: allocation-free IPv4/IPv6 TCP/UDP metadata parsing with strict datagram lengths.
- `netscope-policy`: source/destination CIDR, protocol and port-range rules; lower numeric priority wins, then original input order. Explicit default action and decision provenance. Construction rejects oversized configurations (hard cap: 4096 rules) and inverted port ranges.
- `netscope-conntrack`: directional five-tuple observations, monotonic timestamps, expiry and maximum entry count. Not a TCP state machine.

## Build and verify

Stable Rust; minimum supported version 1.85. The parser/policy/conntrack/engine/DNS libraries use std/internal workspace dependencies. TCP transport uses pinned smoltcp/socket2/getrandom; the separate Android adapter uses jni.

```sh
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo build --workspace
```

CI runs these checks independently on standard `ubuntu-24.04` runners, plus an MSRV build/test. Runner CPU, memory and disk are printed rather than assumed. No Android SDK or paid infrastructure is required.

See [architecture](docs/ARCHITECTURE.md), [security model](docs/SECURITY_MODEL.md), [test plan](docs/TEST_PLAN.md), [roadmap](docs/ROADMAP.md) and [agent context](AGENTS.md).

## Limitations

Portable UDP socket relay exists with loopback coverage; experimental TCP forwarding is available as a portable library; app attribution, question-based classic UDP DNS filtering exists as an opt-in relay feature; DPI, IDS and kernel adapters remain unimplemented. A minimal Android consent/service/JNI diagnostic discards all read datagrams; it is not a usable forwarding firewall. IPv4 options/fragments, IPv6 extension headers/jumbograms and non-TCP/UDP protocols are rejected. `parse` extracts metadata without checksum checks; `parse_checked` validates IPv4 header and TCP/UDP pseudo-header checksums under an explicit UDP omission policy. TCP options are bounded but not interpreted. Parsed metadata is untrusted, not proof of authenticity. Synthetic hosted-runner microbenchmarks exist; there are no Android performance or device leak-test results.

This public project must never receive private code from `samilerol/netscope`.

## Core hardening follow-up

`Policy::new` now returns `Result<Policy, PolicyError>`; callers must handle configuration rejection without replacing a previous policy with implicit allow. `Policy::with_limit` can impose a smaller rule cap. The input Vec is already allocated: this is not an input-file size limit.

A separate [parser fuzz target](fuzz/README.md) exercises untrusted datagrams with address sanitizer. Its CI smoke run is bounded to 30 seconds; this is not exhaustive security validation. CIDR property tests cover every prefix length and single-bit address changes without a new core dependency.

## Performance baseline harness

`tools/core-bench` is a development-only workspace binary with 31 synthetic parser/policy/flow scenarios, release-only execution and CSV output. `cargo run --release --locked -p netscope-bench -- --smoke` checks the harness quickly. See [benchmark methodology](docs/BENCHMARKS.md) for full runs, warmup/sample interpretation, CI artifacts and limitations. These are host library microbenchmarks, not Android performance measurements.

## Explicit checksum validation

Use `netscope_packet::parse_checked(bytes, ChecksumPolicy::Require)` at a boundary requiring complete wire checksums. It returns the packet metadata plus `TransportChecksum::Verified`, or a structural/checksum error. `ChecksumPolicy::AllowIpv4UdpOmission` permits the IPv4 UDP standard's optional zero checksum and reports `OmittedIpv4Udp`; IPv6 UDP zero is always rejected. `parse` remains metadata-only for callers that deliberately choose not to verify checksums. Neither API authenticates traffic. Checksum offload may leave partial checksums in OS buffers; determine the actual platform contract before using strict validation on a TUN path.

## Android diagnostic milestone

`android/` contains a consent/start/stop screen and VPNService; `netscope-android` provides the bounded JNI inspection bridge. **Starting the diagnostic VPN blocks routed traffic: there is no forwarding.** See [Android integration](docs/ANDROID_INTEGRATION.md) for ownership, APK build/CI, limitations and outstanding physical-device validation. Java is limited to platform/lifecycle integration and this temporary diagnostic screen; the final Rust-native UI is not implemented.

## Portable engine and UDP relay

- `netscope-engine`: checked packet admission, bounded flows, atomic policy replacement, explicit response authorization and aggregate counters.
- `netscope-transport`: nonblocking IPv4/IPv6 UDP relay with mandatory protection-before-connect hook, current response-policy checks, bounded socket count, MTU enforcement and network reset.
- Conntrack uses one ordered expiry record per active flow; policy compiles priority order once while preserving original rule indices.

See [engine/transport contracts](docs/ENGINE_TRANSPORT.md). APK/UI work is paused; the Android diagnostic remains drop-all and is not connected to this relay. An experimental portable TCP proxy is now available; it is not integrated into the diagnostic app. A successful UDP loopback test is not Android/device enforcement evidence.

## Classic DNS/domain policy

`netscope-dns` adds bounded compression/EDNS/message parsing and exact/subdomain rules. Enable it explicitly on selected UDP destination ports with `UdpRelay::set_dns_filter`; allowed names still require packet policy allow. Replies must match one pending transaction/question per flow. See [DNS scope and limits](docs/DNS_POLICY.md): this does not inspect DoH/DoT, TCP DNS, aliases or direct IP access, and is not DNSSEC validation. APK/UI remains paused.

## Experimental TCP software path

`netscope_transport::tcp::TcpRelay` connects raw IPv4/IPv6 TCP to caller-protected nonblocking OS streams using smoltcp. It has bounded flow/stream/packet budgets, partial-write backpressure, half-close handling and explicit clock/connect/idle limits. See [TCP contracts](docs/TCP_TRANSPORT.md). TCP DNS/encrypted-domain filtering and platform integration are not implemented. APK/UI remains paused.
