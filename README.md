# NetScope Rust NGFW

An independent, privacy-first, offline-first Android firewall project, Apache-2.0 licensed. Milestone 1 is a portable Rust library workspace, **not an Android firewall application**. It does not currently intercept or protect traffic.

## Implemented

- `netscope-packet`: allocation-free IPv4/IPv6 TCP/UDP metadata parsing with strict datagram lengths.
- `netscope-policy`: source/destination CIDR, protocol and port-range rules; lower numeric priority wins, then original input order. Explicit default action and decision provenance. Construction rejects oversized configurations (hard cap: 4096 rules) and inverted port ranges.
- `netscope-conntrack`: directional five-tuple observations, monotonic timestamps, expiry and maximum entry count. Not a TCP state machine.

## Build and verify

Stable Rust; minimum supported version 1.85. No third-party runtime dependencies.

```sh
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo build --workspace
```

CI runs these checks independently on standard `ubuntu-24.04` runners, plus an MSRV build/test. Runner CPU, memory and disk are printed rather than assumed. No Android SDK or paid infrastructure is required.

See [architecture](docs/ARCHITECTURE.md), [security model](docs/SECURITY_MODEL.md), [test plan](docs/TEST_PLAN.md), [roadmap](docs/ROADMAP.md) and [agent context](AGENTS.md).

## Limitations

No socket forwarding, JNI, Android UI/service, app attribution, DNS filtering, DPI, IDS, kernel adapter or packet enforcement exists. IPv4 options/fragments, IPv6 extension headers/jumbograms and non-TCP/UDP protocols are rejected. Checksums are not verified. TCP options are bounded but not interpreted. Parsed metadata is untrusted, not proof of authenticity. There are no performance or device leak-test results.

This public project must never receive private code from `samilerol/netscope`.

## Core hardening follow-up

`Policy::new` now returns `Result<Policy, PolicyError>`; callers must handle configuration rejection without replacing a previous policy with implicit allow. `Policy::with_limit` can impose a smaller rule cap. The input Vec is already allocated: this is not an input-file size limit.

A separate [parser fuzz target](fuzz/README.md) exercises untrusted datagrams with address sanitizer. Its CI smoke run is bounded to 30 seconds; this is not exhaustive security validation. CIDR property tests cover every prefix length and single-bit address changes without a new core dependency.
