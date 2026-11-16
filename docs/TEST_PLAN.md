# Test plan and milestone 1 evidence

## Executed locally

Stable Rust 1.100.0, Linux x86_64:

- `cargo fmt --check`: passed.
- `cargo clippy --workspace --all-targets -- -D warnings`: passed.
- `cargo test --workspace`: 10 tests passed, no failures; three empty doctest suites.
- `cargo build --workspace`: passed.

`cargo +1.85.0 test --workspace --locked`: passed (10 tests). The initial [GitHub Actions run](https://github.com/samilerol/rust-firewall/actions/runs/43885928166) also passed all five jobs. GitHub CI has independent stable fmt/clippy/test/build jobs and an MSRV job. Local results do not establish remote CI status; consult the actual GitHub Actions run.

## Reproducible coverage

Packet tests cover IPv4/IPv6 crossed with TCP/UDP, both addresses and ports, all truncated prefixes, inconsistent datagram/UDP/TCP lengths, IPv4 fragments/options, extension-header rejection and 16,384 deterministic arbitrary inputs without panic. Fixtures test header structure; checksum fields are synthetic and are not validated. This is not a cargo-fuzz campaign.

Policy tests cover IPv4 /0, /24, /32 and IPv6 /0, /64, /128, host bits, family mismatch, invalid prefixes, all five filter fields, overlapping priority conflicts, equal-priority input order and default deny. Integration tests parse UDP, allow port 53, deny port 443 and track only the permitted flow.

Flow tests cover refresh, creation/last-seen timestamps, exact timeout boundary, capacity rejection, entry reuse after expiry, zero limits, reverse directions, TCP/UDP separation, reversed clocks and u64 maximum time without overflow.

## Pending validation

Dedicated coverage reporting, true property-based generation, sustained parser fuzzing, performance benchmarks, cross-target builds and dependency audit automation are future work. No third-party runtime packages are present; review all future dependencies for advisories and license compatibility.

No Android device, VPN, leak, forwarding, battery, memory or performance comparison test has been run. Future physical-device matrix must include IPv4/IPv6/DNS leaks, VPN loss, always-on/lockdown, Wi-Fi/cellular switching, app identity/unknown identity, TCP/UDP reliability, long-running memory/stability and battery use. Record device/OS, commit, settings, traffic generator and observations. Never convert a planned check into a passing result.

## Core hardening follow-up

The current local stable suite contains 12 passing tests, including new configuration rejection and CIDR property coverage. The CIDR oracle checks every IPv4/IPv6 prefix against every single-bit address difference (17,568 comparisons total). Tests verify the exact rule cap, stricter custom limits, zero limits, attempts to exceed the hard ceiling and rejection of inverted source/destination ranges.

The isolated fuzz workspace adds address-sanitized raw packet testing with structural success invariants and truncation/appending rejection properties. See fuzz/README.md for commands and constraints. A bounded CI run is separate evidence from local stable tests; check the PR's actual Actions result. Benchmarking, checksum validation and broad property/fuzz coverage remain outstanding.

## Benchmark harness follow-up

Local verification: workspace fmt, Clippy with warnings denied, build and all 12 existing behavior tests passed; the workspace including netscope-bench also passed Rust 1.85 tests. The release smoke command executed all 31 cases with three measured samples plus warmup, producing 125 CSV lines including the header; the stdlib Python summarizer consumed that actual output successfully. No performance threshold was asserted. Full hosted-runner results must be read from the benchmark CI job, not inferred from this local smoke check. See BENCHMARKS.md for commands and limitations.
