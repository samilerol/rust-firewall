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

The isolated fuzz workspace adds address-sanitized raw packet testing with structural success invariants and truncation/appending rejection properties. See fuzz/README.md for commands and constraints. A bounded CI run is separate evidence from local stable tests; check the PR's actual Actions result. At that checkpoint, benchmarking/checksums were pending; subsequent sections record their implementation. Broad property/fuzz coverage remains ongoing.

## Benchmark harness follow-up

Local verification: workspace fmt, Clippy with warnings denied, build and all 12 existing behavior tests passed; the workspace including netscope-bench also passed Rust 1.85 tests. The release smoke command executed all 31 cases with three measured samples plus warmup, producing 125 CSV lines including the header; the stdlib Python summarizer consumed that actual output successfully. No performance threshold was asserted. Full hosted-runner results must be read from the benchmark CI job, not inferred from this local smoke check. See BENCHMARKS.md for commands and limitations.

## Explicit checksum follow-up

Local stable checks (fmt, Clippy with warnings denied, tests, build) passed with 21 tests total. Rust 1.85 checks passed as well. Nine new integration tests cover independently generated IPv4/IPv6 TCP/UDP vectors with empty/odd/even payloads; TCP options; maximum supported IPv4 TCP and IPv6 UDP lengths; every single-bit transport mutation on small vectors; IPv4 header corruption; IPv4/IPv6 pseudo-header address changes; IPv6 hop-limit exclusion; explicit IPv4 UDP omission; IPv6 zero-checksum rejection; valid TCP zero and UDP 0xffff representation; structural errors before checksum checks. The deterministic arbitrary-byte test now calls both checksum policies.

`python3 tools/generate_checksum_fixtures.py` uses a separate Python big-integer checksum oracle, anchored by the RFC 1071 0x220d example, to reproduce committed fixtures. The normal CI test job regenerates them and requires no diff. The fuzz target calls both policies and checks checked/metadata consistency, with checksum-valid/invalid fixtures and maximum-length datagrams added to its seeds. Actual current-head fuzz/CI outcomes must be read from the run, not inferred from these local results. No offload/device validation or checked-path benchmark result is claimed.

## Android diagnostic follow-up

Local stable fmt, Clippy, build and 22 Rust tests passed. Rust 1.85 tests also passed. This environment has a Java runtime but no javac/Android SDK, so the Java/native smoke and APK build were not executed locally. CI must run tools/JniSmoke.java with -Xcheck:jni against the host cdylib (nine real JNI contract checks: valid packet, truncated input, invalid bounds, null array, oversize capacity, pooled-buffer prefix and corruption), then cross-compile ARM64/x86_64 and build/lint/package the diagnostic APK. Consult actual current-head CI results; creating this job does not prove it passed. No emulator/physical-device lifecycle, routing/leak, battery, UI or stability test has run.

## Portable engine/UDP follow-up

Local stable fmt, Clippy with warnings denied, workspace tests/build and Rust 1.85 tests passed initially with 42 tests; an additional partial/full-drain callback regression test brings the current suite to 43 tests. Tests include a 20,000-operation conntrack reference comparison, 2,048 policy decisions against the old precedence oracle, one-index-record invariants, response association/current inbound policy, transactional updates, capacity/time/reset failures and independent UDP checksum vectors. Nine real UDP socket tests use IPv4/IPv6 loopback only: echo/reply encoding, no sends on denial/failed protection, empty payloads, socket reuse, limit/expiry/reset/policy changes and oversized reply drops. No external server or device was used.

Stateful engine and packet/serializer fuzz targets have separate 30-second CI budgets; the engine target never opens a socket. The 31-case local release smoke run and Python summary succeeded. Current-head hosted fuzz, reference comparison and normal CI require actual result inspection before reporting pass. Android source/UI was not modified; any existing Android CI run is regression build evidence only.

## Classic DNS follow-up

Local normal checks and Rust 1.85 tests passed with 60 tests total: 11 new parser/policy tests and six new DNS relay tests (including actual IPv4/IPv6 loopback, denial before socket allocation, malformed/mismatched/unsolicited replies, different ID/name/type/class, identical retransmissions, bounded Busy state, expiry/reset/filter changes and domain allow not overriding packet deny). Compression cycles/forward/header pointers, jump limits, expanded names, ASCII/IDNA boundaries, flags/counts/truncation, EDNS option budgets and selected RDATA checks are covered. No external resolver was contacted.

Release smoke successfully exercised 37 benchmark cases (149 CSV lines including header/warmup) and the Python summary. A pure DNS fuzz target and four structural seeds were added; actual current-head fuzz/benchmark/CI outcomes require reading the run. No DNSSEC, DoH/DoT, TCP DNS, alias/rebinding or Android/device protection is claimed.
