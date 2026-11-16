# Decisions

- ADR-001: Three small crates, no third-party runtime dependencies. Keep engine portable; defer Android/UI/privileged code until transport contracts are designed.
- ADR-002: Strict one-datagram input, no trailing bytes. Conservatively reject IPv4 options/fragments and IPv6 extension headers; the original parser does not validate checksums or reassemble (optional checksum validation added by ADR-010).
- ADR-003: Lower numeric rule priority wins, then original input order. Return provenance and require explicit default action. O(R) scan avoids premature indexing.
- ADR-004: Directional flow observations, configured entry cap and monotonic u64 ticks. O(F) expiry is simple and testable; benchmark before optimizing. No TCP state-machine claim or implicit flow authorization.
- ADR-005: Stable Rust with tested MSRV 1.85; forbid unsafe. std-only implementation and committed lockfile reduce supply-chain exposure.
- ADR-006: Public standard Ubuntu Actions runners, independent bounded checks, SHA-pinned actions, read-only permissions. No Android SDK in milestone 1.

- ADR-007: Reject the entire policy on excess rules or inverted port ranges. `Policy::new` is now fallible; 4096 is a conservative engineering ceiling, not a measured latency guarantee. Smaller caller limits are supported; external file byte limits remain future work.
- ADR-008: Isolate fuzz-only dependencies and nightly from the stable/MSRV core workspace. Retain a fuzz lockfile and deterministic structural seeds. Use bounded address-sanitized CI smoke testing; core code continues to forbid unsafe. Exhaustive CIDR prefix/bit properties use independent mask oracles without adding a property-testing runtime dependency.

- ADR-009: Add a dependency-free release microbenchmark binary rather than nightly bench APIs or a framework dependency. Output raw per-sample CSV and preserve machine/toolchain context; exclude warmup from summaries. Include real expiry scans and allocation during insertion. No timing regression gate until variation is measured across repeated runs; no optimization is bundled with this baseline.

- ADR-010: Preserve metadata-only parse and add explicit parse_checked with checksum policy/result status. IPv4 UDP omission requires opt-in and is distinguishable from verified transport; IPv6 UDP zero-checksum tunnel exceptions remain unsupported. TCP zero checksums are validated normally. No automatic offload bypass; platform contract/device testing is required before strict TUN use. Independent Python big-integer fixtures and mutation tests validate the Rust folded-sum implementation.

- ADR-011: Implement an explicitly labelled drop-all diagnostic VPN before choosing a TCP/UDP transport. Java owns the TUN descriptor and its one reader; JNI handles bounded owned byte copies only. No raw FD crosses the bridge. Use a single symbol-export unsafe-lint exception in the adapter; core crates retain forbid. JVM smoke and ABI APK builds are required, while device tests remain separate. Disable always-on support and automatic restart for this diagnostic; no upstream sockets, no forwarding or implicit allow. The temporary Java Activity supplies platform consent/start/stop only, pending Rust-native UI evaluation.
