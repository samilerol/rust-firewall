# Decisions

- ADR-001: Three small crates, no third-party runtime dependencies. Keep engine portable; defer Android/UI/privileged code until transport contracts are designed.
- ADR-002: Strict one-datagram input, no trailing bytes. Conservatively reject IPv4 options/fragments and IPv6 extension headers; do not claim checksum validation or reassembly.
- ADR-003: Lower numeric rule priority wins, then original input order. Return provenance and require explicit default action. O(R) scan avoids premature indexing.
- ADR-004: Directional flow observations, configured entry cap and monotonic u64 ticks. O(F) expiry is simple and testable; benchmark before optimizing. No TCP state-machine claim or implicit flow authorization.
- ADR-005: Stable Rust with tested MSRV 1.85; forbid unsafe. std-only implementation and committed lockfile reduce supply-chain exposure.
- ADR-006: Public standard Ubuntu Actions runners, independent bounded checks, SHA-pinned actions, read-only permissions. No Android SDK in milestone 1.

- ADR-007: Reject the entire policy on excess rules or inverted port ranges. `Policy::new` is now fallible; 4096 is a conservative engineering ceiling, not a measured latency guarantee. Smaller caller limits are supported; external file byte limits remain future work.
- ADR-008: Isolate fuzz-only dependencies and nightly from the stable/MSRV core workspace. Retain a fuzz lockfile and deterministic structural seeds. Use bounded address-sanitized CI smoke testing; core code continues to forbid unsafe. Exhaustive CIDR prefix/bit properties use independent mask oracles without adding a property-testing runtime dependency.
