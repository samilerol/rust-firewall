# Decisions

- ADR-001: Three small crates, no third-party runtime dependencies. Keep engine portable; defer Android/UI/privileged code until transport contracts are designed.
- ADR-002: Strict one-datagram input, no trailing bytes. Conservatively reject IPv4 options/fragments and IPv6 extension headers; do not claim checksum validation or reassembly.
- ADR-003: Lower numeric rule priority wins, then original input order. Return provenance and require explicit default action. O(R) scan avoids premature indexing.
- ADR-004: Directional flow observations, configured entry cap and monotonic u64 ticks. O(F) expiry is simple and testable; benchmark before optimizing. No TCP state-machine claim or implicit flow authorization.
- ADR-005: Stable Rust with tested MSRV 1.85; forbid unsafe. std-only implementation and committed lockfile reduce supply-chain exposure.
- ADR-006: Public standard Ubuntu Actions runners, independent bounded checks, SHA-pinned actions, read-only permissions. No Android SDK in milestone 1.
