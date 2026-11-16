# Agent instructions

Read README.md and docs/PROJECT_CONTEXT.md, ARCHITECTURE.md, SECURITY_MODEL.md, DECISIONS.md and ROADMAP.md before changes.

- Develop independently. Never access, change, expose or copy private `samilerol/netscope` code.
- Rust-first portable security core. Target 95% Rust where practical; correctness overrides percentage. Minimal Kotlin/Java only for Android APIs. Prefer evaluated Rust-native UI; Flutter requires owner approval.
- Stable Rust, MSRV 1.85. Workspace forbids unsafe. Justify any future unsafe boundary explicitly and test it.
- Treat packets/configuration as hostile. Check bounds and lengths before offsets. Bound state and queues; document rejection behavior and allocation costs.
- Keep policy ordering deterministic; never use conntrack presence as authorization.
- Implement needed modules only; no placeholder capability claims.
- Run cargo fmt --check, cargo clippy --workspace --all-targets -- -D warnings, cargo test --workspace and cargo build --workspace. Add meaningful regression tests for changed behavior. Record restrictions and actual CI results.
- Use focused feature branches and reviewable commits/PRs. Do not merge without instruction. Never claim checks passed without evidence.
- Keep interactive workloads light (8 GB workstation target). Heavy Android builds/fuzzing belong in bounded GitHub Actions jobs; do not create paid infrastructure.
- No analytics, mandatory accounts or uploaded browsing history. Core functions remain offline.
- Current owner priority: pause APK/UI work and advance portable software. Validate the engine/UDP transport and evaluate bounded TCP forwarding. Do not claim Android protection before integration/device tests.

- The Android adapter documents a single JNI export lint exception; the portable crates still forbid unsafe. Preserve FD ownership on Android, bounded array copies, no-allow diagnostic result contract, and cancellation before close. Never relabel the diagnostic as a forwarding firewall or claim device tests passed from APK builds.

- Read docs/ENGINE_TRANSPORT.md for current admission, response authorization, expiry-index, socket-protection and reset contracts. No implicit reverse-flow allow; no socket connect/send before protection succeeds. Keep one expiry record per flow, bounded sockets/buffers, and preserve original rule indices after precedence compilation.
