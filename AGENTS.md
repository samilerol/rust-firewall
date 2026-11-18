# Agent instructions

Read docs/CURRENT_STATUS.md, README.md and docs/PROJECT_CONTEXT.md, ARCHITECTURE.md, SECURITY_MODEL.md, DECISIONS.md and ROADMAP.md before changes.

- Develop independently. Never change, expose or copy private `samilerol/netscope` code. Owner exception (2026-11-18): netscope may be read **only** to build a feature/behavior inventory (what it does, UI features, user-visible behavior) so features can be re-implemented in Rust here. Record the inventory in own words in `docs/`; never paste or translate netscope engine code, identifiers, assets or secrets into this repository, and never write to netscope. The original Dart/Flutter UI is not ported; menus and behavior are re-implemented in Rust from the inventory.
- Rust-first portable security core. Target 95% Rust where practical; correctness overrides percentage. Minimal Kotlin/Java only for Android APIs. UI: the owner decided (2026-11-18, superseding an earlier Flutter approval) that the whole product, including the UI, is written in Rust with the original app's menus (Dashboard, Connections, Apps, Captures, Settings). Rust-native UI on Android is unevaluated: run a small spike first, and ask before adding any UI/windowing dependency.
- Stable Rust, MSRV 1.85. Workspace forbids unsafe. Justify any future unsafe boundary explicitly and test it.
- Treat packets/configuration as hostile. Check bounds and lengths before offsets. Bound state and queues; document rejection behavior and allocation costs.
- Keep policy ordering deterministic; never use conntrack presence as authorization.
- Implement needed modules only; no placeholder capability claims.
- Run cargo fmt --check, cargo clippy --workspace --all-targets -- -D warnings, cargo test --workspace and cargo build --workspace. Add meaningful regression tests for changed behavior. Record restrictions and actual CI results.
- Use focused feature branches and reviewable commits/PRs. Do not merge without instruction. Never claim checks passed without evidence.
- Keep interactive workloads light (8 GB workstation target). Heavy Android builds/fuzzing belong in bounded GitHub Actions jobs; do not create paid infrastructure.
- No analytics, mandatory accounts or uploaded browsing history. Core functions remain offline. Owner decision (2026-11-18): optional, user-initiated blocklist downloads are allowed (https only, no identifiers, nothing sent except the request, off by default, failures keep the previous list); background/automatic updates only behind an explicit opt-in switch.
- Current owner priority: pause APK/UI work and advance portable software. Validate the engine/UDP transport and evaluate bounded TCP forwarding. Do not claim Android protection before integration/device tests.

- The Android adapter documents a single JNI export lint exception; the portable crates still forbid unsafe. Preserve FD ownership on Android, bounded array copies, no-allow diagnostic result contract, and cancellation before close. Never relabel the diagnostic as a forwarding firewall or claim device tests passed from APK builds.

- Read docs/ENGINE_TRANSPORT.md for current admission, response authorization, expiry-index, socket-protection and reset contracts. No implicit reverse-flow allow; no socket connect/send before protection succeeds. Keep one expiry record per flow, bounded sockets/buffers, and preserve original rule indices after precedence compilation.

- Read docs/DNS_POLICY.md before DNS changes. Preserve bounded compression/message/record work, label-boundary matching, ID/question correlation, explicit port activation, no domain-allow override of packet policy, and pending-state cleanup. Never relabel question-only filtering as encrypted DNS, alias-chain or DNSSEC protection.

- Read docs/TCP_TRANSPORT.md and docs/TCP_DNS.md before TCP changes. Require accepted initial SYN before upstream creation and protection before connect. Preserve bounded queues/partial-write consumption, half-close/RST/TIME-WAIT behavior, inbound policy checks and microsecond-safe clocks. TCP DNS filtering requires explicit guard activation; it and generic TCP imply no encrypted-DNS or device guarantee. Dependency advisory/license/source checks must pass for new runtime dependencies.
