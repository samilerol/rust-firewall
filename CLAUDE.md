# CLAUDE.md

Read `AGENTS.md` and `docs/` first; this file adds working rules and does not replace them.

## Project overview

Rust workspace for an offline, privacy-first Android firewall core (Apache-2.0, MSRV 1.85, `unsafe_code = "forbid"`).

- `netscope-packet`: allocation-free IPv4/IPv6 TCP/UDP parsing and optional checksum validation.
- `netscope-policy`: CIDR/protocol/port rules with deterministic priority.
- `netscope-conntrack`: bounded flow observations with expiry.
- `netscope-engine`: checked admission, bounded flows, atomic policy replacement.
- `netscope-transport`: UDP relay and experimental smoltcp TCP relay.
- `netscope-dns`: bounded classic DNS question parsing and domain rules.
- `netscope-android`: single JNI bridge (diagnostic, drop-all); `android/` holds the minimal Java shell.
- `tools/core-bench`, `fuzz/`: benchmarks and fuzz targets.

## Commands

```sh
cargo build --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --check   # use `cargo fmt` to apply
```

IPv6 loopback tests skip themselves (with a message) when the environment has no IPv6 loopback; CI sets `NETSCOPE_REQUIRE_IPV6=1` so a missing loopback there fails instead of skipping. Report skips, do not hide them.

## Working rules

- Think before coding: state assumptions, name unclear points, ask when uncertain, and present alternatives instead of silently choosing one.
- Keep it simple: write the minimum that solves the request; no speculative features or abstractions.
- Make only the requested change; do not refactor or reformat unrelated code. Mention unrelated problems instead of fixing them.
- Before starting any work, `git fetch` and check open pull requests and `feat/*` branches for overlapping work (another agent or person may be changing the same area); build on the latest integration branch, keep branches short-lived and PRs small (about 400 lines), and never reimplement something an open PR already contains.
- Define the success criterion first (a failing test, a command that must pass) and verify it before claiming completion.

## Project-specific rules

- Do not use `unsafe`. If it seems necessary, ask first.
- Ask before adding a new crate or dependency.
- After every change, `cargo fmt --check`, `cargo clippy ... -D warnings` and `cargo test --workspace` must pass. Report real results; never claim a check passed without running it.
- Never copy code from the private `samilerol/netscope` repository into this one. Read-only access is allowed solely for a feature inventory (see AGENTS.md owner exception); features are re-implemented independently in Rust.
