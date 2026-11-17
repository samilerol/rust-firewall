# Resume here

Updated: 2026-11-17. Public project: `samilerol/rust-firewall` only. Never access/copy the separate private `samilerol/netscope` repository.

## Owner direction

Advance the portable software first. APK/UI work is paused. Emulator testing comes after the software stages, followed by real-device testing; neither has been performed. Continue from repository evidence rather than restarting the project from old chat summaries.

## Baseline and current change

This work started from main `2a1772c` (PR #23 merged). Main already contains the portable checked engine, protected UDP relay, experimental bounded TCP relay, opt-in classic UDP DNS question filtering, and Android JNI/session/socket-protection diagnostic work. Android live ingress remains deny-only: this is not a forwarding Android firewall.

PR #24 (`feat/dns-concurrent-transactions`, head `ed563a7`) adds bounded concurrent UDP DNS IDs, independent first-send expiry, budgets and individual late-reply rejection. All 10 hosted checks passed. At the start of the TCP work it remained open/unmerged; verify its current GitHub state.

Branch `feat/tcp-dns-guard` builds on PR #24 and adds opt-in classic TCP DNS complete-frame validation, bounded pipeline IDs, independent millisecond query/frame deadlines, and guarded-flow payload budget checks. See TCP_DNS.md and ADR-021. Its PR targets the PR #24 branch so only the TCP change is reviewed; neither PR is automatically merged. Main is not claimed to contain these feature changes.

Local TCP-guard validation: workspace and fuzz fmt, workspace/feature Clippy, workspace build, 98 workspace tests on stable and Rust 1.85, and 51 transport fuzzing-feature tests passed. The TCP fuzz target now additionally exercises pure frame/transaction validation and partial I/O schedules without OS sockets. Actual hosted results live on the feature PR. IPv4/IPv6 loopback and APK/host-JVM results remain host/build evidence only; no emulator/device tests were performed.

## Continue safely

1. Inspect current GitHub main, open PRs and their head commit/check results. Check local branch/status before changing anything. Do not recreate already merged work.
2. Finish review/CI for the DNS feature branches and preserve their dependency order before starting another dependent change. Do not merge without owner instruction.
3. Next portable priorities: bounded readiness/fairness scheduling, supported identity/network context and bounded external configuration. Classic TCP/UDP DNS now has explicit opt-in question filtering; broader DNS interoperability and alias/rebinding/resolver-authentication designs remain future work. Preserve partial reads/writes, stream backpressure and protocol limits.
4. Platform forwarding integration and later emulator/device tests remain separate milestones. APK compilation, cross-compilation, host JVM and loopback tests do not prove VPN routing, leak prevention or battery behavior.

No paid infrastructure, telemetry or persistent DNS history is authorized. Keep focused branches and durable documentation up to date.
