# Resume here

Updated: 2026-11-17. Public project: `samilerol/rust-firewall` only. Never access/copy the separate private `samilerol/netscope` repository.

## Owner direction

Advance the portable software first. APK/UI work is paused. Emulator testing comes after the software stages, followed by real-device testing; neither has been performed. Continue from repository evidence rather than restarting the project from old chat summaries.

## Baseline and current change

This work started from main `2a1772c` (PR #23 merged). Main already contains the portable checked engine, protected UDP relay, experimental bounded TCP relay, opt-in classic UDP DNS question filtering, and Android JNI/session/socket-protection diagnostic work. Android live ingress remains deny-only: this is not a forwarding Android firewall.

Branch `feat/dns-concurrent-transactions` adds bounded concurrent DNS IDs per UDP flow, independent first-send expiry, per-flow/global budgets, collision rejection, and individual rejection of late/mismatched responses. See DNS_POLICY.md and ADR-020. This is a feature-branch change awaiting review, not an assertion that it has merged into main. Use GitHub's current PR state to determine what is merged.

Validation for this change: local workspace tests, fmt, Clippy and workspace build passed. GitHub PR checks provide the independent hosted evidence; check their actual status before making claims. The DNS target also exercises a pure linear-reference transaction oracle, without sockets. IPv4/IPv6 loopback concurrency is host evidence only.

## Continue safely

1. Inspect current GitHub main, open PRs and their head commit/check results. Check local branch/status before changing anything. Do not recreate already merged work.
2. Finish review/CI for the DNS concurrency branch before starting another dependent change. Do not merge without owner instruction.
3. Next portable DNS milestone: bounded TCP DNS framing and question/response enforcement integrated with the existing TCP relay. Preserve partial reads/writes, stream backpressure and explicit protocol limitations. Other planned work includes readiness scheduling, identity/network context and bounded external configuration.
4. Platform forwarding integration and later emulator/device tests remain separate milestones. APK compilation, cross-compilation, host JVM and loopback tests do not prove VPN routing, leak prevention or battery behavior.

No paid infrastructure, telemetry or persistent DNS history is authorized. Keep focused branches and durable documentation up to date.
