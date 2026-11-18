# Feature parity with the original NetScope app

Status: planning inventory, 2026-11-18. Written in the owner's own words from the original app's public-facing README and user guide (read-only access under the owner exception in AGENTS.md). No code, identifiers, assets or secrets from that project are used here. Features are re-implemented independently in Rust; the original is a Flutter UI over a Kotlin traffic engine and targets rootless Android only (Linux/OpenWrt/DD-WRT are not goals).

"Here today" reflects this repository's documents as of this date, not device evidence. Nothing below is a protection claim; device validation is tracked in ROADMAP.md.

| # | Original feature (user-visible behavior) | Here today | Gap / decision needed |
|---|---|---|---|
| 1 | Live dashboard: throughput, connection counters, top apps and addresses | Traffic report (bounded, in-memory) | Live graph and top-N views are not implemented |
| 2 | Connection list with app, domain, protocol (DNS/HTTP/TLS/QUIC), state, search/filter; detail shows block reason and first 1 KB | Not implemented | Needs protocol/SNI classification (ROADMAP item 5) and a bounded per-connection log. Privacy limits: no persistence by default |
| 3 | TLS SNI domain extraction | Not implemented | ROADMAP item 5, explicit scope and budgets required |
| 4 | Per-app block, separately for Wi-Fi and mobile data | App blocklist exists (not per network) | Per-network policy is an open design item |
| 5 | Per-app block while screen is off (60 s delay, lifts on screen on) | Not implemented | New; needs screen-state signal and a bounded timer |
| 6 | Block newly installed apps until allowed | Not implemented | New; needs install-event handling and default-deny for new UIDs |
| 7 | Domain blocking with subdomains; blocked DNS answered NXDOMAIN; cut TCP/QUIC to the already-known IP of a blocked domain | DNS question filtering with label-boundary matching exists | NXDOMAIN synthesis and IP-based follow-up cutting are not implemented; QUIC is currently dropped by the fixed profile |
| 8 | Blocklist subscriptions (hosts/domain lists), suggestions, optional weekly auto-update, allow-list override | Not implemented | Conflicts with "core remains offline" unless made explicit, opt-in and user-initiated; owner decision |
| 9 | Ordered IP/port rules (app, protocol, CIDR, port range), first match allows or denies | Deterministic policy with CIDR/port rules and bounded policy files (PRs #29, #30) | App dimension and user-facing editor missing |
| 10 | Decision order: rules, then app block (by network/screen), then domain lists | Not defined | Define and document precedence before wiring the pieces |
| 11 | Existing connections cut when a block is added | Not specified | Needs flow revocation on policy change (engine has atomic replacement; verify revocation of live flows) |
| 12 | PCAP capture, share, delete | Not implemented | ROADMAP item 7; user-controlled retention |
| 13 | IPv6 capture and blocking | Supported in the portable core; upstream IPv6 untested on a device | Device test |
| 14 | Self-resource card (CPU, RAM, flow count, busiest threads) | Performance screen (CPU, PSS, device memory) | Flow count and thread breakdown missing |
| 15 | Protection status card, Always-on/lockdown guidance | Documented limits only | Needs OS-supported always-on handling and device tests |
| 16 | App lock (device credential on open and after 30 s in background) | Not implemented | New; independent of VPN protection |
| 17 | Battery-optimization exemption prompt | Not implemented | New; OEM background kill is a real risk on Xiaomi |
| 18 | UI language Turkish | English strings | Localization decision |
| 19 | Flutter UI | Temporary framework Java screens | AGENTS.md: Rust-native UI preferred, Flutter requires owner approval. Owner decision |

## Suggested order

1. Define the decision-order contract (item 10) and per-network/screen-state policy inputs (4, 5): they shape the engine API.
2. Flow revocation on policy change (11) and NXDOMAIN synthesis (7).
3. Connection log with bounded memory and block reasons (1, 2, 3), then PCAP (12).
4. New-app default-deny (6), blocklists as explicit opt-in (8).
5. Always-on/lockdown, battery exemption, app lock (15, 16, 17), then the UI direction decision (19).

Each step is a small PR with tests. Device evidence is required before any claim.
