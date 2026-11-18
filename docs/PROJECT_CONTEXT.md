# Project context

NetScope Rust NGFW aims to become a capable, evidence-tested open-source Android NGFW, later Linux/OpenWrt. This is an ambition, not a superiority claim. Public repo: samilerol/rust-firewall. Apache-2.0; zero-cost infrastructure preferred.

Architecture: at least 95% Rust where practical, security-critical logic in Rust, minimal Kotlin/Java VPNService/JNI bridge, evaluated Rust-native UI (egui is a candidate). Rootless VPNService and separate rooted kernel enforcement will share a portable engine. Core functionality must remain private, offline, account-free, analytics-free and free/open-source.

Codex Cloud handles implementation and focused checks. Standard public GitHub Actions runners handle independent builds/tests and later bounded Android/fuzzing jobs. CI is not an autonomous AI developer; someone must inspect failures and apply fixes. Runner RAM is not available to the interactive environment. No paid infrastructure without explicit permission.

The private Kotlin project samilerol/netscope is entirely separate. Never modify it, expose it or copy its sources here.

Milestone 1 implements packet metadata, policy and bounded flow observations only. README and ROADMAP define actual and planned functionality. Future tasks must preserve this context and update decision/security/test documents with behavior changes.

Current platform milestone adds a deliberately traffic-blocking Android diagnostic VPN and JNI bridge, documented in ANDROID_INTEGRATION.md. This is not forwarding or proven Android protection; device tests and transport selection are still required.

Owner direction: pause APK/UI work and prioritize the portable software. Engine/UDP relay, optimized bounded expiry and compiled policy precedence are documented in ENGINE_TRANSPORT.md; the Android diagnostic is not wired to the new relay. Experimental portable TCP relay is now implemented; its scope/limits are in TCP_TRANSPORT.md. It is not integrated into Android.

Classic UDP DNS parsing and opt-in question-domain filtering now extend the portable relay; limits/correlation/scope are in DNS_POLICY.md. The separate opt-in classic TCP DNS guard is described in TCP_DNS.md. No encrypted DNS, alias-chain enforcement or DNSSEC validation exists.

DNS transactions now support bounded concurrent IDs per UDP flow and independent first-send expiration, documented in DNS_POLICY.md. Preserve the per-flow/global caps, one index record per query, atomic configuration and individual rejection of late/mismatched DNS replies. See CURRENT_STATUS.md when resuming; verify GitHub main/open PRs before assuming a local checkout is current.

TCP DNS now uses bounded complete frames, unique outstanding IDs and explicit per-flow/global limits with millisecond request/frame deadlines. Guard activation validates the extra frame-buffer budget; failures abort the affected TCP stream. UDP and TCP activation/counters are independent.
