# Project context

NetScope Rust NGFW aims to become a capable, evidence-tested open-source Android NGFW, later Linux/OpenWrt. This is an ambition, not a superiority claim. Public repo: samilerol/rust-firewall. Apache-2.0; zero-cost infrastructure preferred.

Architecture: at least 95% Rust where practical, security-critical logic in Rust, minimal Kotlin/Java VPNService/JNI bridge, evaluated Rust-native UI (egui is a candidate). Rootless VPNService and separate rooted kernel enforcement will share a portable engine. Core functionality must remain private, offline, account-free, analytics-free and free/open-source.

Codex Cloud handles implementation and focused checks. Standard public GitHub Actions runners handle independent builds/tests and later bounded Android/fuzzing jobs. CI is not an autonomous AI developer; someone must inspect failures and apply fixes. Runner RAM is not available to the interactive environment. No paid infrastructure without explicit permission.

The private Kotlin project samilerol/netscope is entirely separate. Never modify it, expose it or copy its sources here.

Milestone 1 implements packet metadata, policy and bounded flow observations only. README and ROADMAP define actual and planned functionality. Future tasks must preserve this context and update decision/security/test documents with behavior changes.

Current platform milestone adds a deliberately traffic-blocking Android diagnostic VPN and JNI bridge, documented in ANDROID_INTEGRATION.md. This is not forwarding or proven Android protection; device tests and transport selection are still required.
