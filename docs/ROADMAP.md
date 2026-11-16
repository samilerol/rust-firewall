# Roadmap

1. Portable core: safe IP/TCP/UDP metadata parser, deterministic policy, bounded flow observations, tests and CI (implemented; validation evidence is in TEST_PLAN).
2. Harden the portable boundary: cargo-fuzz harnesses, property tests, checksum validation decisions, configuration limits and reproducible parser/policy/flow benchmarks. Define acceptance thresholds from measurements, not Rust assumptions.
3. Android design spike: evaluate maintained TCP/UDP forwarding libraries and licenses, JNI ownership, VPNService TUN lifecycle, socket protection, explicit unknown-UID policy, per-network policy, attribution restrictions, foreground services and Rust-native UI. No silent bypass; define enforceable failure behavior before shipping.
4. Android MVP: forwarding and policy integration, physical-device IPv4/IPv6/DNS/disconnect/network-transition tests, always-on and lockdown compatibility. Ship only after measured evidence.
5. DNS/domain policy, privacy-bounded TLS/HTTP/QUIC classification and encrypted-transport limitations; no unauthorized TLS interception.
6. Rooted adapter with actual kernel capability checks, rollback/recovery; reusable Linux/OpenWrt adapters.
7. Threat updates, IDS/IPS with explainable confidence/false-positive controls, PCAP export with user retention/privacy controls.

Compare performance against NetGuard, RethinkDNS and PCAPdroid on comparable devices and workloads before publishing claims. Extended fuzzing, dependency/license checks, coverage and Android builds will run as separately bounded CI jobs when introduced.
