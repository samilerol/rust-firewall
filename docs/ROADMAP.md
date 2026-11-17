# Roadmap

1. Portable core: safe IP/TCP/UDP metadata parser, deterministic policy, bounded flow observations, tests and CI (implemented; validation evidence is in TEST_PLAN).
2. Harden the portable boundary (rule limits, CIDR properties and parser fuzz harness added; benchmark harness added; explicit checksum API added; broader workloads remain): cargo-fuzz harnesses, property tests, checksum validation platform/offload decisions, configuration limits and reproducible parser/policy/flow benchmarks. Define acceptance thresholds from measurements, not Rust assumptions.
3. Android design spike (drop-all diagnostic service/JNI added; forwarding/UI/physical-device validation remain): evaluate maintained TCP/UDP forwarding libraries and licenses, JNI ownership, VPNService TUN lifecycle, socket protection, explicit unknown-UID policy, per-network policy, attribution restrictions, foreground services and Rust-native UI. No silent bypass; define enforceable failure behavior before shipping.
4. Android MVP: forwarding and policy integration, physical-device IPv4/IPv6/DNS/disconnect/network-transition tests, always-on and lockdown compatibility. Ship only after measured evidence.
5. DNS/domain policy, privacy-bounded TLS/HTTP/QUIC classification and encrypted-transport limitations; no unauthorized TLS interception.
6. Rooted adapter with actual kernel capability checks, rollback/recovery; reusable Linux/OpenWrt adapters.
7. Threat updates, IDS/IPS with explainable confidence/false-positive controls, PCAP export with user retention/privacy controls.

Compare performance against NetGuard, RethinkDNS and PCAPdroid on comparable devices and workloads before publishing claims. Extended fuzzing, dependency/license checks, coverage and Android builds will run as separately bounded CI jobs when introduced.

## Active software track (APK/UI paused)

Implemented: optimized one-record expiry index, compiled precedence, checked Engine and bounded IPv4/IPv6 UDP relay with loopback tests. Android diagnostic is unchanged and not wired to it. Next priorities: maintained TCP stack selection and stream lifecycle/backpressure; readiness scheduling and transport byte budgets; supported identity/network policy context; bounded serialized config; DNS/domain inspection. Keep device integration/production claims gated on actual device evidence.

Classic UDP question parsing/domain policy is implemented with explicit scope in DNS_POLICY.md. Bounded concurrent transactions and independent first-send expiry are implemented. Next DNS work: TCP DNS framing/stream policy, evaluated alias/rebinding policies and secure resolver/authentication designs. No encrypted-DNS visibility should be assumed.

Experimental TCP relay is implemented with explicit scope in TCP_TRANSPORT.md. Next portable priorities are bounded readiness scheduling, handshake/fairness limits, TCP DNS framing, richer identity/network context and bounded external configuration. APK/UI/platform integration remains paused; no device or WAN guarantees are inferred.
