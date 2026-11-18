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

Implemented: optimized one-record expiry index, compiled precedence, checked Engine and bounded IPv4/IPv6 UDP relay with loopback tests. Android diagnostic is unchanged and not wired to it. Done since: TCP stack selection and lifecycle, readiness hooks and a safe poll wait, uid/network policy context, bounded policy configuration, handshake/per-uid quotas, concurrent UDP DNS questions and DNS over TCP on selected ports. Remaining portable work: byte/rate fairness, epoll if measurements justify it, long-running/loss/reorder tests, alias/rebinding and richer DNS policy, and platform integration. Keep device integration/production claims gated on actual device evidence.

Classic UDP question parsing/domain policy is implemented with explicit scope in DNS_POLICY.md. Concurrent transactions with independent expiry and DNS over TCP on selected ports now exist. Next DNS work: evaluated alias/rebinding policies and secure resolver/authentication designs. No encrypted-DNS visibility should be assumed.

Experimental TCP relay is implemented with explicit scope in TCP_TRANSPORT.md. Readiness hooks, handshake/per-uid quotas, TCP DNS framing, uid/network context and bounded configuration are implemented; see the status paragraph above for what remains. APK/UI/platform integration remains paused; no device or WAN guarantees are inferred.
