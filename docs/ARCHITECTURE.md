# Architecture

Milestone 1 has three crates. Packet parsing returns owned fixed-size metadata without allocating; policy consumes that metadata and returns an action plus original matched-rule index; conntrack optionally records a directional flow after policy allows it. Each packet must be reevaluated against the current policy. Reverse traffic needs an explicit policy; tracking does not grant access.

Policy validates original input then sorts immutable rules by (priority, original index), stopping at the first match. Worst-case evaluation is O(R); decisions retain original indices. CIDR host bits are ignored by comparison, and address families never cross-match. Policy construction rejects inverted port ranges and more than 4096 rules (or a smaller caller-provided limit). Construction is fallible; reject the entire update on error and retain the previously valid policy. Input Vec allocation happens before validation, so byte/record limits are still required in a future external configuration loader.

Tracking uses a HashMap, limited by configured maximum entries; Rust allocator overhead means this is an entry bound, not a byte bound. A BTreeSet last-seen index keeps one record per flow. Observations inspect the oldest time and remove only due entries in O(E log F); changed-time updates/inserts cost O(log F), with no stale queue records. Caller-supplied ticks must be monotonic, in one consistent unit. Capacity/zero-timeout errors require caller handling, never implicit allow. Queries reflect the last expire/observe call; callers must expire before querying current liveness. This is not TCP validation, NAT, stream reassembly or UDP forwarding.

Diagnostic implemented: minimal Java VPNService owns/reads TUN -> bounded Rust JNI inspection -> strict parser/default-deny policy; all read datagrams are discarded. Future: protected socket bridge -> explicit transport -> OS sockets. Socket protection must precede forwarding to avoid VPN loops. The UI and Android APIs stay outside these crates. The DNS crate is now implemented for bounded classic UDP question filtering; DPI, threat, IDS, platform, Linux and Rust-native UI crates remain future targets.

Rootless mode is constrained by Android's VPN lifecycle and competing VPN apps. Rooted mode is a separate future adapter evaluating nftables/iptables/netfilter/eBPF against actual kernel support, with privilege checks, atomic apply, rollback and safe restoration. No kernel changes occur in milestone 1.

`tools/core-bench` is a development-only fourth workspace package, using the three core libraries without changing their APIs. Its work is bounded by fixed sample counts and input sizes. See BENCHMARKS.md for measurement boundaries.

The packet crate additionally exposes parse_checked with explicit Require/AllowIpv4UdpOmission policy and Verified/OmittedIpv4Udp result status. It first calls the structural parser, then validates header/pseudo-header/transport sums without allocation. This keeps offload/UDP omission choices at the platform boundary instead of silently changing all metadata callers.

The platform adapter and Android project are described in ANDROID_INTEGRATION.md. Descriptor ownership stays in one Java reader; JNI receives bounded bytes only. The temporary platform consent screen is distinct from the future Rust-native product UI.

The netscope-engine and netscope-transport crates implement checked admission and bounded nonblocking UDP socket relay. See ENGINE_TRANSPORT.md for response authorization, transactional policy revocation, endpoint/MTU restrictions and protection-before-connect. UDP/admission use std/internal workspace dependencies; the TCP module adds the pinned dependencies reviewed in TCP_TRANSPORT.md. Experimental TCP forwarding is implemented by a separate bounded module; platform event loops, Android socket protection and production UI remain separate work.

The relay optionally calls netscope-dns for explicitly selected UDP ports, with one pending canonical question/ID per flow and current response-policy checks. DNS policy cannot grant IP permission. See DNS_POLICY.md for conservative parsing profiles, state revocation and bypass/encryption limitations.

TCP uses smoltcp for a virtual per-flow raw-IP TCP endpoint and a protected nonblocking OS TCP stream for upstream bytes. Accepted SYN precedes upstream creation; OS read/write buffers are bridged with bounded zero-extra-queue closures. See TCP_TRANSPORT.md for limits, dependency/MSRV choice, scheduling, teardown, half-close and unimplemented TCP DNS semantics.
