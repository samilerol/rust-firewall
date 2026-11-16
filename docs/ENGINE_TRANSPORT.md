# Portable engine and UDP relay

## Current scope

The Rust libraries now provide a functional checked-packet engine and synchronous/nonblocking UDP relay. They are independent of JNI, TUN, UI and Android lifecycle. TCP parsing/policy admission still exists, but **no TCP forwarding/state machine** exists. The Android diagnostic remains unchanged and does not use this relay. APK/UI work is paused by owner preference; advance/test the portable software first.

## Engine contract

`netscope-engine::Engine` combines strict checksum parsing, current immutable policy and bounded directional flow observations. `Config` requires explicit flow cap, tick timeout and checksum policy. Maximum engine cap is 65,536; zero capacity or zero timeout deliberately denies new admissions. Every datagram is re-parsed and re-evaluated; observing an existing flow is not authorization. Monotonic time reversal rejects without changing flows. Expiry may still occur when malformed input arrives at a later valid timestamp.

`Outcome::Accepted` means admitted by these library checks, **not delivered to a network** or TCP-state-valid. Drops identify malformed input, current policy, capacity, reversed clock or unmatched response. Aggregate saturating counters contain no traffic history; accepted counts include admissions whose subsequent socket I/O fails and authorized responses. Relay prechecks are not all included in engine counters; these are not end-to-end delivery metrics.

A response must match the exact reverse tuple of a still-active original flow and receive its own current directional policy allow. It never creates/refreshes an extra reverse observation. Successful policy updates validate the whole replacement before switching and revoke all old observations; invalid updates retain the previous policy/state. Network reset clears state but preserves monotonic-clock validation. No external JSON/TOML configuration parser or byte-size loader exists.

## Expiry and rule precedence

Conntrack uses a HashMap plus BTreeSet `(last_seen, flow_id)` with exactly one index record per active flow. No stale heap entries/event queue accumulate on refresh. No-expiry checks inspect the oldest timestamp; changed-timestamp refresh/insertion is O(log F), expiry is O(E log F) for E due entries, and same-timestamp refresh avoids index mutation. This trades bounded extra O(F) memory and potentially slower bulk drains for avoiding an O(F) scan on every packet. Timestamps use subtraction, not overflow-prone absolute deadlines. Remove/clear update both structures.

Policy validates original input first, then compiles rules in `(priority, original_index)` order. It stops at the first matching compiled rule while retaining original index in decisions/errors. Construction is O(R log R), evaluation remains O(R) worst-case but can stop early. Default and equal-priority behavior are unchanged. Differential tests compare both optimized structures to their original linear reference behavior.

## UDP lifecycle

`UdpRelay<P: SocketProtector>` requires a caller-supplied platform protection hook; the crate provides no default/no-op implementation. For a new admitted flow it binds a fresh UDP socket, invokes protection, then connects and sends. Binding allocates a local endpoint but no upstream datagram is sent before the callback succeeds. On Android the trusted hook must call VpnService.protect on the upstream socket and reject false/errors. **That Android hook is not implemented here.** Loopback tests use an explicit test protector, not VPN enforcement evidence.

One connected nonblocking UDP socket corresponds to each original five-tuple. The OS chooses a local ephemeral port: this is user-space UDP proxying, not source-address/port preservation. Connections are limited to a caller cap <=1024. Invalid/checksum/policy/capacity inputs are rejected before opening sockets. Open/protection/connect/send failure releases the observation/socket; a successful send returns the original FlowId and payload-byte count. WouldBlock is surfaced, without a hidden retry queue.

Receive is caller-driven per FlowId; connected sockets filter the remote tuple. The relay builds a complete reverse IPv4/IPv6 UDP datagram with checksums, then requires original-flow association plus a current inbound rule. Outbound allow does not imply inbound allow; directional default-deny profiles need explicit response rules. Rejected responses close that mapping. Checksums/connected tuples are not cryptographic peer authentication.

The reusable receive buffer is 65,528 bytes, enough to detect unsupported non-jumbo UDP sizes rather than silently accepting a truncated maximum datagram. Output allocation is bounded by the configured MTU (1280..65,575). Oversized requests/responses are rejected, not fragmented; no ICMP Packet Too Big/error synthesis exists. Empty UDP payloads are supported. Application-held returned Vecs, OS socket receive buffers and allocator overhead are outside an exact byte-budget guarantee; the socket count is bounded but kernel buffering varies by OS.

Outbound activity refreshes the original flow. Responses deliberately do not extend its outbound-idle timeout. The caller must invoke expire(now) periodically while idle; sends/receives also expire due flows and synchronously close their sockets. No background scheduler is supplied. A valid policy update or explicit network reset closes all mappings; the caller must signal network changes. Invalid policy updates leave active sockets/policy intact. No automatic OS network observer exists.

Supported endpoints are nonzero-port unicast destinations with explicit policy permission. Unspecified, multicast, limited broadcast, IPv4-mapped IPv6 aliases and IPv6 link-local destinations without scope are rejected; alias rejection avoids implicit OS family/address reinterpretation. Loopback is intentionally allowed for explicit policies/tests. Interface-scoped routing, directed-broadcast classification, multicast and IPv6 scope identifiers need future platform design.

## Validation and next work

Local tests execute real IPv4 and IPv6 loopback echo, no external hosts. They exercise checked replies, empty datagrams, socket reuse, denied traffic, failed protection/no send, capacity, exact expiry, transactional policy changes, network resets, response policy and MTU rejection. This does not prove Android routing, leak prevention, WAN reliability or battery behavior.

A pure stateful fuzz target varies packet admissions, clocks, policy replacement and resets without opening sockets. A separate parser target now exercises serializer/checksum round trips. Each target has a bounded 30-second sanitizer CI smoke budget. CI compares the unchanged 31-case benchmark harness against immutable pre-optimization commit eade0426c803aabb59cd4626718143c75287324a on the same runner/toolchain. Bulk expiry/memory tradeoffs and hosted-runner noise must be reported alongside improvements; no fixed speed threshold or Android claim is made.

Next: select a maintained Rust TCP/IP implementation after security/license/MSRV review; add TCP stream lifecycle, bounded per-flow/global buffers, backpressure and retransmission/device tests. Add UDP readiness multiplexing, explicit application/network identity policies, safe serialized configuration limits, DNS/domain policy and protected upstream socket integration. Do not treat this UDP relay as complete NGFW/TCP functionality.
