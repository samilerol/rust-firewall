# Experimental portable TCP relay

## Architecture and implemented boundary

`netscope_transport::tcp::TcpRelay` bridges raw IP/TCP datagrams to one protected, nonblocking OS TCP stream per original flow. It is a terminating TCP proxy: smoltcp handles the virtual-client handshake, sequence/ACK/retransmit/window/FIN state; the OS handles the independent upstream connection. Source ports/ISNs/timing are not preserved end-to-end, and a virtual handshake is not proof that the upstream application is ready. Stream bytes are opaque; there is no TLS interception or HTTP inspection.

This is library software with real host loopback coverage. No TUN/event-loop executable, automatic network observer, readiness multiplexer, JNI socket-protection implementation or Android integration is added. APK/UI remains paused; the existing diagnostic remains drop-all.

## Dependency choice and safety

smoltcp 0.12.0 is pinned with default features disabled and only std, medium-ip, IPv4, IPv6 and TCP sockets enabled. No DHCP/DNS/UDP/fragment reassembly/raw-socket/TUN driver is enabled in that dependency. It is 0BSD licensed and declares MSRV 1.80. Newer 0.13/0.14 declare Rust 1.91, incompatible with the repository's tested 1.85 workspace policy. This compatibility choice requires ongoing advisory/maintenance review; it is not a claim that the older branch is indefinitely supported. Revisit the MSRV rather than silently pinning around a future vulnerability.

socket2 0.6.5 (MIT/Apache-2.0, MSRV 1.70) creates/configures an unconnected socket safely so the platform can protect it before connect. getrandom 0.2.17 (MIT/Apache-2.0) obtains a fresh OS seed for each virtual TCP interface. A deterministic seed is used only by the separate in-memory fuzz/test harness. Seeds and TCP sequence checks are not cryptographic peer authentication. libc is used for the Unix EINPROGRESS constant. Dependency FFI/unsafe internals are outside the portable source's unsafe-forbid guarantee; no handwritten unsafe was added.

A targeted RustSec snapshot inspection at database revision 02e2517f457a359fc6d3440ea4560c8ea188fee8 found the known socket2 and heapless historical issues patched by the selected versions. Full runtime/fuzz advisory, license and registry-source checks are configured via deny.toml and cargo-deny 0.21.0 on CI stable Rust; local inspection is not equivalent to that CI passing, nor to a full source security audit.

## Caller API and ordering

1. Construct with an explicit packet Policy, Config and TcpSocketProtector. No default/no-op protector is provided.
2. Call ingest(full_ip_datagram, now_ms) for virtual-client input. Checksums, protocol/endpoint/profile, current packet rules, capacity and input-slot availability must pass. A new flow requires a payload-free pure SYN; first ACKs, Fast Open data, initial ECN flags, reserved/NS header bits, invalid options and an ignored SYN (e.g. zero MSS) are not accepted. The private stack must enter SYN-RECEIVED before any upstream socket opens. Entropy/stack initialization failures also precede upstream creation.
3. The new OS stream socket is nonblocking, has buffer-size hints and TCP_NODELAY, then the trusted platform hook runs. Only after successful protection does connect run, so even the upstream SYN follows protection. On Android this hook must call VpnService.protect and reject false/errors; it is not implemented here. Hooks must not retain socket clones, connect/send themselves, panic or block indefinitely.
4. Drive poll(now_ms) regularly. One pass performs at most one OS read/write per active flow, plus bounded stack RX/TX work. Socket WouldBlock/Interrupted preserves pending bytes. Partial writes dequeue only the accepted prefix. Zero-write/error, connect deadline and accepted peer RST stop the affected connection. OS errors and unobserved connect deadlines abort the virtual endpoint and queue a reset when possible.
5. Drain next_packet(now_ms) and deliver returned IP packets to the virtual client. Output is round-robin among flows and passes the current inbound policy and exact reverse-flow association at dequeue time. Outbound allow never implies inbound allow. A caller holding an already-returned Vec owns it; the relay cannot revoke that external copy.

A full output queue pauses smoltcp transmission/ingress processing. There is one additional ingress slot per flow; further packets return Backpressure before overwriting it. Callers must preserve/retry within their own bounded scheduler or accept TCP retransmission; no hidden queue or background task exists.

## Lifecycle and policy

FIN in either direction shuts down only that write half after its pending bytes drain. The other direction remains usable. Virtual TIME-WAIT is retained until stack closure or configured expiry. A valid client reset, including SYN-RECEIVED returning to LISTEN, immediately removes that flow/upstream; an out-of-window reset does not kill the connection. Normal completion may release the upstream before virtual TIME-WAIT ends.

A valid packet-policy update or explicit network reset closes all flows and discards queued packets; an invalid update retains state. Each discarded flow whose client connection is active (including SYN-RECEIVED) gets a RST through `next_packet`; these relay-generated RSTs carry no data and are not re-evaluated by inbound policy. At most `2 * max_flows` RSTs are queued and overflow is dropped, so that client falls back to its own timeout. The same RST is produced for idle expiry, a policy-denied reply (after the `Dropped` error) and a failed upstream setup (protection or connect error) on the client's SYN. Forced teardown requests abortive SO_LINGER=0 best-effort so kernel-queued data is not intentionally drained after revocation. This cannot undo bytes the OS already accepted/transmitted or guarantee identical linger semantics on every platform. Graceful completion is distinct. Do not retain clones in a platform hook.

Idle expiry follows policy-admitted outbound datagrams, not application payload progress; the stack also applies its configured idle timeout. Invalid checksum/header input never refreshes a lease, but this is not a per-app fairness or anti-SYN-flood system. The SYN-ACK is withheld (not emitted by `next_packet`) until `poll` observes the upstream connect as complete, so the client never sees an established connection the upstream refused: a refused or failed connect is answered with a RST instead, and the client's SYN retransmissions meanwhile only refill the bounded output slots. This adds up to one poll interval to connect latency. The absolute connect-observation deadline does not reset on retransmitted SYN. Callers must poll before that deadline: an unobserved connection can time out even if the OS completed it in the background. A client whose RST was dropped (queue overflow) or never drained may still time out; no RST is sent for flows already closed or in TIME-WAIT. PollReport counts current pump failures/timeouts and normal reaps, not every implicit expiry/reset.

Time is monotonic u64 milliseconds. smoltcp stores i64 microseconds; MAX_TIME_MS leaves two days of headroom below its representable boundary for configured timers. Excessive/backward time returns Clock before stack mutation. Timers are not hard real-time deadlines; scheduling is a caller obligation.

## Resource limits

- Max 64 active flows; zero flows explicitly disables new admissions.
- Raw-IP MTU 1280..1500; oversize input is rejected. IPv4 options/fragments and IPv6 extension headers remain unsupported by the front parser.
- Each stream direction reserves 1024..65536 bytes, one ingress packet slot and 1..16 output slots per flow.
- Config validates `max_flows * (2*buffer_bytes + (output_slots+1)*MTU)` against an explicit payload budget <=16 MiB before allocation. Allocator metadata, smoltcp metadata/assembler records, OS buffers and application-held returned packets are not included in this byte estimate. OS send/receive buffer settings are bounded hints, not exact kernel accounting.
- Connect deadline 1..30000 ms, idle timeout 1..86400000 ms and connect <= idle. The API does not spawn threads, allocate queues without a cap, or busy-wait internally. Poll cost is O(active flows); no readiness multiplexer is present.
- Device output tokens rely on smoltcp's MTU contract. An internal assertion rejects above-MTU output before allocation if the dependency breaks that contract; fuzz/host tests exercise it, without claiming a proof against all dependency bugs.

## Scope and remaining work

This adds generic TCP bytes, **not TCP DNS filtering**. The existing DNS guard applies only to selected UDP ports. For a profile requiring classic DNS-domain enforcement, deny TCP/53 in packet policy until a bounded TCP DNS stream guard exists; DoH/DoT/DoQ and alias/rebinding controls remain outside that guard. Other current limitations include initial ECN/TFO/simultaneous-open, urgent semantics, per-app UID attribution, OS network transition hooks, transparent source identity, ICMP/path-MTU/error translation and WAN/device interoperability. No production secure/leak-free claim is made.

Next: readiness/backpressure scheduling, per-app/global fairness and handshake quotas, evaluated TCP DNS framing, broader options/loss/reorder/long-running tests, protected platform integration and measured memory/battery behavior. Do not convert host evidence into Android or cross-network protection claims.

## Validation

Host tests use a synthetic smoltcp virtual client and actual loopback OS TCP servers. They cover IPv4/IPv6 echo, 100 KB data with smaller buffers/delayed reader, both half-close directions, lost SYN/ACK retransmission without duplicate socket creation, protection refusal/no connect, invalid checksum/options/zero MSS, initial ACK rejection, capacity, bounded queue backpressure, policy/reset/expiry, response deny, out-of-window vs accepted RST, real refused connection, deterministic pending-connect timeout and clock boundary conversion. Deadline tests explicitly model pending observation, not a real WAN blackhole.

A feature-gated, deterministic in-memory TCP fuzz harness exercises both virtual families, parser/control/sequence/queue states and buffer invariants. It creates no upstream OS socket and does not call the entropy source. It does not fuzz OS read/write behavior. Real I/O remains covered by loopback tests. CI adds Android ARM64/x86_64 transport compile checks, not runtime execution, plus four bounded sanitizer fuzz targets and dependency policy checks. Consult current Actions results before calling them passed.
