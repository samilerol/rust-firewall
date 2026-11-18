# Opt-in classic DNS over TCP

## Activation and scope

`TcpRelay::set_dns_filter(Some(domain_policy), ports)` enables question-based filtering on up to 32 unique nonzero TCP destination ports. UDP and TCP activation are independent. Configure both relays for a classic DNS enforcement profile, or explicitly deny the unguarded protocol in packet policy. A constructor alone enables no DNS filtering. Unselected TCP ports retain the existing opaque byte relay.

The same netscope-dns conservative one-IN-question profile, ASCII/domain ordering, record/compression/EDNS budgets and question-only limitations apply (DNS_POLICY.md). This is not a resolver/cache, encrypted DNS inspector, DNSSEC/TSIG verifier, alias/rebinding guard or comprehensive domain-access control. No DNS history or synthetic blocked response is generated. TCP DNS does not imply DoH/DoT/DoQ visibility, nor Android routing or device enforcement.

The TCP handshake/protected upstream connection still opens before application data is available. Domain denial prevents forwarding any bytes of the denied DNS frame, including its length prefix; it does not prevent that already-authorized upstream connection. Current outbound packet policy, accepted SYN and protection-before-connect remain prerequisites. Every returned reverse IP packet also requires current inbound packet authorization.

## Framing and admission

Classic DNS uses a two-byte big-endian message length. Each direction assembles one complete frame before forwarding any of it. Prefixes and bodies may span TCP segments, reads, circular-buffer boundaries and poll passes; coalesced/pipelined frames are consumed one at a time without swallowing the next frame. Permitted frame bytes, including the original prefix, are unchanged, though TCP segmentation is proxy-owned.

Supported message lengths are 12..4096 bytes; full DNS parsing imposes its additional question/record requirements. The RFC TCP maximum of 65535 bytes is deliberately outside this bounded profile. Zero/short/oversized lengths, malformed DNS, disallowed names, duplicate outstanding IDs (even identical-question retries), query capacity failures, unknown IDs and question/type/class mismatches abort the affected TCP connection and discard queued frames. UDP's individual malformed-reply behavior does not apply to this stream. A reset is emitted when stack/packet policy permits; no guarantee of a delivered RST or synthetic DNS error is made. Earlier permitted frames may already have been delivered.

Requests with distinct IDs may pipeline; matched responses may complete out of order. Defaults are 8 pending requests per flow and 4096 across this TCP relay. `set_dns_limits(DnsLimits)` accepts the same nonzero count ceilings as UDP (64 per flow, 4096 total); `query_timeout` is **milliseconds** here. Valid filter/limit/packet-policy changes and network reset close all flows and clear pending requests/partial frames; invalid configuration changes nothing. TCP and UDP relays have separate global counters/budgets.

A request is recorded when its complete frame passes admission, immediately before its first OS write attempt. Its age is not extended by TCP retransmissions, additional requests or ACKs. It remains pending until the complete validated response has been queued to the virtual TCP socket, not necessarily delivered/ACKed by the client. Active ID reuse is rejected; reuse after completion cannot distinguish an old response with the same ID and question. Connected peers and transaction matching are not authentication/replay protection. Multi-message AXFR/IXFR-style transactions are not supported.

## Memory, backpressure and clocks

Each guarded flow reserves two 4098-byte frame buffers (8196 bytes in total), in addition to its existing TCP stream/packet buffers. Enabling the guard validates the worst case `max_flows * (existing_per_flow_payload + 8196)` against the existing Config.buffer_budget (<=16 MiB) before changing state. A budget sufficient for generic TCP may therefore reject DNS activation. Both frame capacities are reserved at guarded-flow creation; no frame list or retry queue grows with pipelining. Pending names/indexes, allocator metadata, OS buffers and externally held returned packets remain outside that payload-byte estimate, with request counts/name lengths bounded separately. `buffers().dns_frame_bytes` reports currently buffered frame lengths; `reserved_payload_bytes` includes frame capacity for guarded flows.

A poll pass performs at most one upstream write and read per flow and processes at most one frame per direction. Partial writes retain the unsent suffix; WouldBlock/Interrupted preserve offsets and ownership. Small virtual TCP send buffers partially consume a validated response and hold the remainder. Backpressure blocks reading the next frame in that direction. Other flows still get their bounded pump pass.

The configured query timeout also bounds each frame from its first consumed byte until its last byte is forwarded/queued; additional bytes do not refresh this age. Expiry of any pending request or undrained frame aborts that flow and removes its pending entries. This bounds incomplete-prefix/body and stalled-delivery state, including while ACK traffic keeps the base flow alive. Expiry uses age subtraction and monotonic milliseconds validated before mutation. If the generic flow idle lease expires first, normal flow removal applies. The driver must call ingest/poll/next_packet regularly; there is no scheduler or hard real-time deadline.

FIN at a frame boundary retains the existing independent half-close behavior. A client FIN inside a frame or upstream EOF inside a response frame aborts the stream, without forwarding the incomplete frame. Client write shutdown propagates upstream only after both its stack receive queue and its DNS outbound frame drain. Pending unanswered requests can still time out after a half-close.

`PollReport.dns_failures` counts DNS failures/timeouts detected by that poll call; expiry driven by ingest/next_packet can occur before a later poll, just as other implicit lifecycle events are not a persistent event log. Socket failures retain the separate io_failures count. Forced teardown requests best-effort SO_LINGER=0; it cannot retract bytes previously accepted by the OS or application.

## Validation

Host tests use actual IPv4/IPv6 loopback streams and a synthetic virtual client: split prefix/body, coalesced queries, out-of-order responses, 4096-byte messages through 1024-byte virtual buffers, no unchecked prefix delivery, denied/malformed/oversized/incomplete frames, duplicate IDs, per-flow/global caps, request/frame deadlines, reversed clocks, half-close, unselected ports, policy/reset/filter revocation and atomic budget/limit rejection. Pure tests schedule partial reads/writes, Interrupted and WouldBlock and test every prefix/body split against the exact byte sequence.

The existing bounded TCP sanitizer fuzz target additionally exercises the pure frame codec, query/response admission and partial-I/O schedules using memory-backed I/O. It opens no OS socket. Real OS I/O evidence comes from loopback tests; a 30-second fuzz smoke is not exhaustive security validation. No new runtime dependency or unsafe source is introduced. Check current PR Actions for actual hosted results; no emulator or device tests were performed.
