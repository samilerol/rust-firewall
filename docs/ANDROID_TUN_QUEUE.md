# Bounded TUN egress queue (non-activated integration component)

`TunEgressQueue` accepts **complete IP datagrams** from a future Rust transport return path, defensively copies each packet before the source buffer can be recycled, and limits both packet count (1–64) and total queued bytes (at most 65,536). When at capacity, `offer` declines rather than allocating an unbounded backlog. `drain` writes at most a caller-specified packet budget and must be run by the same thread that owns `TunPacketWriter`.

`TunPacketWriter` performs IP framing and MTU checks before writing. A framing/write failure during `drain` causes the queue to enter its stopped state, clear buffered packets and close its writer. A separate service lifecycle thread may invoke `requestStop()`, which only clears the queue; it does **not** close the TUN descriptor from the wrong thread. The writer owner must subsequently call `close()`.

## Security and scope

- **Not activated** in `DiagnosticVpnService`. Diagnostic traffic remains dropped and no packet is forwarded.
- This queue is **not an authorization engine**. A future Rust transport must apply current inbound firewall policy, flow association and DNS rules before packets enter the queue.
- An ordinary `false` result from `offer` must be interpreted as backpressure/drop, **never** as a reason to bypass the VPN or forward directly.
- A future TUN event loop must coordinate packet selection, expiration and fairness, lifecycle cancellation, consent revocation, protected upstream sockets, and handling sustained backpressure.
- Host JVM tests exercise copies, queue budgets, owner-thread rejection, stop and fail-stop behavior. They are not Android device evidence.

See issue #9 for remaining end-to-end Android integration and device acceptance requirements.
