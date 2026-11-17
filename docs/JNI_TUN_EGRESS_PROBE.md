# Rust → JNI → bounded Java TUN queue: synthetic integration probe

`NativeCore.probeTunEgressQueue(queue, ipv6)` builds a **synthetic**, checksummed IPv4 or IPv6 UDP datagram using `netscope_packet::udp::encode` and `parse_checked`. JNI copies the packet into a Java byte array and calls the queue's `offer(byte[], int)`. The queue defensively copies again and delivers through `TunPacketWriter` when its owner drains it. The host-JVM smoke test checks both IP families, byte framing, capacity rejection, revocation and Java callback exceptions.

This is *not* the production firewall return path. In particular:
- The probe uses loopback source/destination addresses and creates no upstream socket or Android TUN.
- The bytes originate from a synthetic fixture, **not an authorized UDP/TCP relay response**. This method must never be called by a production VPN service or treated as a general-purpose packet injection API.
- `DiagnosticVpnService` still drops all input. Nothing is connected to a live TUN output stream, and VPN traffic cannot be forwarded by this probe.
- JNI returns `0` only when the Java queue explicitly accepted the synthetic packet. A full queue, missing object or Java exception yields `-1`; pending exceptions are cleared on failure. This is not a policy authorization decision.
- A future production bridge must associate every upstream response with a current tracked flow and current inbound allow decision **in Rust**, enforce DNS/domain policy, preserve VPN lifetime isolation and route updates, and put only those authorized datagrams into the bounded Java queue. A separate owner thread must drain to the real TUN FD while respecting cancellation and backpressure.

This isolated test advances JNI byte-array transport and queue integration while keeping the diagnostic VPN's refusal to forward intact. Physical Android leak, lifecycle, IPv4/IPv6, app attribution, and battery tests remain mandatory. See issue #9.
