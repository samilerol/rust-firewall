# Android UDP session kernel (not wired to TUN)

`netscope_android::udp_session::UdpSession<P>` owns a bounded `netscope_transport::UdpRelay<P>` instance with 64-flow maximum, MTU 1500, strict checksums and a 30-second idle timeout. A new session has an **empty, default-deny policy**. `update_rules` installs rules with default action fixed to Deny, revoking all existing flows upon a valid policy change; invalid policies are rejected without replacement.

`send` and `receive` wrap the existing Rust transport, which demands platform socket protection before upstream `connect`/`send` and requires reverse-direction policy authorization for every delivered response. `reset_network` drops sockets and connections on network changes; `revoke` permanently disables the session, immediately drops all flows and rejects subsequent calls. These methods never write directly to an Android TUN.

Unit tests use **real localhost UDP sockets** with an explicitly marked fake protector, verify new sessions deny traffic without calling protection, enforce reverse response policies, ensure a reset removes flows and prove revoked sessions refuse use. A fake protector is only for host tests; real Android integration must use `AndroidVpnProtector` with current VPN consent and lifecycle guard.

**Not yet implemented:** JNI lifecycle handle ownership, real VpnService instance binding, live TUN ingress/egress, synchronization of the Android protector's `revoke()` with session cancellation, Android emulator/physical-device IPv4/IPv6/DNS leak verification and always-on/lockdown behavior. The pre-existing `DiagnosticVpnService` remains unchanged and **drops every packet**. Do not advertise this as a functioning firewall or leak-proof Android VPN.

See issue #9.
