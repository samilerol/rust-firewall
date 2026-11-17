# Platform targets

The Rust packet parser, policy (including the text loader), connection tracking, DNS and engine are platform-independent crates. TCP/UDP forwarding uses the OS socket APIs through the transport crate. Android's VPN lifecycle, TUN I/O, socket protection, UID lookup and menus live in the Android adapter. The core builds and runs its library and loopback tests on Linux in workspace CI.

| Target | Status | Integration needed |
| --- | --- | --- |
| Android | VPN forwarding preview and device-native controls | Physical-device validation and application rules |
| Linux | Portable libraries build and test on the hosted Linux runner | A service with an explicit packet path, lifecycle and policy loading |
| OpenWrt | Target design | A package for supported router architectures and firmware, integrated with firewall4/nftables and safe reload/rollback |
| DD-WRT | Target design | Identify supported router model and firmware, verify CPU, libc, memory and storage, and build a compatible service and packet-path adapter |

An Android APK is not a router package. A Linux build proves library compatibility, not enforcement on that host. Router ingress generally provides authenticated network/interface context and observable device addresses, not an Android app UID. Keep those identities and adapters separate and use the same verified packet and policy core.

Start router integration on a virtual OpenWrt target with disposable routing, then package against a selected router architecture. Preserve existing router rules on failed configuration, clean up only owned state, and verify recovery after stop or restart. Evaluate DD-WRT against the candidate hardware before claiming support.
