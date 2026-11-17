# Android JNI surface: host probes excluded from APK

Android binaries must export only production-required JNI entrypoints. Existing Rust/JNI host integration probes create synthetic or local-loopback packets, fake VpnService protection services and TUN queues. They are regression instruments, **not public Android forwarding interfaces**.

For `target_os = "android"`, `socket_protection`, `udp_relay_probe`, `tun_egress_probe` and the `probeProtectedSocketsOnWorker` JNI entrypoint are excluded at compilation. The underlying `AndroidVpnProtector` adapter remains compiled for a future reviewed transport integration. The actual Android diagnostic entrypoint `NativeCore.inspect` remains present, with unchanged deny-only behavior. Java `NativeCore` declarations for host-only probes remain for the Linux JVM CI smoke tests but MUST NOT be called by the Android application; the Android native library intentionally has no implementations of these host-only symbols.

Android CI uses `llvm-nm` on **both** ARM64 and x86_64 native libraries to assert that `inspect` remains exported and all four host-probe JNI symbols are absent. The existing host JVM smoke tests still exercise both families, UDP relay policy, protected socket callbacks and bounded queue behavior. Source-level and ELF-export checks do not prove Android device-level leak resistance.

Do not enable forwarding or expose ad hoc JNI packet injection methods in a shipping application. Production transport must have explicit session-owned policy and FD guards, bounded ingress/egress, lifecycle cancellation and independent physical-device evidence.
