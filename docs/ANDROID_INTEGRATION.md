# Android diagnostic integration

## Implemented scope

The Android project is a **drop-all diagnostic VPN**, not a usable forwarding firewall. API 26 minimum, API 35 target/compile, ARM64 and x86_64. The temporary framework Java Activity is a platform permission/start/stop screen, not the planned product UI. Rust-native egui/winit/Android lifecycle integration remains unevaluated for the final UI; Flutter is not used.

The user sees an explicit traffic-blocking warning before requesting Android VPN consent. On API 33+, the diagnostic also requires notification permission before its user-initiated start, so stop controls can be shown. The foreground notification identifies the diagnostic and provides Stop. START_NOT_STICKY and SUPPORTS_ALWAYS_ON=false intentionally prevent advertising unattended/always-on protection. No app rules, DNS filtering, root enforcement or forwarder is exposed. Existing VPN apps may conflict. System-exempt traffic and device-specific routing behavior have not been measured; no leak-free or fail-closed claim is made.

## Packet and resource ownership

1. Android grants VPN consent; the service checks it again and starts a specialUse foreground service (API 34+) before establishing TUN.
2. The builder sets MTU 1500, private IPv4/ULA IPv6 addresses, IPv4/IPv6 default routes and a diagnostic-only DNS address. All read datagrams are discarded. No upstream socket exists, so protect() is not yet used; it is mandatory before connecting future upstream sockets.
3. Android retains ParcelFileDescriptor ownership. On successful start, ownership transfers to the reader's AutoCloseInputStream, which closes it in try-with-resources. A failed startup closes the still-owned descriptor. The FD never crosses JNI; Rust never closes it.
4. One worker polls with 200 ms timeout and reuses one 65,575-byte Java array. Stop/revoke/destroy request cancellation; the worker owns final close. The main thread never closes an FD concurrently with a native read. No queue and no packet logging/persistence. A worker failure stops the diagnostic service. The completion callback checks session identity before affecting a newer reader.
5. JNI validates requested length and Java array capacity (both <=65,575) before making one bounded owned copy. Only the requested prefix is inspected. No pinned array/reference survives the call. The Rust core applies strict checksum parsing and an immutable default-deny policy. Codes: -1 bridge/length error, 0 invalid/unsupported packet, 1 supported packet denied. **There is no allow result.** Java discards 0 and 1; -1 ends the diagnostic session.

Closing TUN restores ordinary Android routing. Process death, service failure or stopping does not provide enforceable blocking outside the running VPN. OS-supported always-on/lockdown behavior requires a later supported implementation and device tests. Checksums on real TUN/offload input are unverified; this diagnostic drops all input regardless of classification.

## JNI safety exception and dependencies

The platform adapter is separate from the three portable crates, which still forbid unsafe. The adapter denies unsafe by default, except one named JNI symbol export with a documented function-local lint exception. There are no handwritten unsafe blocks/raw pointer dereferences. jni 0.21.1 wraps FFI operations; its ABI/array handling is exercised by an actual JVM smoke program with -Xcheck:jni in CI. No claim that dependency internals contain no unsafe is made. Rust panic unwinding is caught before return to Java; allocation failure/process abort and JVM exceptions remain platform failure conditions.

jni is pinned and its transitive versions are in Cargo.lock. License metadata offers MIT/Apache-compatible choices (plus Unicode-3.0 for unicode-ident); this is not a complete vulnerability advisory audit. Core libraries do not acquire JNI dependencies. The JNI library is a cdylib; there is no Java VM invocation feature or network client dependency.

## Build and evidence

GitHub Actions uses standard Ubuntu runners with two Rust/Gradle workers, bounded memory and 25-minute timeout. It runs JVM/native checks on Linux, installs Android SDK 35/NDK 27.2.12479018, cross-compiles the two ABI libraries with 16 KiB ELF page alignment, builds/lints a debug APK and verifies both .so files are present in the ZIP. Artifacts and lint reports have seven-day retention. This is build evidence, **not** Android/device execution evidence. The debug APK is development-signed, not a production release.

Local Android build needs JDK 17+ and SDK/NDK above. Reproduce the native cross-build/copy commands in .github/workflows/android.yml, then `cd android && ./gradlew :app:assembleDebug :app:lintDebug`. The Gradle 8.11.1 wrapper is committed with a SHA-256-checked distribution download. Do not use an APK without both native ABIs (or a deliberately narrowed ABI configuration).

## Transport evaluation and next gates

smoltcp 0.12.0 metadata was evaluated as one Rust-native candidate (0BSD, MSRV 1.80, IPv4/IPv6/TCP/UDP/medium-ip features). It is not added as a dependency or selected as a forwarder. It provides a TCP/IP stack, not a complete Android TUN-to-protected-OS-socket integration; stream buffering, backpressure, timers, UDP mapping/expiry and concurrency still need explicit design. A newer release exists and needs compatibility/security review before selection. A hand-written TCP stack is not justified. C-based lwIP-style/tun2socks adapters would add FFI and require license/maintenance review; no implementation is copied or chosen here.

Next: review transport candidates and maintained versions; define bounded flow/buffer budgets and socket-protection-before-connect contract; add a separate explicit forwarding mode only after integration tests. Define unknown UID policy using supported attribution (API/version/visibility restrictions), network transitions, failure behavior and robust config updates. Physical-device acceptance must cover consent denial/revocation, repeated start/stop, foreground restrictions on Android 14/15+, both ABIs, IPv4/IPv6/DNS behavior, other VPN coexistence, switching networks, crash/close behavior and long-running resource use. No such device checks have been executed here.

## Opt-in forwarding preview

The forwarding preview is selected separately on the consent screen. The preceding sections describe diagnostic mode. A single Java worker owns a nonblocking TUN descriptor and closes its native session before releasing the descriptor. It polls bounded Rust TCP/UDP relays and holds at most one packet for a retry when TUN writes would block. Rust-owned sockets require Android socket protection before connect. A stale JNI token cannot operate on a new session.

The fixed outbound policy allows TCP destination ports 80/443 and TCP/UDP destination port 53 only to 1.1.1.1. The VPN advertises 1.1.1.1 as its DNS server, which is operated by Cloudflare. Forwarding applies an outbound-only gate before using the relay's separate reverse-flow checks. Other routed traffic, including QUIC, is dropped. The preview does not expose editable rules or application identity.

Before publishing a stable release, verify permitted and denied connections on an emulator and real devices, verify VPN stop and revocation, verify IPv4/IPv6 and DNS routing, and test upstream network changes. This preview uses a fixed web and DNS profile and has no automatic upstream network-change recovery. Android build/lint and host JVM smoke tests verify build and JNI contracts. Device routing requires separate runtime evidence.
