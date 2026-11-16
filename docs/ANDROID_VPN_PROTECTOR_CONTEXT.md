# Revocable JavaVM-backed Android socket protector (development)

`AndroidVpnProtector` owns a `JavaVM`, a JNI `GlobalRef` to a Java object exposing `boolean protect(int fd)`, and an atomic active flag. It can be invoked from native Rust worker threads: it attaches to the JVM for the duration of each callback and passes **the actual Rust UDP/TCP socket FD** into the Java method. This is the method signature used by Android `VpnService.protect(int)`.

- False, Java exceptions, inability to attach or revoked state are denied.
- The JNI exception is cleared after failure; it never authorizes a socket.
- Calling `revoke()` blocks subsequent calls and re-checks the flag after Java returns.
- The borrowed socket FD is not retained or closed by Java. The owning Rust socket closes when dropped.
- The test JNI export `probeProtectedSocketsOnWorker` spawns a bounded worker and joins it. It performs no connect/send/receive and is **not invoked by the diagnostic VPN**.

## Important limits

An atomic flag **is not a sufficient lifecycle barrier**: a revocation race is possible after a successful protection callback, and Android routing/network state can change. The eventual live TUN worker must serialize shutdown/transport reset, stop sends and new connections, close all sockets on revoke/network change, and add a generation-based session gate. A Java GlobalRef must be released when the worker stops; never retain Activity/Service references forever. Use real `VpnService` objects on physical Android devices to verify the platform API. The host-JVM fake service only proves invocation and error propagation.

No forwarding, policy UI, device leak claims, always-on or lockdown support is included. Existing diagnostic is still drop-all. Follow issue #9.
