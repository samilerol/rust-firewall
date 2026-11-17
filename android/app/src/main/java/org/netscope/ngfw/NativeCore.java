package org.netscope.ngfw;

/** JNI entry points for the diagnostic and opt-in forwarding sessions. */
public final class NativeCore {
    static { System.loadLibrary("netscope_android"); }
    private NativeCore() {}
    public static native int inspect(byte[] packet, int length);
    static native long startForwarding(Object vpnService);
    /** 0 = invalid, 1 = profile permits, 2 = profile blocks, -1 = bridge failure. */
    static native int forwardPacket(long session, byte[] packet, int length, byte[] observation);
    static native int pollForwarding(long session, byte[] packet);
    static native int stopForwarding(long session);
    /** Dormant default-deny UDP session; no packet forwarding API. Zero is failure. */
    public static native long startUdpSession(Object vpnService);
    /** Returns 1 for valid UDP dropped, 0 for other packets dropped, -1 on session error. Never allows. */
    public static native int inspectUdpSession(long sessionId, byte[] packet, int length);
    public static native int stopUdpSession(long sessionId);
    public static native int resetUdpSessionNetwork(long sessionId);
    /** Opt-in probe only: protection of Rust-owned sockets; never forwards traffic. */
    public static native int probeProtectedSockets(Object vpnProtectionService);
    /** Host-testable JavaVM/GlobalRef worker probe; not live VPN forwarding. */
    public static native int probeProtectedSocketsOnWorker(Object vpnProtectionService, boolean revokeBeforeUse);
    /** Host/loopback-only UDP relay integration probe, not VPN forwarding. */
    public static native int probeUdpRelayLoopback(Object protector, Object tunQueue, int port, boolean allowInbound, boolean ipv6);
    /** Synthetic Rust -> JNI -> Java output queue test only; no live VPN packets. */
    public static native int probeTunEgressQueue(Object queue, boolean ipv6);
}
