package org.netscope.ngfw;

/** The native API has no allow/forward result. No packet contents are logged. */
public final class NativeCore {
    static { System.loadLibrary("netscope_android"); }
    private NativeCore() {}
    public static native int inspect(byte[] packet, int length);
    /** Opt-in probe only: protection of Rust-owned sockets; never forwards traffic. */
    public static native int probeProtectedSockets(Object vpnProtectionService);
    /** Host-testable JavaVM/GlobalRef worker probe; not live VPN forwarding. */
    public static native int probeProtectedSocketsOnWorker(Object vpnProtectionService, boolean revokeBeforeUse);
}
