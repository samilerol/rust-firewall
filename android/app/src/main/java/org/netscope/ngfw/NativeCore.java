package org.netscope.ngfw;

/** The native API has no allow/forward result. No packet contents are logged. */
public final class NativeCore {
    static { System.loadLibrary("netscope_android"); }
    private NativeCore() {}
    public static native int inspect(byte[] packet, int length);
}
