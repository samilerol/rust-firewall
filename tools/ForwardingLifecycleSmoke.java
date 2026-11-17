package org.netscope.ngfw;

public final class ForwardingLifecycleSmoke {
    public boolean protect(int fd) {
        throw new AssertionError("Empty sessions must not open upstream sockets");
    }

    private static void check(boolean condition) {
        if (!condition) throw new AssertionError("Forwarding lifecycle contract");
    }

    public static void main(String[] args) {
        var service = new ForwardingLifecycleSmoke();
        byte[] packet = new byte[1500];
        check(NativeCore.startForwarding(null) == 0);
        long first = NativeCore.startForwarding(service);
        check(first > 0);
        check(NativeCore.startForwarding(service) == 0);
        check(NativeCore.forwardPacket(first, null, 20) == -1);
        check(NativeCore.forwardPacket(first, packet, 1501) == -1);
        check(NativeCore.forwardPacket(first, packet, 20) == 0);
        check(NativeCore.pollForwarding(first, new byte[1499]) == -1);
        check(NativeCore.pollForwarding(first, packet) == 0);
        check(NativeCore.stopForwarding(first) == 0);
        check(NativeCore.pollForwarding(first, packet) == -1);
        long second = NativeCore.startForwarding(service);
        check(second > first);
        check(NativeCore.stopForwarding(first) == -1);
        check(NativeCore.stopForwarding(second) == 0);
    }
}
