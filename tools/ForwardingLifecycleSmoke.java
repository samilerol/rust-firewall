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
        byte[] observation = new byte[38];
        check(NativeCore.startForwarding(null) == 0);
        long first = NativeCore.startForwarding(service);
        check(first > 0);
        check(NativeCore.startForwarding(service) == 0);
        check(NativeCore.forwardPacket(first, null, 20, observation) == -1);
        check(NativeCore.forwardPacket(first, packet, 1501, observation) == -1);
        check(NativeCore.forwardPacket(first, packet, 20, observation) == 0);
        byte[] denied = java.util.HexFormat.of().parseHex(
            "4500001f1234400040113c63c0000201c633640230390035000b1ed0616263");
        System.arraycopy(denied, 0, packet, 0, denied.length);
        check(NativeCore.forwardPacket(first, packet, denied.length, new byte[37]) == -1);
        check(NativeCore.forwardPacket(first, packet, denied.length, observation) == 2);
        check(observation[0] == 17 && observation[1] == 4 && observation[5] == 53);
        check((observation[6] & 0xff) == 192 && (observation[22] & 0xff) == 198);
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
