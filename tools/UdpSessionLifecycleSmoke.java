import org.netscope.ngfw.NativeCore;

/** Real host JVM/native session lifetime tests; no TUN or packet forwarding. */
public final class UdpSessionLifecycleSmoke {
    public static final class FakeVpnService {
        int protectionCalls;
        public boolean protect(int fd) {
            protectionCalls++;
            throw new AssertionError("dormant session must not protect or transmit");
        }
    }

    private static void check(boolean condition) {
        if (!condition) throw new AssertionError("native UDP session lifecycle contract failed");
    }

    public static void main(String[] args) {
        check(NativeCore.startUdpSession(null) == 0);
        check(NativeCore.stopUdpSession(0) == -1);
        check(NativeCore.resetUdpSessionNetwork(0) == -1);
        FakeVpnService service = new FakeVpnService();
        long first = NativeCore.startUdpSession(service);
        check(first > 0);
        check(NativeCore.startUdpSession(new FakeVpnService()) == 0);
        check(NativeCore.resetUdpSessionNetwork(first) == 0);
        check(NativeCore.resetUdpSessionNetwork(first + 1) == -1);
        check(NativeCore.stopUdpSession(first + 1) == -1);
        check(NativeCore.resetUdpSessionNetwork(first) == 0);
        check(NativeCore.stopUdpSession(first) == 0);
        check(NativeCore.stopUdpSession(first) == -1);
        check(NativeCore.resetUdpSessionNetwork(first) == -1);
        long second = NativeCore.startUdpSession(new FakeVpnService());
        check(second > first);
        check(NativeCore.stopUdpSession(first) == -1);
        check(NativeCore.resetUdpSessionNetwork(second) == 0);
        check(NativeCore.stopUdpSession(second) == 0);
        check(service.protectionCalls == 0);
        System.out.println("UDP session lifecycle JNI host smoke: PASS");
    }
}
