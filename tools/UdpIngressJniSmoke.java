import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HexFormat;
import org.netscope.ngfw.NativeCore;

/** Host JVM JNI checks only; does not prove Android TUN or device behavior. */
public final class UdpIngressJniSmoke {
    public static final class FakeVpnService {
        int protectedCalls;
        public boolean protect(int fd) {
            protectedCalls++;
            throw new AssertionError("dry-run cannot create upstream sockets");
        }
    }

    private static void check(boolean condition) {
        if (!condition) throw new AssertionError("UDP ingress deny-only contract failed");
    }

    private static byte[] fixture(String path) throws Exception {
        return HexFormat.of().parseHex(Files.readString(Path.of(path)).trim());
    }

    public static void main(String[] args) throws Exception {
        check(args.length == 3);
        byte[] v4 = fixture(args[0]);
        byte[] v6 = fixture(args[1]);
        byte[] tcp = fixture(args[2]);
        FakeVpnService protector = new FakeVpnService();

        check(NativeCore.inspectUdpSession(0, v4, v4.length) == -1);
        long id = NativeCore.startUdpSession(protector);
        check(id > 0);
        check(NativeCore.inspectUdpSession(id, v4, v4.length) == 1);
        check(NativeCore.inspectUdpSession(id, v6, v6.length) == 1);
        check(NativeCore.inspectUdpSession(id, tcp, tcp.length) == 0);
        byte[] malformed = v4.clone();
        malformed[malformed.length - 1] ^= 1;
        check(NativeCore.inspectUdpSession(id, malformed, malformed.length) == 0);
        check(NativeCore.inspectUdpSession(id, null, 2) == -1);
        check(NativeCore.inspectUdpSession(id, v4, 0) == -1);
        check(NativeCore.inspectUdpSession(id, v4, -1) == -1);
        check(NativeCore.inspectUdpSession(id, v4, v4.length + 1) == -1);
        check(NativeCore.inspectUdpSession(id, new byte[65576], 20) == -1);
        byte[] pooled = new byte[65575];
        System.arraycopy(v4, 0, pooled, 0, v4.length);
        check(NativeCore.inspectUdpSession(id, pooled, v4.length) == 1);
        check(NativeCore.inspectUdpSession(id + 1, v4, v4.length) == -1);
        check(NativeCore.resetUdpSessionNetwork(id) == 0);
        check(NativeCore.inspectUdpSession(id, v4, v4.length) == 1);
        check(NativeCore.stopUdpSession(id) == 0);
        check(NativeCore.inspectUdpSession(id, v4, v4.length) == -1);
        check(protector.protectedCalls == 0);
        System.out.println("Native UDP ingress inspect-only dry-run JNI smoke: PASS");
    }
}
