import java.nio.file.Files;
import java.nio.file.Path;
import org.netscope.ngfw.NativeCore;

/** Real JVM/native-boundary smoke checks, independent of Android SDK/device. */
public final class JniSmoke {
    private static void check(boolean value) { if (!value) throw new AssertionError("JNI contract failed"); }
    public static void main(String[] args) throws Exception {
        byte[] valid = java.util.HexFormat.of().parseHex(Files.readString(Path.of(args[0])).trim());
        check(NativeCore.inspect(valid, valid.length) == 1);
        check(NativeCore.inspect(valid, valid.length - 1) == 0);
        check(NativeCore.inspect(valid, valid.length + 1) == -1);
        check(NativeCore.inspect(valid, -1) == -1);
        check(NativeCore.inspect(null, 1) == -1);
        check(NativeCore.inspect(new byte[0], 0) == -1);
        check(NativeCore.inspect(new byte[65576], 1) == -1);
        byte[] pooled = new byte[65575];
        System.arraycopy(valid, 0, pooled, 0, valid.length);
        check(NativeCore.inspect(pooled, valid.length) == 1);
        valid[valid.length - 1] ^= 1;
        check(NativeCore.inspect(valid, valid.length) == 0);
        System.out.println("JNI smoke: 9 real JVM/native contract checks passed");
    }
}
