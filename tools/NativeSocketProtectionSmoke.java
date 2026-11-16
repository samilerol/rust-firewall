import org.netscope.ngfw.NativeCore;

/** Host-JVM/JNI checks only. Not Android VpnService or TUN/device evidence. */
public final class NativeSocketProtectionSmoke {
    public static final class FakeService {
        int calls;
        int firstFd = -1;
        int secondFd = -1;
        final int behavior;
        FakeService(int behavior) { this.behavior = behavior; }
        public boolean protect(int fd) {
            if (fd < 0) throw new AssertionError("invalid native socket FD");
            if (++calls == 1) firstFd = fd;
            else secondFd = fd;
            if (behavior == 2) throw new SecurityException("VPN revoked");
            if (behavior == 3 && calls == 2) return false;
            return behavior != 1;
        }
    }
    private static void check(boolean result) {
        if (!result) throw new AssertionError("native socket protection contract failed");
    }
    public static void main(String[] args) {
        check(NativeCore.probeProtectedSockets(null) == -1);
        FakeService reject = new FakeService(1);
        check(NativeCore.probeProtectedSockets(reject) == -1);
        check(reject.calls == 1 && reject.firstFd >= 0 && reject.secondFd < 0);
        FakeService throwsService = new FakeService(2);
        check(NativeCore.probeProtectedSockets(throwsService) == -1);
        check(throwsService.calls == 1);
        // Ensure a JNI exception was cleared and never became an authorization.
        FakeService secondRejected = new FakeService(3);
        check(NativeCore.probeProtectedSockets(secondRejected) == -1);
        check(secondRejected.calls == 2 && secondRejected.secondFd >= 0);
        FakeService accepts = new FakeService(0);
        check(NativeCore.probeProtectedSockets(accepts) == 0);
        check(accepts.calls == 2 && accepts.firstFd >= 0 && accepts.secondFd >= 0);
        check(NativeCore.probeProtectedSockets(reject) == -1);
        check(NativeCore.probeProtectedSocketsOnWorker(null, false) == -1);
        FakeService workerApproved = new FakeService(0);
        check(NativeCore.probeProtectedSocketsOnWorker(workerApproved, false) == 0);
        check(workerApproved.calls == 2);
        FakeService workerDenied = new FakeService(1);
        check(NativeCore.probeProtectedSocketsOnWorker(workerDenied, false) == -1);
        check(workerDenied.calls == 1);
        FakeService workerThrows = new FakeService(2);
        check(NativeCore.probeProtectedSocketsOnWorker(workerThrows, false) == -1);
        check(workerThrows.calls == 1);
        FakeService revoked = new FakeService(0);
        check(NativeCore.probeProtectedSocketsOnWorker(revoked, true) == -1);
        check(revoked.calls == 0);
        FakeService secondDenied = new FakeService(3);
        check(NativeCore.probeProtectedSocketsOnWorker(secondDenied, false) == -1);
        check(secondDenied.calls == 2);
        System.out.println("Native socket protection JNI host smoke: PASS");
    }
}
