package org.netscope.ngfw;

import java.io.ByteArrayOutputStream;
import org.netscope.ngfw.NativeCore;

/** Real host JVM + Rust JNI test; neither Android TUN nor live forwarding. */
public final class TunEgressJniSmoke {
    private static void check(boolean ok) {
        if (!ok) throw new AssertionError("Rust -> JNI -> TUN queue probe failed");
    }
    public static void main(String[] args) throws Exception {
        check(NativeCore.probeTunEgressQueue(null, false) == -1);

        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        TunEgressQueue queue = new TunEgressQueue(
            new TunPacketWriter(bytes, 1280), 1280, 2, 1280);
        check(NativeCore.probeTunEgressQueue(queue, false) == 0);
        check(NativeCore.probeTunEgressQueue(queue, true) == 0);
        check(queue.queuedPackets() == 2);
        check(NativeCore.probeTunEgressQueue(queue, false) == -1); // capacity backpressure
        check(queue.drain(2) == 2);
        byte[] delivered = bytes.toByteArray();
        int ipv4Length = 20 + 8 + "netscope-probe".length();
        int ipv6Length = 40 + 8 + "netscope-probe".length();
        check(delivered.length == ipv4Length + ipv6Length);
        check((delivered[0] & 0xf0) == 0x40);
        check((delivered[ipv4Length] & 0xf0) == 0x60);
        check(queue.queuedPackets() == 0 && queue.queuedBytes() == 0);
        queue.requestStop();
        check(NativeCore.probeTunEgressQueue(queue, false) == -1);
        queue.close();

        // Throwing Java callback must fail closed and clear pending JNI exception.
        class ThrowingQueue {
            public boolean offer(byte[] packet, int length) {
                throw new IllegalStateException("revoked");
            }
        }
        check(NativeCore.probeTunEgressQueue(new ThrowingQueue(), false) == -1);
        check(NativeCore.probeTunEgressQueue(null, true) == -1);

        System.out.println("Rust/JNI bounded TUN egress synthetic host smoke: PASS");
    }
}
