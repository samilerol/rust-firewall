package org.netscope.ngfw;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.util.concurrent.atomic.AtomicReference;

/** Host-JVM only. No Android VPN/TUN endpoint or native policy evaluation. */
public final class TunEgressQueueSmoke {
    private static void ok(boolean condition) {
        if (!condition) throw new AssertionError("TUN queue contract failed");
    }
    private static byte[] v4(int length) {
        byte[] packet = new byte[length];
        packet[0] = 0x45;
        packet[2] = (byte) (length >>> 8);
        packet[3] = (byte) length;
        return packet;
    }
    public static void main(String[] args) throws Exception {
        ByteArrayOutputStream sink = new ByteArrayOutputStream();
        TunEgressQueue queue = new TunEgressQueue(new TunPacketWriter(sink, 1280),1280,2,1280);
        byte[] first = v4(20);
        ok(queue.offer(first, 20));
        first[0] = 0x70; // production may reuse the buffer after submission.
        ok(queue.offer(v4(20), 20));
        ok(!queue.offer(v4(20),20)); // capacity is exact.
        ok(queue.queuedPackets() == 2 && queue.queuedBytes() == 40);
        ok(queue.drain(1) == 1);
        ok(sink.size() == 20 && (sink.toByteArray()[0] & 0xff) == 0x45);
        ok(queue.queuedPackets() == 1 && queue.queuedBytes() == 20);
        ok(queue.drain(64) == 1);
        ok(queue.drain(1) == 0);
        ok(sink.size() == 40);
        ok(!queue.offer(new byte[1281], 1281));
        ok(!queue.offer(null, 10));
        ok(!queue.offer(v4(20), 21));

        AtomicReference<Throwable> threadError = new AtomicReference<>();
        Thread intruder = new Thread(() -> {
            try { queue.drain(1); } catch (Throwable e) { threadError.set(e); }
        });
        intruder.start();
        intruder.join();
        ok(threadError.get() instanceof IllegalStateException);

        // Lifecycle cancellation from a different thread frees pending buffers.
        ok(queue.offer(v4(20), 20));
        Thread cancel = new Thread(queue::requestStop);
        cancel.start();
        cancel.join();
        ok(queue.queuedPackets() == 0 && queue.queuedBytes() == 0);
        ok(!queue.offer(v4(20), 20));
        try { queue.drain(1); throw new AssertionError(); }
        catch (IOException expected) { }
        queue.close();
        ok(sink.size() == 40);

        ByteArrayOutputStream budgetSink = new ByteArrayOutputStream();
        TunEgressQueue budget = new TunEgressQueue(
            new TunPacketWriter(budgetSink, 1280),1280,64,1280);
        ok(budget.offer(v4(1280), 1280));
        ok(!budget.offer(v4(20), 20));
        ok(budget.queuedBytes() == 1280);
        ok(budget.drain(1) == 1);
        budget.close();

        // Invalid IP framing cannot escape: writer throws, queue shuts down.
        ByteArrayOutputStream rejectedSink = new ByteArrayOutputStream();
        TunEgressQueue invalid = new TunEgressQueue(
            new TunPacketWriter(rejectedSink,1280),1280,2,1280);
        byte[] bad = v4(20);
        bad[3] = 21;
        ok(invalid.offer(bad,20));
        ok(invalid.offer(v4(20),20));
        try { invalid.drain(2); throw new AssertionError(); }
        catch (IOException expected) { }
        ok(rejectedSink.size() == 0 && invalid.queuedPackets() == 0);
        ok(!invalid.offer(v4(20),20));
        invalid.close();

        final class FailSink extends OutputStream {
            boolean closed;
            @Override public void write(int b) throws IOException { throw new IOException("disk error"); }
            @Override public void write(byte[] b, int o, int l) throws IOException { throw new IOException("device error"); }
            @Override public void close() { closed = true; }
        }
        FailSink fails = new FailSink();
        TunEgressQueue failure = new TunEgressQueue(new TunPacketWriter(fails,1280),1280,2,1280);
        ok(failure.offer(v4(20),20));
        try { failure.drain(1); throw new AssertionError(); }
        catch (IOException expected) { }
        ok(fails.closed && !failure.offer(v4(20),20));
        failure.close();

        try { new TunEgressQueue(new TunPacketWriter(new ByteArrayOutputStream(),1280),1280,65,1280);
            throw new AssertionError();
        } catch (IllegalArgumentException expected) { }
        System.out.println("Bounded TUN egress queue host-JVM smoke: PASS");
    }
}
