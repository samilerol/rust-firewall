package org.netscope.ngfw;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.util.concurrent.atomic.AtomicReference;

/** Host-JVM transport framing checks. Not Android TUN/device or VPN evidence. */
public final class TunPacketWriterSmoke {
    private TunPacketWriterSmoke() { }

    private static void check(boolean ok) {
        if (!ok) throw new AssertionError("TUN egress invariant violated");
    }
    private static void reject(TunPacketWriter writer, byte[] packet, int length)
            throws Exception {
        try {
            writer.write(packet, length);
            throw new AssertionError("invalid packet accepted");
        } catch (IOException expected) {
            // Invalid framing must not reach the sink.
        }
    }
    public static void main(String[] args) throws Exception {
        ByteArrayOutputStream sink = new ByteArrayOutputStream();
        TunPacketWriter writer = new TunPacketWriter(sink, 1280);
        byte[] ipv4 = new byte[20];
        ipv4[0] = 0x45;
        ipv4[2] = 0;
        ipv4[3] = 20;
        writer.write(ipv4, 20);
        check(sink.size() == 20);

        byte[] ipv6 = new byte[41];
        ipv6[0] = 0x60;
        ipv6[5] = 1;
        writer.write(ipv6, 41);
        check(sink.size() == 61);

        reject(writer, null, 0);
        reject(writer, new byte[0], 0);
        reject(writer, ipv4, 21);
        reject(writer, ipv4, -1);
        reject(writer, new byte[1281], 1281);
        byte[] truncatedV4 = ipv4.clone();
        truncatedV4[3] = 21;
        reject(writer, truncatedV4, 20);
        byte[] invalidIhl = ipv4.clone();
        invalidIhl[0] = 0x44;
        reject(writer, invalidIhl, 20);
        byte[] badVersion = ipv4.clone();
        badVersion[0] = 0x75;
        reject(writer, badVersion, 20);
        byte[] truncatedV6 = ipv6.clone();
        truncatedV6[5] = 2;
        reject(writer, truncatedV6, 41);
        check(sink.size() == 61);

        AtomicReference<Throwable> wrongThread = new AtomicReference<>();
        Thread t = new Thread(() -> {
            try { writer.write(ipv4, 20); } catch (Throwable error) { wrongThread.set(error); }
        });
        t.start();
        t.join();
        check(wrongThread.get() instanceof IllegalStateException);
        check(sink.size() == 61);
        writer.close();
        writer.close();
        reject(writer, ipv4, 20);

        final class BrokenStream extends OutputStream {
            boolean closed;
            @Override public void write(int value) throws IOException {
                throw new IOException("write rejected");
            }
            @Override public void write(byte[] value, int offset, int length) throws IOException {
                throw new IOException("write rejected");
            }
            @Override public void close() { closed = true; }
        }
        BrokenStream broken = new BrokenStream();
        TunPacketWriter failed = new TunPacketWriter(broken, 1500);
        reject(failed, ipv4, 20);
        check(broken.closed);
        reject(failed, ipv4, 20);
        try { new TunPacketWriter(new ByteArrayOutputStream(), 100); throw new AssertionError(); }
        catch (IllegalArgumentException expected) { }
        System.out.println("TUN egress host-JVM framing, ownership, fail-stop checks: PASS");
    }
}
