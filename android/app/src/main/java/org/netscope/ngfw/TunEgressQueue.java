package org.netscope.ngfw;

import java.io.Closeable;
import java.io.IOException;
import java.util.ArrayDeque;
import java.util.Arrays;
import java.util.Objects;

/**
 * Bounded queue for complete IP datagrams returned by a future authorized Rust
 * transport. This is NOT a policy engine and never activates VPN forwarding.
 * All writes occur on the thread owning TunPacketWriter.
 */
final class TunEgressQueue implements Closeable {
    private final TunPacketWriter writer;
    private final ArrayDeque<byte[]> pending = new ArrayDeque<>();
    private final int maxPackets;
    private final int maxBytes;
    private final int mtu;
    private final Thread owner;
    private int queuedBytes;
    private boolean stopped;

    TunEgressQueue(TunPacketWriter writer, int mtu, int maxPackets, int maxBytes) {
        this.writer = Objects.requireNonNull(writer, "writer");
        if (mtu < 1280 || mtu > 1500 || maxPackets < 1 || maxPackets > 64
                || maxBytes < mtu || maxBytes > 65536) {
            throw new IllegalArgumentException("invalid queue budget");
        }
        this.mtu = mtu;
        this.maxPackets = maxPackets;
        this.maxBytes = maxBytes;
        this.owner = Thread.currentThread();
    }

    /** Defensive copy: the producer may immediately reuse its JNI/TUN buffer. */
    synchronized boolean offer(byte[] bytes, int length) {
        if (stopped || bytes == null || length < 20 || length > mtu || length > bytes.length
                || pending.size() >= maxPackets || length > maxBytes - queuedBytes) {
            return false;
        }
        pending.addLast(Arrays.copyOf(bytes, length));
        queuedBytes += length;
        return true;
    }

    /** Drain at most maxDrain packets. A write/framing failure invalidates the session. */
    synchronized int drain(int maxDrain) throws IOException {
        checkOwner();
        if (stopped) throw new IOException("TUN queue stopped");
        if (maxDrain < 1 || maxDrain > 64) throw new IllegalArgumentException("invalid drain limit");
        int written = 0;
        while (written < maxDrain && !pending.isEmpty()) {
            byte[] datagram = pending.removeFirst();
            queuedBytes -= datagram.length;
            try {
                writer.write(datagram, datagram.length);
            } catch (IOException | RuntimeException error) {
                stopped = true;
                pending.clear();
                queuedBytes = 0;
                try { writer.close(); } catch (IOException ignored) { }
                throw error;
            }
            written++;
        }
        return written;
    }

    synchronized int queuedPackets() { return pending.size(); }
    synchronized int queuedBytes() { return queuedBytes; }

    /** May be invoked by service lifecycle thread; never directly closes TUN FD. */
    synchronized void requestStop() {
        stopped = true;
        pending.clear();
        queuedBytes = 0;
    }

    @Override public synchronized void close() throws IOException {
        checkOwner();
        requestStop();
        writer.close();
    }

    private void checkOwner() {
        if (Thread.currentThread() != owner) {
            throw new IllegalStateException("TUN output must be drained by owner thread");
        }
    }
}
