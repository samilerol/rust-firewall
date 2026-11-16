package org.netscope.ngfw;

import java.io.Closeable;
import java.io.IOException;
import java.io.OutputStream;
import java.util.Objects;

/**
 * Bounded full-IP-datagram TUN egress gate for a future explicitly enabled relay.
 * Does not initiate traffic or grant firewall permission. Never used by the
 * existing drop-all DiagnosticVpnService.
 *
 * A single owner thread writes only packets produced by a separately authorized
 * Rust inbound-policy path. This class validates basic wire framing, NOT policy.
 */
final class TunPacketWriter implements Closeable {
    private final OutputStream output;
    private final Thread owner;
    private final int mtu;
    private boolean closed;

    TunPacketWriter(OutputStream output, int mtu) {
        this.output = Objects.requireNonNull(output, "output");
        if (mtu < 1280 || mtu > 1500) throw new IllegalArgumentException("unsupported MTU");
        this.mtu = mtu;
        this.owner = Thread.currentThread();
    }

    synchronized void write(byte[] packet, int length) throws IOException {
        checkOwner();
        if (closed) throw new IOException("TUN writer closed");
        if (packet == null || length < 0 || length > packet.length
                || length < 20 || length > mtu) {
            throw new IOException("invalid packet bounds");
        }
        final int version = (packet[0] & 0xff) >>> 4;
        if (version == 4) {
            int ihl = (packet[0] & 0x0f) * 4;
            int total = ((packet[2] & 0xff) << 8) | (packet[3] & 0xff);
            if (ihl < 20 || ihl > length || total != length) {
                throw new IOException("invalid IPv4 framing");
            }
        } else if (version == 6) {
            if (length < 40) throw new IOException("short IPv6 packet");
            int payload = ((packet[4] & 0xff) << 8) | (packet[5] & 0xff);
            if (payload == 0 || payload + 40 != length) {
                throw new IOException("invalid IPv6 framing");
            }
        } else {
            throw new IOException("unsupported IP version");
        }

        // OutputStream.write(byte[],off,len) either completes or throws.
        // No retry after an IOException: partial device writes cannot safely
        // be replayed without an independent framed transport contract.
        try {
            output.write(packet, 0, length);
        } catch (IOException | RuntimeException failure) {
            closed = true;
            try { output.close(); } catch (IOException ignored) { }
            throw failure;
        }
    }

    private void checkOwner() {
        if (Thread.currentThread() != owner) {
            throw new IllegalStateException("TUN writer used outside owner thread");
        }
    }

    @Override public synchronized void close() throws IOException {
        checkOwner();
        if (closed) return;
        closed = true;
        output.close();
    }
}
