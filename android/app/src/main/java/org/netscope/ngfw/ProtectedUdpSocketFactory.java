package org.netscope.ngfw;

import java.io.IOException;
import java.net.DatagramSocket;
import java.net.InetSocketAddress;
import java.util.Objects;

/**
 * Standalone protected-UDP socket construction boundary.
 *
 * Not wired to the diagnostic VPN or Rust relay. The Android caller must provide
 * vpnService::protect; refusing protection must never fall back to a direct socket.
 * Ownership of a successful socket transfers to the caller, which must close it.
 */
public final class ProtectedUdpSocketFactory {
    private ProtectedUdpSocketFactory() { }

    @FunctionalInterface
    public interface Protector {
        boolean protect(DatagramSocket socket) throws IOException;
    }

    public static DatagramSocket open(Protector protector, InetSocketAddress remote)
            throws IOException {
        Objects.requireNonNull(protector, "protector");
        Objects.requireNonNull(remote, "remote");
        // Reject hostnames: implicit resolution might happen outside a protected path.
        if (remote.isUnresolved() || remote.getAddress() == null
                || remote.getPort() == 0 || remote.getAddress().isMulticastAddress()) {
            throw new IOException("UDP destination must be resolved, unicast and nonzero-port");
        }

        DatagramSocket socket = new DatagramSocket(null); // unbound, unconnected
        boolean success = false;
        try {
            // No bind, connect, send or receive before platform VPN protection.
            if (!protector.protect(socket)) {
                throw new IOException("VPN socket protection refused");
            }
            socket.bind(new InetSocketAddress(0));
            socket.connect(remote);
            success = true;
            return socket;
        } finally {
            if (!success) socket.close();
        }
    }
}
