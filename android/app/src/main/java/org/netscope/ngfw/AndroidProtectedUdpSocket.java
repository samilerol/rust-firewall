package org.netscope.ngfw;

import android.net.VpnService;
import java.io.IOException;
import java.net.DatagramSocket;
import java.net.InetSocketAddress;
import java.util.Objects;

/**
 * Android-only adapter for the fail-closed UDP socket constructor.
 * This helper is not activated by the drop-all diagnostic service.
 */
public final class AndroidProtectedUdpSocket {
    private AndroidProtectedUdpSocket() { }

    public static DatagramSocket open(VpnService service, InetSocketAddress remote)
            throws IOException {
        Objects.requireNonNull(service, "service");
        return ProtectedUdpSocketFactory.open(service::protect, remote);
    }
}
