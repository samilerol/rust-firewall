import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import org.netscope.ngfw.ProtectedUdpSocketFactory;

/** Host-JVM contract checks, not Android VPN/device evidence. */
public final class ProtectedUdpSocketSmoke {
    private static void check(boolean condition) {
        if (!condition) throw new AssertionError("UDP protection invariant failed");
    }

    private static void expectIOException(ProtectedUdpSocketFactory.Protector protector,
                                          InetSocketAddress remote) throws Exception {
        try (DatagramSocket unused = ProtectedUdpSocketFactory.open(protector, remote)) {
            throw new AssertionError("Expected failure, got connected socket");
        } catch (IOException expected) {
            // Failure must not return an unprotected socket.
        }
    }

    public static void main(String[] args) throws Exception {
        try (DatagramSocket server = new DatagramSocket(0)) {
            server.setSoTimeout(2000);
            InetSocketAddress remote = new InetSocketAddress("127.0.0.1", server.getLocalPort());
            AtomicInteger calls = new AtomicInteger();
            AtomicReference<DatagramSocket> observed = new AtomicReference<>();

            expectIOException(socket -> {
                calls.incrementAndGet();
                observed.set(socket);
                check(!socket.isBound() && !socket.isConnected());
                return false;
            }, remote);
            check(calls.get() == 1 && observed.get().isClosed());

            expectIOException(socket -> {
                observed.set(socket);
                throw new IOException("protect unavailable");
            }, remote);
            check(observed.get().isClosed());

            try {
                ProtectedUdpSocketFactory.open(socket -> {
                    observed.set(socket);
                    throw new SecurityException("VPN unavailable");
                }, remote);
                throw new AssertionError("SecurityException was suppressed");
            } catch (SecurityException expected) {
                check(observed.get().isClosed());
            }

            expectIOException(socket -> {
                throw new AssertionError("must not be reached");
            }, InetSocketAddress.createUnresolved("example.invalid", 53));

            expectIOException(socket -> {
                throw new AssertionError("must not be reached");
            }, new InetSocketAddress("127.0.0.1", 0));

            try (DatagramSocket client = ProtectedUdpSocketFactory.open(socket -> {
                calls.incrementAndGet();
                check(!socket.isBound() && !socket.isConnected());
                return true;
            }, remote)) {
                check(client.isBound() && client.isConnected());
                byte[] ping = "netscope".getBytes(StandardCharsets.US_ASCII);
                client.send(new DatagramPacket(ping, ping.length));
                byte[] received = new byte[32];
                DatagramPacket packet = new DatagramPacket(received, received.length);
                server.receive(packet);
                check(packet.getLength() == ping.length);
                check(new String(packet.getData(), 0, packet.getLength(), StandardCharsets.US_ASCII)
                      .equals("netscope"));
            }
            check(calls.get() == 2);
        }
        System.out.println("Protected UDP socket host-JVM contract smoke: PASS");
    }
}
