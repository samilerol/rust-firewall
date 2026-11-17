package org.netscope.ngfw;

import java.io.ByteArrayOutputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicReference;

/** Actual local UDP socket -> native Rust relay -> JNI -> queue. NOT Android VPN evidence. */
public final class UdpRelayJniSmoke {
    private static void check(boolean value) {
        if (!value) throw new AssertionError("UDP relay JNI integration invariant failed");
    }

    public static final class FakeVpnProtector {
        int calls;
        final int mode;
        FakeVpnProtector(int mode) { this.mode = mode; }
        public boolean protect(int fd) {
            check(fd >= 0);
            calls++;
            if (mode == 2) throw new SecurityException("VPN revoked");
            return mode != 1;
        }
    }

    private static int roundtrip(FakeVpnProtector protector, TunEgressQueue queue, boolean allowInbound, boolean ipv6)
            throws Exception {
        try (DatagramSocket server = new DatagramSocket(0, InetAddress.getByName(ipv6 ? "::1" : "127.0.0.1"))) {
            server.setSoTimeout(2500);
            AtomicReference<Throwable> workerFailure = new AtomicReference<>();
            Thread echo = new Thread(() -> {
                try {
                    byte[] buf = new byte[256];
                    DatagramPacket request = new DatagramPacket(buf, buf.length);
                    server.receive(request);
                    String message = new String(
                        request.getData(), request.getOffset(), request.getLength(),
                        StandardCharsets.US_ASCII);
                    check(message.equals("netscope-udp-loopback"));
                    byte[] reply = "reply-from-loopback".getBytes(StandardCharsets.US_ASCII);
                    server.send(new DatagramPacket(reply, reply.length, request.getSocketAddress()));
                } catch (Throwable e) {
                    workerFailure.set(e);
                }
            });
            echo.start();
            int result = NativeCore.probeUdpRelayLoopback(
                protector, queue, server.getLocalPort(), allowInbound, ipv6);
            echo.join(3000);
            check(!echo.isAlive());
            check(workerFailure.get() == null);
            return result;
        }
    }

    public static void main(String[] args) throws Exception {
        ByteArrayOutputStream acceptedBytes = new ByteArrayOutputStream();
        TunEgressQueue allowed = new TunEgressQueue(
            new TunPacketWriter(acceptedBytes, 1280), 1280, 2, 1280);
        FakeVpnProtector accept = new FakeVpnProtector(0);
        check(roundtrip(accept, allowed, true, false) == 0);
        check(accept.calls == 1);
        check(allowed.queuedPackets() == 1);
        check(allowed.drain(1) == 1);
        byte[] response = acceptedBytes.toByteArray();
        check(response.length > 28 && (response[0] & 0xff) == 0x45);
        int len = (response[2] & 0xff) * 256 + (response[3] & 0xff);
        check(len == response.length);
        check((response[9] & 0xff) == 17);
        String reply = new String(response, 28, response.length - 28, StandardCharsets.US_ASCII);
        check(reply.equals("reply-from-loopback"));
        allowed.close();

        // IPv6 loopback uses a separately tracked IPv6 socket and strict reverse policy.
        ByteArrayOutputStream v6bytes = new ByteArrayOutputStream();
        TunEgressQueue v6queue = new TunEgressQueue(
            new TunPacketWriter(v6bytes, 1280), 1280, 2, 1280);
        FakeVpnProtector v6protector = new FakeVpnProtector(0);
        check(roundtrip(v6protector, v6queue, true, true) == 0);
        check(v6protector.calls == 1 && v6queue.queuedPackets() == 1);
        check(v6queue.drain(1) == 1);
        byte[] v6response = v6bytes.toByteArray();
        check(v6response.length > 48 && (v6response[0] & 0xf0) == 0x60);
        int v6payload = ((v6response[4] & 0xff) << 8) | (v6response[5] & 0xff);
        check(v6response.length == 40 + v6payload);
        check((v6response[6] & 0xff) == 17);
        check(new String(v6response, 48, v6response.length - 48,
            StandardCharsets.US_ASCII).equals("reply-from-loopback"));
        v6queue.close();

        ByteArrayOutputStream v6deniedSink = new ByteArrayOutputStream();
        TunEgressQueue v6denied = new TunEgressQueue(
            new TunPacketWriter(v6deniedSink, 1280), 1280, 2, 1280);
        check(roundtrip(new FakeVpnProtector(0), v6denied, false, true) == -1);
        check(v6denied.queuedPackets() == 0 && v6deniedSink.size() == 0);
        v6denied.close();

        ByteArrayOutputStream blockedBytes = new ByteArrayOutputStream();
        TunEgressQueue denied = new TunEgressQueue(
            new TunPacketWriter(blockedBytes, 1280),1280,2,1280);
        check(roundtrip(new FakeVpnProtector(0), denied, false, false) == -1);
        check(denied.queuedPackets() == 0 && blockedBytes.size() == 0);
        denied.close();

        TunEgressQueue refused = new TunEgressQueue(
            new TunPacketWriter(new ByteArrayOutputStream(),1280),1280,1,1280);
        FakeVpnProtector reject = new FakeVpnProtector(1);
        check(NativeCore.probeUdpRelayLoopback(reject, refused, 12345, true, false) == -1);
        check(reject.calls == 1 && refused.queuedPackets() == 0);
        FakeVpnProtector throwsProtect = new FakeVpnProtector(2);
        check(NativeCore.probeUdpRelayLoopback(throwsProtect, refused, 12345, true, false) == -1);
        check(throwsProtect.calls == 1 && refused.queuedPackets() == 0);
        check(NativeCore.probeUdpRelayLoopback(null, refused, 12345, true, false) == -1);
        check(NativeCore.probeUdpRelayLoopback(new FakeVpnProtector(0), null, 12345, true, false) == -1);
        check(NativeCore.probeUdpRelayLoopback(new FakeVpnProtector(0), refused, 0, true, false) == -1);
        check(NativeCore.probeUdpRelayLoopback(new FakeVpnProtector(0), refused, 65536, true, false) == -1);
        refused.close();

        System.out.println("Native Rust UDP loopback relay / JNI / Java TUN queue smoke: PASS");
    }
}
