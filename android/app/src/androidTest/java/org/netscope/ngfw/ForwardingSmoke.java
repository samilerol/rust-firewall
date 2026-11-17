package org.netscope.ngfw;

import android.app.Activity;
import android.app.Instrumentation;
import android.content.Intent;
import android.net.VpnService;
import android.os.Bundle;
import android.os.SystemClock;
import android.widget.Button;
import java.io.IOException;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.util.Arrays;

/** Debug instrumentation driven by the emulator runner and its two local echo sockets. */
public final class ForwardingSmoke extends Instrumentation {
    @Override public void onCreate(Bundle arguments) {
        super.onCreate(arguments);
        start();
    }

    @Override public void onStart() {
        Activity activity = null;
        Bundle result = new Bundle();
        int code = Activity.RESULT_CANCELED;
        String phase = "launch";
        try {
            activity = startActivitySync(new Intent(getTargetContext(), MainActivity.class)
                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK));
            Activity screen = activity;
            if (VpnService.prepare(screen) != null) throw new AssertionError("VPN consent unavailable");
            phase = "direct baseline";
            requireEcho(8080);
            phase = "direct DNS fixture";
            requireDnsUdp("10.0.2.2", false);
            phase = "VPN startup";
            click(screen, R.string.vpn_connect);
            awaitEcho(80, "10.111.0.1");
            phase = "denied TCP port";
            requireBlockedTcp();
            phase = "IPv6 route capture";
            try (DatagramSocket ipv6 = new DatagramSocket(null)) {
                ipv6.connect(new InetSocketAddress("2001:db8::53", 53));
                if (!ipv6.getLocalAddress().equals(java.net.InetAddress.getByName("fd12:3456:789a::1"))) {
                    throw new AssertionError("IPv6 did not select the VPN interface");
                }
            }
            phase = "allowed UDP DNS through TUN";
            requireDnsUdp("1.1.1.1", true);
            phase = "allowed TCP DNS through TUN";
            requireDnsTcp();
            phase = "denied alternate DNS endpoint";
            try {
                requireDnsUdp("10.0.2.2", true);
                throw new AssertionError("Alternate DNS endpoint was reachable through VPN");
            } catch (SocketTimeoutException expected) {
                // The same fixture answered this query before VPN startup.
            }
            phase = "restoration after Stop";
            click(screen, R.string.vpn_disconnect);
            awaitEcho(8080, null);
            phase = "forwarding session restart";
            click(screen, R.string.vpn_connect);
            awaitEcho(80, "10.111.0.1");
            requireBlockedTcp();
            click(screen, R.string.vpn_disconnect);
            phase = "restoration after second Stop";
            awaitEcho(8080, null);
            result.putString("stream", "NETSCOPE_FORWARDING_SMOKE_PASS\n");
            code = Activity.RESULT_OK;
        } catch (Exception | AssertionError error) {
            result.putString("stream", "NETSCOPE_FORWARDING_SMOKE_FAIL (" + phase + "): " + error + "\n");
        } finally {
            if (activity != null) {
                activity.stopService(new Intent(activity, DiagnosticVpnService.class));
                activity.finish();
            }
            finish(code, result);
        }
    }

    private static final byte[] QUERY = hex("1234010000010000000000000463697479076578616d706c650000010001");
    private static final byte[] ANSWER = hex("1234818000010001000000000463697479076578616d706c650000010001c00c00010001000000000004c000022a");

    private static byte[] hex(String text) {
        byte[] bytes = new byte[text.length() / 2];
        for (int i = 0; i < bytes.length; i++) {
            bytes[i] = (byte) Integer.parseInt(text.substring(2 * i, 2 * i + 2), 16);
        }
        return bytes;
    }

    private static void requireDnsUdp(String server, boolean viaVpn) throws IOException {
        try (DatagramSocket socket = new DatagramSocket()) {
            socket.connect(new InetSocketAddress(server, 53));
            if (viaVpn && !"10.111.0.1".equals(socket.getLocalAddress().getHostAddress())) {
                throw new AssertionError("UDP DNS escaped the VPN interface");
            }
            socket.setSoTimeout(2500);
            socket.send(new DatagramPacket(QUERY, QUERY.length));
            byte[] bytes = new byte[512];
            DatagramPacket reply = new DatagramPacket(bytes, bytes.length);
            socket.receive(reply);
            if (!Arrays.equals(Arrays.copyOf(bytes, reply.getLength()), ANSWER)) {
                throw new AssertionError("Unexpected UDP DNS reply");
            }
        }
    }

    private static void requireDnsTcp() throws IOException {
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress("1.1.1.1", 53), 2500);
            requireVpnSource(socket);
            socket.setSoTimeout(2500);
            DataOutputStream out = new DataOutputStream(socket.getOutputStream());
            out.writeShort(QUERY.length);
            out.write(QUERY);
            DataInputStream in = new DataInputStream(socket.getInputStream());
            if (in.readUnsignedShort() != ANSWER.length || !Arrays.equals(in.readNBytes(ANSWER.length), ANSWER)) {
                throw new AssertionError("Unexpected TCP DNS reply");
            }
        }
    }

    private static void requireVpnSource(Socket socket) {
        if (!"10.111.0.1".equals(socket.getLocalAddress().getHostAddress())) {
            throw new AssertionError("TCP did not select the VPN interface");
        }
    }

    private static void requireBlockedTcp() throws IOException {
        try (Socket socket = new Socket()) {
            try {
                socket.connect(new InetSocketAddress("10.0.2.2", 8080), 1500);
            } catch (SocketTimeoutException expected) {
                return;
            }
            throw new AssertionError("VPN allowed the denied TCP port to connect");
        }
    }

    private static void awaitEcho(int port, String expectedSource) throws IOException {
        long deadline = SystemClock.elapsedRealtime() + 20000;
        while (true) {
            try (Socket socket = new Socket()) {
                socket.connect(new InetSocketAddress("10.0.2.2", port), 1500);
                if (expectedSource != null && !expectedSource.equals(socket.getLocalAddress().getHostAddress())) {
                    throw new IOException("VPN is not the selected route");
                }
                socket.setSoTimeout(1500);
                socket.getOutputStream().write(42);
                if (socket.getInputStream().read() == 42) return;
                throw new IOException("Unexpected echo on port " + port);
            } catch (IOException error) {
                if (SystemClock.elapsedRealtime() >= deadline) throw error;
                SystemClock.sleep(150);
            }
        }
    }

    private static void requireEcho(int port) throws IOException {
        awaitEcho(port, null);
    }

    private void click(Activity activity, int label) {
        long deadline = SystemClock.elapsedRealtime() + 5000;
        boolean[] clicked = {false};
        while (!clicked[0] && SystemClock.elapsedRealtime() < deadline) {
            runOnMainSync(() -> {
                Button button = activity.findViewById(R.id.vpn_action);
                if (button != null && button.isEnabled()
                    && activity.getString(label).contentEquals(button.getText())) {
                    clicked[0] = button.performClick();
                }
            });
            if (!clicked[0]) SystemClock.sleep(50);
        }
        if (!clicked[0]) throw new AssertionError("Unavailable VPN action: " + activity.getString(label));
    }
}
