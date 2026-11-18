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
            phase = "voice command mapping and report totals";
            verifyVoiceCommandsAndReport();
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
            phase = "upstream-refused TCP connect is reported as refused";
            requireRefusedTcp();
            phase = "denied alternate DNS endpoint";
            try {
                requireDnsUdp("10.0.2.2", true);
                throw new AssertionError("Alternate DNS endpoint was reachable through VPN");
            } catch (SocketTimeoutException expected) {
                // The same fixture answered this query before VPN startup.
            }
            phase = "application attribution and live Apps screen";
            requireObservedApp(screen);
            phase = "live session traffic report";
            requireReport(screen);
            phase = "restoration after Stop";
            click(screen, R.string.vpn_disconnect);
            awaitEcho(8080, null);
            if (!DiagnosticVpnService.trafficSnapshot().isEmpty()) {
                throw new AssertionError("Traffic counts survived Stop");
            }
            phase = "forwarding session restart";
            click(screen, R.string.vpn_connect);
            awaitEcho(80, "10.111.0.1");
            requireBlockedTcp();
            click(screen, R.string.vpn_disconnect);
            phase = "restoration after second Stop";
            awaitEcho(8080, null);
            phase = "Android modem diagnostics";
            requireModemScreen(screen);
            phase = "live CPU and memory performance";
            requirePerformanceScreen(screen);
            phase = "saved app rule denies a profile-allowed connection";
            requireAppBlock(screen);
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

    /** The profile allows TCP 443; the fixture refuses it upstream, so the app must see a refusal. */
    private static void requireRefusedTcp() throws IOException {
        long started = SystemClock.elapsedRealtime();
        try (Socket socket = new Socket()) {
            try {
                socket.connect(new InetSocketAddress("10.0.2.2", 443), 4000);
            } catch (java.net.ConnectException expected) {
                requireVpnSource(socket);
                if (SystemClock.elapsedRealtime() - started > 3500) {
                    throw new AssertionError("Refusal arrived only after " + (SystemClock.elapsedRealtime() - started) + " ms");
                }
                return;
            } catch (SocketTimeoutException timeout) {
                throw new AssertionError("Refused upstream connect hung until the timeout");
            }
            throw new AssertionError("VPN reported a connection the upstream refused as established");
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

    private static void verifyVoiceCommandsAndReport() {
        if (VoiceCommand.parse(" Trafik RAPORU! ") != VoiceCommand.REPORT
            || VoiceCommand.parse("BAĞLANTIYI KES") != VoiceCommand.DISCONNECT
            || VoiceCommand.parse("VPN status") != VoiceCommand.STATUS
            || VoiceCommand.parse("don't disconnect") != VoiceCommand.UNKNOWN
            || VoiceCommand.parse("connect and disconnect") != VoiceCommand.UNKNOWN) {
            throw new AssertionError("Unexpected voice command mapping");
        }
        TrafficReport report = TrafficReport.summarize(java.util.Arrays.asList(
            new TrafficObservations.Entry(10001, 100, 4, 1, 1),
            new TrafficObservations.Entry(-1, 20, 1, 0, 0)));
        if (!report.equals(new TrafficReport(120, 5, 1, 1, 1, 1))) {
            throw new AssertionError("Traffic report totals are incorrect");
        }
    }

    private void requireReport(Activity screen) {
        if (TrafficReport.summarize(DiagnosticVpnService.trafficSnapshot()).blocked() == 0) {
            throw new AssertionError("Live report did not count profile blocks");
        }
        runOnMainSync(() -> screen.findViewById(R.id.traffic_report_action).performClick());
        var ui = getUiAutomation();
        long deadline = SystemClock.elapsedRealtime() + 5000;
        while (true) {
            var root = ui.getRootInActiveWindow();
            if (root != null && !root.findAccessibilityNodeInfosByText("Blocked by network profile:").isEmpty()) {
                ui.performGlobalAction(android.accessibilityservice.AccessibilityService.GLOBAL_ACTION_BACK);
                waitForIdleSync();
                return;
            }
            if (SystemClock.elapsedRealtime() >= deadline) throw new AssertionError("Live report did not appear");
            SystemClock.sleep(100);
        }
    }

    private void requireAppBlock(Activity screen) throws IOException {
        if (!AppBlockRules.save(getTargetContext(), java.util.Collections.singleton(getTargetContext().getPackageName()))) {
            throw new AssertionError("Could not store app rule");
        }
        try {
            click(screen, R.string.vpn_connect);
            long deadline = SystemClock.elapsedRealtime() + 10000;
            while (true) {
                try (DatagramSocket socket = new DatagramSocket()) {
                    socket.connect(new InetSocketAddress("10.0.2.2", 53));
                    if ("10.111.0.1".equals(socket.getLocalAddress().getHostAddress())) break;
                }
                if (SystemClock.elapsedRealtime() >= deadline) throw new AssertionError("VPN route did not start");
                SystemClock.sleep(100);
            }
            try (Socket denied = new Socket()) {
                try {
                    denied.connect(new InetSocketAddress("10.0.2.2", 80), 1500);
                    throw new AssertionError("App rule allowed a connection to port 80");
                } catch (SocketTimeoutException expected) {
                    // This port was reachable through the previous unblocked VPN session.
                }
            }
            int uid = android.os.Process.myUid();
            if (DiagnosticVpnService.trafficSnapshot().stream().noneMatch(
                item -> item.uid() == uid && item.appBlocks() > 0)) {
                throw new AssertionError("The blocked app was not identified in the counters");
            }
            click(screen, R.string.vpn_disconnect);
            awaitEcho(8080, null);
        } finally {
            AppBlockRules.save(getTargetContext(), java.util.Collections.emptySet());
        }
        click(screen, R.string.vpn_connect);
        awaitEcho(80, "10.111.0.1");
        click(screen, R.string.vpn_disconnect);
        awaitEcho(8080, null);
    }

    private void requirePerformanceScreen(Activity screen) {
        if (PerformanceActivity.cpuShare(100, 10, 300, 110) != 0.5
            || PerformanceActivity.cpuShare(100, 10, 300, 310) != 1.5
            || !Double.isNaN(PerformanceActivity.cpuShare(100, 10, 100, 10))) {
            throw new AssertionError("CPU time share is incorrect");
        }

        ActivityMonitor monitor = addMonitor(PerformanceActivity.class.getName(), null, false);
        runOnMainSync(() -> screen.findViewById(R.id.performance_action).performClick());
        Activity performance = waitForMonitorWithTimeout(monitor, 5000);
        removeMonitor(monitor);
        if (performance == null) throw new AssertionError("Performance did not open");
        try {
            long deadline = SystemClock.elapsedRealtime() + 7500;
            boolean[] sampled = {false};
            while (SystemClock.elapsedRealtime() < deadline) {
                runOnMainSync(() -> {
                    String waiting = performance.getString(R.string.performance_waiting);
                    String unavailable = performance.getString(R.string.performance_not_available);
                    sampled[0] = true;
                    for (int id : new int[]{R.id.performance_cpu, R.id.performance_app_ram, R.id.performance_device_ram}) {
                        android.widget.TextView value = performance.findViewById(id);
                        String text = value.getText().toString();
                        if (text.isEmpty() || waiting.equals(text) || unavailable.equals(text)) sampled[0] = false;
                    }
                });
                if (sampled[0]) return;
                SystemClock.sleep(100);
            }
            throw new AssertionError("CPU or memory readings did not become available");
        } finally {
            runOnMainSync(performance::finish);
            waitForIdleSync();
        }
    }

    private void requireModemScreen(Activity screen) {
        if (ModemActivity.networkLabel(android.telephony.TelephonyManager.NETWORK_TYPE_LTE) != R.string.modem_lte
            || ModemActivity.networkLabel(android.telephony.TelephonyManager.NETWORK_TYPE_NR) != R.string.modem_nr
            || ModemActivity.networkLabel(Integer.MAX_VALUE) != R.string.modem_unknown) {
            throw new AssertionError("Modem network labels are incorrect");
        }
        ActivityMonitor monitor = addMonitor(ModemActivity.class.getName(), null, false);
        runOnMainSync(() -> screen.findViewById(R.id.modem_action).performClick());
        Activity modem = waitForMonitorWithTimeout(monitor, 5000);
        removeMonitor(monitor);
        if (modem == null) throw new AssertionError("Modem diagnostics did not open");
        try {
            long deadline = SystemClock.elapsedRealtime() + 5000;
            int[] eventCount = {0};
            while (SystemClock.elapsedRealtime() < deadline) {
                runOnMainSync(() -> {
                    android.widget.ListView list = modem.findViewById(R.id.modem_events);
                    eventCount[0] = list.getAdapter().getCount();
                });
                if (eventCount[0] > 0) return;
                SystemClock.sleep(100);
            }
            throw new AssertionError("No public Android telephony callback was displayed");
        } finally {
            runOnMainSync(modem::finish);
            waitForIdleSync();
        }
    }

    private void requireObservedApp(Activity screen) throws IOException {
        int uid = android.os.Process.myUid();
        boolean found = DiagnosticVpnService.trafficSnapshot().stream().anyMatch(
            entry -> entry.uid() == uid && entry.bytes() > 0 && entry.blocked() > 0);
        if (!found) throw new AssertionError("Android did not attribute allowed and blocked traffic to the test app");

        ActivityMonitor monitor = addMonitor(TrafficActivity.class.getName(), null, false);
        runOnMainSync(() -> screen.findViewById(R.id.traffic_action).performClick());
        Activity traffic = waitForMonitorWithTimeout(monitor, 5000);
        removeMonitor(monitor);
        if (traffic == null) throw new AssertionError("Apps screen did not open");
        try {
            waitForIdleSync();
            runOnMainSync(() -> {
                android.widget.ListView list = traffic.findViewById(R.id.traffic_list);
                boolean listed = false;
                for (int i = 0; i < list.getAdapter().getCount(); i++) {
                    if (String.valueOf(list.getAdapter().getItem(i)).contains("NetScope")) listed = true;
                }
                if (!listed) throw new AssertionError("NetScope's observed traffic is not listed");
            });
            // Capture the Apps window after it gains focus, beyond the transition animation.
            long screenshotDeadline = SystemClock.elapsedRealtime() + 5000;
            while (!traffic.hasWindowFocus()) {
                if (SystemClock.elapsedRealtime() >= screenshotDeadline) {
                    throw new AssertionError("Apps screen did not gain focus");
                }
                SystemClock.sleep(50);
            }
            SystemClock.sleep(350);
            android.graphics.Bitmap screenshot = getUiAutomation().takeScreenshot();
            if (screenshot == null) throw new AssertionError("Apps screenshot unavailable");
            try (var output = getTargetContext().openFileOutput("netscope-apps.png", 0)) {
                screenshot.compress(android.graphics.Bitmap.CompressFormat.PNG, 100, output);
            } finally {
                screenshot.recycle();
            }
        } finally {
            runOnMainSync(traffic::finish);
            waitForIdleSync();
        }
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
