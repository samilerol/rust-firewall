package org.netscope.ngfw;

import android.app.Activity;
import android.app.Instrumentation;
import android.content.Intent;
import android.net.VpnService;
import android.os.Bundle;
import android.os.SystemClock;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;

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
        try {
            activity = startActivitySync(new Intent(getTargetContext(), MainActivity.class)
                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK));
            Activity screen = activity;
            if (VpnService.prepare(screen) != null) throw new AssertionError("VPN consent unavailable");
            requireEcho(8080);
            runOnMainSync(() -> click(screen, "Start forwarding preview"));
            // Wait until the app sees the VPN's IPv4 route, then exercise both policy outcomes.
            long deadline = SystemClock.elapsedRealtime() + 15000;
            while (true) {
                try (Socket socket = new Socket()) {
                    socket.connect(new InetSocketAddress("10.0.2.2", 80), 800);
                    if ("10.111.0.1".equals(socket.getLocalAddress().getHostAddress())) break;
                } catch (IOException ignored) {
                    // VPN establishment and TCP proxy readiness are asynchronous.
                }
                if (SystemClock.elapsedRealtime() >= deadline) throw new AssertionError("VPN TCP route did not become ready");
                SystemClock.sleep(150);
            }
            requireEcho(80);
            try {
                requireEcho(8080);
                throw new AssertionError("VPN allowed the denied TCP port");
            } catch (IOException expected) {
                // The same listener was reachable before VPN startup.
            }
            runOnMainSync(() -> click(screen, "Stop VPN"));
            deadline = SystemClock.elapsedRealtime() + 5000;
            while (true) {
                try {
                    requireEcho(8080);
                    break;
                } catch (IOException error) {
                    if (SystemClock.elapsedRealtime() >= deadline) throw error;
                    SystemClock.sleep(150);
                }
            }
            result.putString("stream", "NETSCOPE_FORWARDING_SMOKE_PASS\n");
            code = Activity.RESULT_OK;
        } catch (Exception | AssertionError error) {
            result.putString("stream", "NETSCOPE_FORWARDING_SMOKE_FAIL: " + error + "\n");
        } finally {
            if (activity != null) {
                activity.stopService(new Intent(activity, DiagnosticVpnService.class));
                activity.finish();
            }
            finish(code, result);
        }
    }

    private static void requireEcho(int port) throws IOException {
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress("10.0.2.2", port), 1500);
            socket.setSoTimeout(1500);
            socket.getOutputStream().write(42);
            if (socket.getInputStream().read() != 42) throw new AssertionError("Unexpected echo on port " + port);
        }
    }

    private static void click(Activity activity, String title) {
        Button button = findButton(activity.getWindow().getDecorView(), title);
        if (button == null || !button.isEnabled() || !button.performClick()) {
            throw new AssertionError("Unavailable button: " + title);
        }
    }

    private static Button findButton(View view, String title) {
        if (view instanceof Button button && title.contentEquals(button.getText())) return button;
        if (view instanceof ViewGroup group) {
            for (int i = 0; i < group.getChildCount(); i++) {
                Button found = findButton(group.getChildAt(i), title);
                if (found != null) return found;
            }
        }
        return null;
    }
}
