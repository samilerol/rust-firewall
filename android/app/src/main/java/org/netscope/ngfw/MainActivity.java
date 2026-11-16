package org.netscope.ngfw;

import android.app.Activity;
import android.content.Intent;
import android.net.VpnService;
import android.os.Bundle;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.TextView;

/** Temporary platform consent/diagnostic screen; not the planned product UI. */
public final class MainActivity extends Activity {
    private static final int CONSENT = 1;
    private TextView status;
    private boolean nativeReady;
    @Override public void onCreate(Bundle state) {
        super.onCreate(state);
        LinearLayout layout = new LinearLayout(this);
        layout.setOrientation(LinearLayout.VERTICAL);
        layout.setPadding(32, 32, 32, 32);
        status = new TextView(this);
        status.setText("DIAGNOSTIC ONLY: starting this VPN blocks routed IPv4 and IPv6 traffic. No forwarding, app rules or production protection. Always-on is unsupported. Stopping restores normal Android routing; this app cannot enforce protection when stopped.");
        layout.addView(status);
        Button start = new Button(this);
        start.setText("Start diagnostic VPN (blocks traffic)");
        layout.addView(start);
        Button stop = new Button(this);
        stop.setText("Stop diagnostic VPN");
        layout.addView(stop);
        setContentView(layout);
        try { nativeReady = NativeCore.inspect(new byte[0], 0) == -1; }
        catch (LinkageError error) { nativeReady = false; }
        start.setEnabled(nativeReady);
        if (!nativeReady) status.append("\nRust library unavailable; VPN disabled.");
        start.setOnClickListener(view -> {
            Intent consent = VpnService.prepare(this);
            if (consent != null) startActivityForResult(consent, CONSENT);
            else startDiagnostic();
        });
        stop.setOnClickListener(view -> {
            stopService(new Intent(this, DiagnosticVpnService.class));
            status.append("\nStop requested.");
        });
    }
    private void startDiagnostic() {
        if (!nativeReady) return;
        try {
            startForegroundService(new Intent(this, DiagnosticVpnService.class).setAction(DiagnosticVpnService.START));
            status.append("\nStart requested; verify the system VPN indicator and notification.");
        } catch (RuntimeException error) { status.append("\nAndroid rejected VPN startup."); }
    }
    @Override protected void onActivityResult(int request, int result, Intent data) {
        super.onActivityResult(request, result, data);
        if (request == CONSENT && result == RESULT_OK) startDiagnostic();
    }
}
