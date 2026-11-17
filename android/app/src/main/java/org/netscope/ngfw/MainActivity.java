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
    private static final int CONSENT_PREVIEW = 3;
    private TextView status;
    private boolean nativeReady;
    @Override public void onCreate(Bundle state) {
        super.onCreate(state);
        LinearLayout layout = new LinearLayout(this);
        layout.setOrientation(LinearLayout.VERTICAL);
        layout.setPadding(32, 32, 32, 32);
        status = new TextView(this);
        status.setText("Forwarding preview allows TCP ports 80 and 443 plus classic DNS to Cloudflare (1.1.1.1). Other routed traffic is blocked. Diagnostic mode blocks all routed traffic. Stopping restores normal Android routing.");
        layout.addView(status);
        Button start = new Button(this);
        start.setText("Start diagnostic VPN (blocks traffic)");
        layout.addView(start);
        Button preview = new Button(this);
        preview.setText("Start forwarding preview");
        layout.addView(preview);
        Button stop = new Button(this);
        stop.setText("Stop VPN");
        layout.addView(stop);
        setContentView(layout);
        try { nativeReady = NativeCore.inspect(new byte[0], 0) == -1; }
        catch (LinkageError error) { nativeReady = false; }
        start.setEnabled(nativeReady);
        preview.setEnabled(nativeReady);
        if (!nativeReady) status.append("\nRust library unavailable; VPN disabled.");
        start.setOnClickListener(view -> requestVpn(CONSENT));
        preview.setOnClickListener(view -> requestVpn(CONSENT_PREVIEW));
        stop.setOnClickListener(view -> {
            stopService(new Intent(this, DiagnosticVpnService.class));
            status.append("\nStop requested.");
        });
    }
    private void requestVpn(int request) {
            if (android.os.Build.VERSION.SDK_INT >= 33 && checkSelfPermission(android.Manifest.permission.POST_NOTIFICATIONS) != android.content.pm.PackageManager.PERMISSION_GRANTED) {
                requestPermissions(new String[]{android.Manifest.permission.POST_NOTIFICATIONS}, 2);
                status.append("\nAllow notifications, then tap Start again. The VPN requires visible stop controls.");
                return;
            }
            Intent consent = VpnService.prepare(this);
            if (consent != null) startActivityForResult(consent, request);
            else startVpn(request);
    }
    private void startVpn(int request) {
        if (!nativeReady) return;
        try {
            startForegroundService(new Intent(this, DiagnosticVpnService.class).setAction(request == CONSENT_PREVIEW ? DiagnosticVpnService.PREVIEW : DiagnosticVpnService.START));
            status.append("\nStart requested; verify the system VPN indicator and notification.");
        } catch (RuntimeException error) { status.append("\nAndroid rejected VPN startup."); }
    }
    @Override protected void onActivityResult(int request, int result, Intent data) {
        super.onActivityResult(request, result, data);
        if ((request == CONSENT || request == CONSENT_PREVIEW) && result == RESULT_OK) startVpn(request);
    }
}
