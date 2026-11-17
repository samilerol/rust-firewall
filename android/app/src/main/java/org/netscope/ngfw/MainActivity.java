package org.netscope.ngfw;

import android.Manifest;
import android.app.Activity;
import android.app.AlertDialog;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.content.res.ColorStateList;
import android.graphics.Color;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.graphics.drawable.RippleDrawable;
import android.net.VpnService;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.view.Gravity;
import android.view.View;
import android.widget.Button;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

public final class MainActivity extends Activity {
    private static final int NOTIFICATIONS = 2;
    private static final int CONSENT = 3;
    private static final int MICROPHONE = 5;
    private static final int DIAGNOSTIC_CONSENT = 4;
    static final int BACKGROUND = 0xff0c1420;
    static final int SURFACE = 0xff121e2c;
    static final int BORDER = 0xff26364a;
    static final int TEXT = 0xfff1f6fc;
    static final int MUTED = 0xffa8b9cd;
    private static final int MINT = 0xff59e6ca;
    private static final int AMBER = 0xffffc480;

    private final Handler handler = new Handler(Looper.getMainLooper());
    private final OnDeviceVoice voice = new OnDeviceVoice();
    private Button voiceAction;
    private TextView stateTitle;
    private TextView stateDetail;
    private View indicator;
    private Button action;
    private Button diagnostics;
    private boolean nativeReady;
    private int notificationMode;
    private int message;
    private DiagnosticVpnService.Status lastStatus;

    private final Runnable refresh = new Runnable() {
        @Override public void run() {
            showStatus();
            handler.postDelayed(this, 200);
        }
    };

    @Override public void onCreate(Bundle saved) {
        super.onCreate(saved);
        if (saved != null) notificationMode = saved.getInt("notificationMode");
        ScrollView scroll = new ScrollView(this);
        scroll.setFillViewport(true);
        scroll.setBackgroundColor(BACKGROUND);
        applySafeInsets(scroll);
        LinearLayout body = column();
        body.setPadding(dp(22), dp(20), dp(22), dp(18));
        scroll.addView(body);
        addHeader(body);
        addConnection(body);
        Button apps = button();
        apps.setId(R.id.traffic_action);
        apps.setText(R.string.traffic_title);
        styleButton(apps, SURFACE, TEXT, BORDER);
        apps.setOnClickListener(view -> startActivity(new Intent(this, TrafficActivity.class)));
        add(body, apps, 12);
        addTools(body);
        addProfile(body);
        setContentView(scroll);
        action.setOnClickListener(view -> {
            if (vpnActive()) disconnect();
            else requestVpn(CONSENT);
        });
        diagnostics.setOnClickListener(view -> new AlertDialog.Builder(this)
            .setTitle(R.string.diagnostic_title)
            .setMessage(R.string.diagnostic_body)
            .setNegativeButton(android.R.string.cancel, null)
            .setPositiveButton(R.string.diagnostic_start, (dialog, option) -> requestVpn(DIAGNOSTIC_CONSENT))
            .show());
        try { nativeReady = NativeCore.inspect(new byte[0], 0) == -1; }
        catch (LinkageError error) { nativeReady = false; }
        showStatus();
    }

    private void addTools(LinearLayout body) {
        LinearLayout tools = row();
        Button report = button();
        report.setId(R.id.traffic_report_action);
        report.setText(R.string.report_title);
        styleButton(report, SURFACE, TEXT, BORDER);
        report.setOnClickListener(view -> showTrafficReport());
        tools.addView(report, new LinearLayout.LayoutParams(0, -2, 1));

        voiceAction = button();
        voiceAction.setText(R.string.voice_title);
        styleButton(voiceAction, SURFACE, TEXT, BORDER);
        voiceAction.setOnClickListener(view -> requestVoice());
        var size = new LinearLayout.LayoutParams(0, -2, 1);
        size.setMarginStart(dp(8));
        tools.addView(voiceAction, size);
        add(body, tools, 8);
    }

    private void showTrafficReport() {
        var report = TrafficReport.summarize(DiagnosticVpnService.trafficSnapshot());
        String summary = report.packets() == 0 ? getString(R.string.report_empty)
            : getString(R.string.report_totals,
                android.text.format.Formatter.formatShortFileSize(this, report.bytes()),
                report.packets(), report.blocked(), report.knownOwners(), report.unknownPackets());
        new AlertDialog.Builder(this).setTitle(R.string.report_title)
            .setMessage(summary + "\n\n" + getString(R.string.report_scope))
            .setPositiveButton(android.R.string.ok, null).show();
    }

    private boolean vpnActive() {
        var status = DiagnosticVpnService.status();
        return status == DiagnosticVpnService.Status.FORWARDING
            || status == DiagnosticVpnService.Status.DIAGNOSTIC;
    }

    private void disconnect() {
        startService(new Intent(this, DiagnosticVpnService.class).setAction(DiagnosticVpnService.STOP));
        action.setEnabled(false);
    }

    private void requestVoice() {
        if (!getPackageManager().hasSystemFeature(PackageManager.FEATURE_MICROPHONE)
            || !OnDeviceVoice.available(this)) {
            voiceNotice(R.string.voice_unavailable);
        } else if (checkSelfPermission(Manifest.permission.RECORD_AUDIO) != PackageManager.PERMISSION_GRANTED) {
            requestPermissions(new String[]{Manifest.permission.RECORD_AUDIO}, MICROPHONE);
        } else {
            listen();
        }
    }

    private void listen() {
        voiceAction.setEnabled(false);
        voiceAction.setText(R.string.voice_listening);
        boolean started = voice.start(this, getResources().getConfiguration().getLocales().get(0),
            command -> {
                resetVoiceButton();
                handleVoice(command);
            }, () -> {
                resetVoiceButton();
                voiceNotice(R.string.voice_failure);
            });
        if (!started) {
            resetVoiceButton();
            voiceNotice(R.string.voice_unavailable);
        }
    }

    private void resetVoiceButton() {
        voiceAction.setText(R.string.voice_title);
        voiceAction.setEnabled(true);
    }

    private void voiceNotice(int message) {
        android.widget.Toast.makeText(this, message, android.widget.Toast.LENGTH_LONG).show();
    }

    private void handleVoice(VoiceCommand command) {
        switch (command) {
            case REPORT -> showTrafficReport();
            case APPS -> startActivity(new Intent(this, TrafficActivity.class));
            case STATUS -> new AlertDialog.Builder(this).setTitle(R.string.voice_status)
                .setMessage(stateTitle.getText()).setPositiveButton(android.R.string.ok, null).show();
            case CONNECT, DISCONNECT -> {
                boolean connecting = command == VoiceCommand.CONNECT;
                var current = DiagnosticVpnService.status();
                if (!action.isEnabled() || connecting == vpnActive()
                    || current == DiagnosticVpnService.Status.STARTING
                    || current == DiagnosticVpnService.Status.STOPPING) {
                    voiceNotice(R.string.voice_no_change);
                    return;
                }
                int title = connecting ? R.string.vpn_connect : R.string.vpn_disconnect;
                new AlertDialog.Builder(this).setTitle(title).setMessage(R.string.voice_confirm)
                    .setNegativeButton(android.R.string.cancel, null)
                    .setPositiveButton(title, (dialog, which) -> {
                        if (DiagnosticVpnService.status() != current || !action.isEnabled()) return;
                        if (connecting) requestVpn(CONSENT);
                        else disconnect();
                    }).show();
            }
            case UNKNOWN -> voiceNotice(R.string.voice_help);
        }
    }

    private void addHeader(LinearLayout body) {
        LinearLayout header = row();
        ImageView icon = new ImageView(this);
        icon.setImageResource(R.drawable.ic_netscope);
        header.addView(icon, new LinearLayout.LayoutParams(dp(40), dp(40)));
        TextView name = text("NetScope", 25, TEXT, true);
        var nameLayout = new LinearLayout.LayoutParams(0, -2, 1);
        nameLayout.setMarginStart(dp(10));
        header.addView(name, nameLayout);
        TextView preview = text(getString(R.string.preview_label), 10, MINT, true);
        preview.setLetterSpacing(0.09f);
        preview.setPadding(dp(10), dp(6), dp(10), dp(6));
        preview.setBackground(shape(0xff142f39, 20, 0));
        header.addView(preview);
        add(body, header, 0);
    }

    private void addConnection(LinearLayout body) {
        LinearLayout card = column();
        card.setGravity(Gravity.CENTER_HORIZONTAL);
        card.setPadding(dp(18), dp(24), dp(18), dp(18));
        GradientDrawable panel = new GradientDrawable(GradientDrawable.Orientation.TL_BR,
            new int[]{0xff183040, SURFACE});
        panel.setCornerRadius(dp(24));
        panel.setStroke(dp(1), 0xff30475a);
        card.setBackground(panel);

        android.widget.FrameLayout signal = new android.widget.FrameLayout(this);
        signal.setBackground(shape(0xff102331, 90, BORDER));
        ImageView mark = new ImageView(this);
        mark.setImageResource(R.drawable.ic_netscope);
        signal.addView(mark, new android.widget.FrameLayout.LayoutParams(dp(66), dp(66), Gravity.CENTER));
        indicator = new View(this);
        var dot = new android.widget.FrameLayout.LayoutParams(dp(12), dp(12), Gravity.BOTTOM | Gravity.END);
        dot.bottomMargin = dp(8);
        dot.setMarginEnd(dp(8));
        signal.addView(indicator, dot);
        card.addView(signal, new LinearLayout.LayoutParams(dp(90), dp(90)));

        stateTitle = text("", 26, TEXT, true);
        stateTitle.setGravity(Gravity.CENTER);
        stateTitle.setAccessibilityLiveRegion(View.ACCESSIBILITY_LIVE_REGION_POLITE);
        add(card, stateTitle, 14);
        stateDetail = text("", 14, MUTED, false);
        stateDetail.setGravity(Gravity.CENTER);
        add(card, stateDetail, 5);
        action = button();
        action.setId(R.id.vpn_action);
        add(card, action, 18);
        add(body, card, 22);
    }

    private void addProfile(LinearLayout body) {
        add(body, text(getString(R.string.profile_title), 18, TEXT, true), 24);
        add(body, text(getString(R.string.profile_subtitle), 13, MUTED, false), 4);
        LinearLayout profile = column();
        profile.setPadding(dp(15), dp(2), dp(15), dp(2));
        profile.setBackground(shape(SURFACE, 17, BORDER));
        profile.addView(profileRow(R.string.profile_web, R.string.profile_web_ports));
        View separator = new View(this);
        separator.setBackgroundColor(BORDER);
        profile.addView(separator, new LinearLayout.LayoutParams(-1, dp(1)));
        profile.addView(profileRow(R.string.profile_dns, R.string.profile_dns_name));
        add(body, profile, 12);

        diagnostics = button();
        diagnostics.setText(R.string.diagnostic_title);
        styleButton(diagnostics, SURFACE, MUTED, BORDER);
        add(body, diagnostics, 16);

        Button modem = button();
        modem.setId(R.id.modem_action);
        modem.setText(R.string.modem_title);
        styleButton(modem, SURFACE, TEXT, BORDER);
        modem.setOnClickListener(view -> startActivity(new Intent(this, ModemActivity.class)));
        add(body, modem, 8);
    }

    private LinearLayout profileRow(int label, int value) {
        LinearLayout layout = row();
        layout.setPadding(0, dp(12), 0, dp(12));
        TextView title = text(getString(label), 14, TEXT, true);
        layout.addView(title, new LinearLayout.LayoutParams(0, -2, 1));
        TextView detail = text(getString(value), 13, MUTED, false);
        detail.setGravity(Gravity.END);
        layout.addView(detail, new LinearLayout.LayoutParams(0, -2, 1));
        return layout;
    }

    private void showStatus() {
        var status = DiagnosticVpnService.status();
        if (status == lastStatus) return;
        lastStatus = status;
        boolean active = status == DiagnosticVpnService.Status.FORWARDING
            || status == DiagnosticVpnService.Status.DIAGNOSTIC;
        boolean busy = status == DiagnosticVpnService.Status.STARTING
            || status == DiagnosticVpnService.Status.STOPPING;
        int title = switch (status) {
            case IDLE -> R.string.vpn_off;
            case STARTING -> R.string.vpn_connecting;
            case STOPPING -> R.string.vpn_disconnecting;
            case FORWARDING -> R.string.vpn_connected;
            case DIAGNOSTIC -> R.string.vpn_diagnostic_active;
            case FAILED -> R.string.vpn_failed;
        };
        int detail = switch (status) {
            case FORWARDING -> R.string.vpn_connected_detail;
            case DIAGNOSTIC -> R.string.vpn_diagnostic_detail;
            case FAILED -> R.string.vpn_failed_detail;
            case STARTING, STOPPING -> 0;
            case IDLE -> R.string.vpn_off_detail;
        };
        if (!nativeReady) {
            title = R.string.vpn_unavailable;
            detail = R.string.vpn_unavailable_detail;
        } else if (message != 0 && !active && !busy) {
            detail = message;
        }
        stateTitle.setText(title);
        stateDetail.setVisibility(detail == 0 ? View.GONE : View.VISIBLE);
        if (detail != 0) stateDetail.setText(detail);
        indicator.setBackground(shape(status == DiagnosticVpnService.Status.FORWARDING ? MINT
            : status == DiagnosticVpnService.Status.DIAGNOSTIC || status == DiagnosticVpnService.Status.FAILED
                ? AMBER : MUTED, 12, SURFACE));
        action.setText(busy ? title : active ? R.string.vpn_disconnect : R.string.vpn_connect);
        styleButton(action, active || busy ? 0xff203547 : MINT, active || busy ? TEXT : BACKGROUND,
            active || busy ? BORDER : 0);
        action.setEnabled(nativeReady && !busy);
        diagnostics.setEnabled(nativeReady && !busy && !active);
        diagnostics.setAlpha(diagnostics.isEnabled() ? 1f : 0.55f);
    }

    private void setMessage(int next) {
        message = next;
        lastStatus = null;
        showStatus();
    }

    private void requestVpn(int request) {
        setMessage(0);
        if (Build.VERSION.SDK_INT >= 33
            && checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) {
            notificationMode = request;
            requestPermissions(new String[]{Manifest.permission.POST_NOTIFICATIONS}, NOTIFICATIONS);
            return;
        }
        Intent consent = VpnService.prepare(this);
        if (consent != null) startActivityForResult(consent, request);
        else startVpn(request);
    }

    private void startVpn(int request) {
        try {
            startForegroundService(new Intent(this, DiagnosticVpnService.class).setAction(
                request == DIAGNOSTIC_CONSENT ? DiagnosticVpnService.START : DiagnosticVpnService.PREVIEW));
        } catch (RuntimeException error) {
            setMessage(R.string.startup_rejected);
        }
    }

    @Override public void onRequestPermissionsResult(int request, String[] permissions, int[] results) {
        super.onRequestPermissionsResult(request, permissions, results);
        if (request == MICROPHONE) {
            if (results.length > 0 && results[0] == PackageManager.PERMISSION_GRANTED) listen();
            else voiceNotice(R.string.voice_permission);
            return;
        }
        if (request != NOTIFICATIONS) return;
        int mode = notificationMode;
        notificationMode = 0;
        if (results.length > 0 && results[0] == PackageManager.PERMISSION_GRANTED && mode != 0) {
            requestVpn(mode);
        } else {
            setMessage(R.string.notification_needed);
        }
    }

    @Override protected void onActivityResult(int request, int result, Intent data) {
        super.onActivityResult(request, result, data);
        if (request == CONSENT || request == DIAGNOSTIC_CONSENT) {
            if (result == RESULT_OK) startVpn(request);
            else setMessage(R.string.consent_needed);
        }
    }

    @Override protected void onSaveInstanceState(Bundle out) {
        super.onSaveInstanceState(out);
        out.putInt("notificationMode", notificationMode);
    }

    @Override protected void onStart() {
        super.onStart();
        handler.post(refresh);
    }

    @Override protected void onPause() {
        voice.stop();
        resetVoiceButton();
        super.onPause();
    }

    @Override protected void onStop() {
        handler.removeCallbacks(refresh);
        super.onStop();
    }

    static void applySafeInsets(View view) {
        if (Build.VERSION.SDK_INT < 35) return;
        view.setOnApplyWindowInsetsListener((root, insets) -> {
            android.graphics.Insets safe = insets.getInsets(
                android.view.WindowInsets.Type.systemBars() | android.view.WindowInsets.Type.displayCutout());
            root.setPadding(safe.left, safe.top, safe.right, safe.bottom);
            return insets;
        });
    }

    private LinearLayout column() {
        LinearLayout layout = new LinearLayout(this);
        layout.setOrientation(LinearLayout.VERTICAL);
        return layout;
    }

    private LinearLayout row() {
        LinearLayout layout = new LinearLayout(this);
        layout.setGravity(Gravity.CENTER_VERTICAL);
        return layout;
    }

    private TextView text(String value, int size, int color, boolean bold) {
        TextView view = new TextView(this);
        view.setText(value);
        view.setTextSize(size);
        view.setTextColor(color);
        if (bold) view.setTypeface(Typeface.create("sans-serif-medium", Typeface.NORMAL));
        return view;
    }

    private Button button() {
        Button button = new Button(this);
        button.setAllCaps(false);
        button.setTextSize(16);
        button.setTypeface(Typeface.create("sans-serif-medium", Typeface.NORMAL));
        button.setMinHeight(dp(50));
        button.setPadding(dp(12), dp(10), dp(12), dp(10));
        button.setStateListAnimator(null);
        return button;
    }

    private void styleButton(Button button, int fill, int text, int stroke) {
        button.setTextColor(text);
        button.setBackground(new RippleDrawable(ColorStateList.valueOf(0x3377899b),
            shape(fill, 14, stroke), null));
    }

    private GradientDrawable shape(int fill, int radius, int stroke) {
        GradientDrawable shape = new GradientDrawable();
        shape.setColor(fill);
        shape.setCornerRadius(dp(radius));
        if (stroke != 0) shape.setStroke(dp(1), stroke);
        return shape;
    }

    private void add(LinearLayout parent, View view, int margin) {
        var params = new LinearLayout.LayoutParams(-1, -2);
        params.topMargin = dp(margin);
        parent.addView(view, params);
    }

    private int dp(int size) {
        return Math.round(size * getResources().getDisplayMetrics().density);
    }
}
