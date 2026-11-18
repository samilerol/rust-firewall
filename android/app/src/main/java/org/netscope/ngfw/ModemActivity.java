package org.netscope.ngfw;

import android.Manifest;
import android.annotation.TargetApi;
import android.app.Activity;
import android.content.pm.PackageManager;
import android.os.Build;
import android.os.Bundle;
import android.telephony.ServiceState;
import android.telephony.SignalStrength;
import android.telephony.SubscriptionManager;
import android.telephony.TelephonyCallback;
import android.telephony.TelephonyManager;
import android.text.format.DateFormat;
import android.view.View;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ListView;
import android.widget.TextView;
import java.text.SimpleDateFormat;
import java.util.ArrayDeque;
import java.util.Date;

public final class ModemActivity extends Activity {
    private static final int PHONE_STATE_PERMISSION = 1;
    private static final int MAX_EVENTS = 24;

    private TextView status;
    private Button permission;
    private ArrayAdapter<String> events;
    private final ArrayDeque<String> history = new ArrayDeque<>(MAX_EVENTS);
    private SimpleDateFormat eventTime;
    private Monitor monitor;
    private boolean visible;
    private int lastService = Integer.MIN_VALUE;
    private int lastData = Integer.MIN_VALUE;
    private int lastNetwork = Integer.MIN_VALUE;
    private int lastSignal = Integer.MIN_VALUE;

    @Override public void onCreate(Bundle saved) {
        super.onCreate(saved);
        eventTime = new SimpleDateFormat(DateFormat.is24HourFormat(this) ? "HH:mm:ss" : "h:mm:ss a",
            getResources().getConfiguration().getLocales().get(0));
        LinearLayout frame = column();
        frame.setBackgroundColor(MainActivity.BACKGROUND);
        MainActivity.applySafeInsets(frame);
        LinearLayout page = column();
        page.setPadding(dp(20), dp(12), dp(20), dp(8));
        frame.addView(page, new LinearLayout.LayoutParams(-1, 0, 1));

        Button back = button(R.string.traffic_back);
        back.setOnClickListener(view -> finish());
        page.addView(back, new LinearLayout.LayoutParams(-2, -2));
        TextView title = text(R.string.modem_title, 25, MainActivity.TEXT);
        title.setId(R.id.modem_heading);
        page.addView(title);
        TextView scope = text(R.string.modem_scope, 14, MainActivity.MUTED);
        scope.setPadding(0, dp(6), 0, dp(8));
        page.addView(scope);

        status = text(R.string.modem_waiting, 14, MainActivity.TEXT);
        status.setPadding(0, dp(8), 0, dp(8));
        page.addView(status);
        permission = button(R.string.modem_permission_button);
        permission.setVisibility(View.GONE);
        permission.setOnClickListener(view -> requestPermissions(
            new String[]{Manifest.permission.READ_PHONE_STATE}, PHONE_STATE_PERMISSION));
        page.addView(permission, new LinearLayout.LayoutParams(-1, -2));

        ListView list = new ListView(this);
        list.setId(R.id.modem_events);
        events = new ArrayAdapter<>(this, android.R.layout.simple_list_item_1);
        list.setAdapter(events);
        page.addView(list, new LinearLayout.LayoutParams(-1, 0, 1));
        setContentView(frame);
    }

    @Override protected void onStart() {
        super.onStart();
        visible = true;
        startMonitor();
    }

    @Override protected void onStop() {
        visible = false;
        if (monitor != null && Build.VERSION.SDK_INT >= 31) {
            Monitor old = monitor;
            monitor = null;
            try { old.stop(); } catch (RuntimeException ignored) {
                // Registration may already have been revoked by Android.
            }
        }
        super.onStop();
    }

    @Override public void onRequestPermissionsResult(int code, String[] names, int[] grants) {
        super.onRequestPermissionsResult(code, names, grants);
        if (code == PHONE_STATE_PERMISSION && visible) startMonitor();
    }

    private void startMonitor() {
        if (monitor != null) return;
        permission.setVisibility(View.GONE);
        if (Build.VERSION.SDK_INT < 31
            || !getPackageManager().hasSystemFeature(PackageManager.FEATURE_TELEPHONY)) {
            status.setText(R.string.modem_unavailable);
            return;
        }
        if (checkSelfPermission(Manifest.permission.READ_PHONE_STATE) != PackageManager.PERMISSION_GRANTED) {
            status.setText(R.string.modem_permission_intro);
            permission.setVisibility(View.VISIBLE);
            return;
        }
        TelephonyManager manager = getSystemService(TelephonyManager.class);
        int subscription = SubscriptionManager.getDefaultDataSubscriptionId();
        if (manager == null || !SubscriptionManager.isValidSubscriptionId(subscription)) {
            status.setText(R.string.modem_no_sim);
            return;
        }
        status.setText(R.string.modem_waiting);
        lastService = lastData = lastNetwork = lastSignal = Integer.MIN_VALUE;
        try {
            monitor = new Monitor(manager.createForSubscriptionId(subscription));
            monitor.start();
        } catch (RuntimeException error) {
            monitor = null;
            status.setText(R.string.modem_unavailable);
        }
    }

    private void addEvent(String message) {
        status.setText(R.string.modem_live);
        String time = eventTime.format(new Date());
        if (history.size() >= MAX_EVENTS) history.removeLast();
        history.addFirst(time + "  " + message);
        events.setNotifyOnChange(false);
        events.clear();
        events.addAll(history);
        events.notifyDataSetChanged();
    }

    static int networkLabel(int network) {
        return switch (network) {
            case TelephonyManager.NETWORK_TYPE_LTE -> R.string.modem_lte;
            case TelephonyManager.NETWORK_TYPE_NR -> R.string.modem_nr;
            case TelephonyManager.NETWORK_TYPE_GPRS, TelephonyManager.NETWORK_TYPE_EDGE,
                 TelephonyManager.NETWORK_TYPE_CDMA, TelephonyManager.NETWORK_TYPE_1xRTT,
                 TelephonyManager.NETWORK_TYPE_GSM -> R.string.modem_2g;
            case TelephonyManager.NETWORK_TYPE_UMTS, TelephonyManager.NETWORK_TYPE_HSDPA,
                 TelephonyManager.NETWORK_TYPE_HSUPA, TelephonyManager.NETWORK_TYPE_HSPA,
                 TelephonyManager.NETWORK_TYPE_HSPAP, TelephonyManager.NETWORK_TYPE_TD_SCDMA,
                 TelephonyManager.NETWORK_TYPE_EVDO_0, TelephonyManager.NETWORK_TYPE_EVDO_A,
                 TelephonyManager.NETWORK_TYPE_EVDO_B, TelephonyManager.NETWORK_TYPE_EHRPD -> R.string.modem_3g;
            case TelephonyManager.NETWORK_TYPE_IWLAN -> R.string.modem_iwlan;
            default -> R.string.modem_unknown;
        };
    }

    @TargetApi(31)
    private final class Monitor extends TelephonyCallback implements
            TelephonyCallback.ServiceStateListener, TelephonyCallback.DataConnectionStateListener,
            TelephonyCallback.SignalStrengthsListener {
        private final TelephonyManager manager;

        Monitor(TelephonyManager manager) {
            this.manager = manager;
        }

        void start() {
            if (Build.VERSION.SDK_INT >= 33) {
                manager.registerTelephonyCallback(TelephonyManager.INCLUDE_LOCATION_DATA_NONE,
                    getMainExecutor(), this);
            } else {
                manager.registerTelephonyCallback(getMainExecutor(), this);
            }
        }

        void stop() {
            manager.unregisterTelephonyCallback(this);
        }

        @Override public void onServiceStateChanged(ServiceState state) {
            if (monitor != this || lastService == state.getState()) return;
            lastService = state.getState();
            int label = switch (lastService) {
                case ServiceState.STATE_IN_SERVICE -> R.string.modem_service_in;
                case ServiceState.STATE_OUT_OF_SERVICE -> R.string.modem_service_out;
                case ServiceState.STATE_EMERGENCY_ONLY -> R.string.modem_service_emergency;
                case ServiceState.STATE_POWER_OFF -> R.string.modem_service_off;
                default -> R.string.modem_unknown;
            };
            addEvent(getString(R.string.modem_service_event, getString(label)));
        }

        @Override public void onDataConnectionStateChanged(int state, int networkType) {
            if (monitor != this || (lastData == state && lastNetwork == networkType)) return;
            lastData = state;
            lastNetwork = networkType;
            int label = switch (state) {
                case TelephonyManager.DATA_CONNECTED -> R.string.modem_data_connected;
                case TelephonyManager.DATA_CONNECTING -> R.string.modem_data_connecting;
                case TelephonyManager.DATA_DISCONNECTED -> R.string.modem_data_disconnected;
                case TelephonyManager.DATA_SUSPENDED -> R.string.modem_data_suspended;
                default -> R.string.modem_unknown;
            };
            addEvent(getString(R.string.modem_data_event, getString(label),
                getString(networkLabel(networkType))));
        }

        @Override public void onSignalStrengthsChanged(SignalStrength signal) {
            if (monitor != this || lastSignal == signal.getLevel()) return;
            lastSignal = signal.getLevel();
            addEvent(getString(R.string.modem_signal_event, lastSignal));
        }
    }

    private LinearLayout column() {
        LinearLayout view = new LinearLayout(this);
        view.setOrientation(LinearLayout.VERTICAL);
        return view;
    }

    private Button button(int message) {
        Button view = new Button(this);
        view.setText(message);
        view.setAllCaps(false);
        return view;
    }

    private TextView text(int message, int size, int color) {
        TextView view = new TextView(this);
        view.setText(message);
        view.setTextSize(size);
        view.setTextColor(color);
        return view;
    }

    private int dp(int size) {
        return Math.round(size * getResources().getDisplayMetrics().density);
    }
}
