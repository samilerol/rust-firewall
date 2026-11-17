package org.netscope.ngfw;

import android.app.Activity;
import android.content.pm.PackageManager;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.text.format.Formatter;
import android.view.View;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ListView;
import android.widget.SearchView;
import android.widget.Switch;
import android.widget.TextView;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

public final class TrafficActivity extends Activity {
    private final Handler handler = new Handler(Looper.getMainLooper());
    private final Map<Integer, String> labels = new HashMap<>();
    private final Map<Integer, String> packages = new HashMap<>();
    private ArrayAdapter<String> rows;
    private List<String> shown = java.util.Collections.emptyList();
    private TextView state;
    private Switch blocked;
    private SearchView search;
    private final Runnable refresh = new Runnable() {
        @Override public void run() {
            render();
            handler.postDelayed(this, 1000);
        }
    };

    @Override public void onCreate(Bundle saved) {
        super.onCreate(saved);
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setBackgroundColor(MainActivity.BACKGROUND);
        MainActivity.applySafeInsets(root);
        LinearLayout page = new LinearLayout(this);
        page.setOrientation(LinearLayout.VERTICAL);
        page.setPadding(dp(20), dp(12), dp(20), dp(8));
        root.addView(page, new LinearLayout.LayoutParams(-1, 0, 1));

        Button back = new Button(this);
        back.setText(R.string.traffic_back);
        back.setAllCaps(false);
        back.setOnClickListener(view -> finish());
        page.addView(back, new LinearLayout.LayoutParams(-2, -2));
        page.addView(text(R.string.traffic_title, 26, MainActivity.TEXT));
        page.addView(text(R.string.traffic_scope, 13, MainActivity.MUTED));

        search = new SearchView(this);
        search.setIconifiedByDefault(false);
        search.setQueryHint(getString(R.string.traffic_search));
        page.addView(search, new LinearLayout.LayoutParams(-1, -2));
        search.setOnQueryTextListener(new SearchView.OnQueryTextListener() {
            @Override public boolean onQueryTextSubmit(String query) {
                search.clearFocus();
                return true;
            }
            @Override public boolean onQueryTextChange(String query) {
                if (rows != null) render();
                return true;
            }
        });

        blocked = new Switch(this);
        blocked.setText(R.string.traffic_blocked_only);
        blocked.setMinHeight(dp(48));
        blocked.setOnCheckedChangeListener((view, checked) -> render());
        page.addView(blocked);

        state = text(R.string.traffic_off, 14, MainActivity.MUTED);
        state.setPadding(0, dp(8), 0, dp(8));
        page.addView(state);

        ListView list = new ListView(this);
        list.setId(R.id.traffic_list);
        rows = new ArrayAdapter<>(this, android.R.layout.simple_list_item_1);
        list.setAdapter(rows);
        page.addView(list, new LinearLayout.LayoutParams(-1, 0, 1));
        page.setFocusableInTouchMode(true);
        page.requestFocus();
        setContentView(root);
    }

    private void render() {
        var snapshot = DiagnosticVpnService.trafficSnapshot();
        snapshot.sort(Comparator.comparingLong(TrafficObservations.Entry::bytes).reversed()
            .thenComparingInt(TrafficObservations.Entry::uid));
        String query = search.getQuery().toString().trim().toLowerCase(Locale.ROOT);
        List<String> next = new ArrayList<>();
        for (var entry : snapshot) {
            if (blocked.isChecked() && entry.blocked() == 0) continue;
            int uid = entry.uid();
            String title = labels.get(uid);
            if (title == null) {
                if (labels.size() >= 129) {
                    labels.clear();
                    packages.clear();
                }
                title = resolveLabel(uid);
                labels.put(uid, title);
            }
            String packageName = packages.getOrDefault(uid, "");
            if (!(title + " " + packageName).toLowerCase(Locale.ROOT).contains(query)) continue;
            String details = getString(R.string.traffic_counts, Formatter.formatShortFileSize(this, entry.bytes()),
                entry.packets(), entry.blocked());
            next.add(title + "\n" + details);
        }
        if (!next.equals(shown)) {
            shown = next;
            rows.setNotifyOnChange(false);
            rows.clear();
            rows.addAll(next);
            rows.notifyDataSetChanged();
        }
        int detail = DiagnosticVpnService.status() != DiagnosticVpnService.Status.FORWARDING
            ? R.string.traffic_off
            : Build.VERSION.SDK_INT < 29 ? R.string.traffic_old_android
            : snapshot.isEmpty() ? R.string.traffic_empty
            : next.isEmpty() ? R.string.traffic_no_match : 0;
        state.setVisibility(detail == 0 ? View.GONE : View.VISIBLE);
        if (detail != 0) state.setText(detail);
    }

    private String resolveLabel(int uid) {
        if (uid < 0) return getString(R.string.traffic_unknown);
        PackageManager manager = getPackageManager();
        String[] names = manager.getPackagesForUid(uid);
        if (names == null || names.length == 0) return getString(R.string.traffic_uid, uid);
        if (names.length > 1) return getString(R.string.traffic_shared_uid, uid);
        String name = names[0];
        packages.put(uid, name);
        try {
            return manager.getApplicationLabel(manager.getApplicationInfo(name, 0)).toString();
        } catch (PackageManager.NameNotFoundException error) {
            return name;
        }
    }

    private TextView text(int resource, int size, int color) {
        TextView view = new TextView(this);
        view.setText(resource);
        view.setTextSize(size);
        view.setTextColor(color);
        return view;
    }

    private int dp(int size) {
        return Math.round(size * getResources().getDisplayMetrics().density);
    }

    @Override protected void onStart() {
        super.onStart();
        handler.post(refresh);
    }

    @Override protected void onStop() {
        handler.removeCallbacks(refresh);
        super.onStop();
    }
}
