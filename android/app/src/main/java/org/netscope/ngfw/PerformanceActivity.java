package org.netscope.ngfw;

import android.app.Activity;
import android.app.ActivityManager;
import android.graphics.drawable.GradientDrawable;
import android.os.Bundle;
import android.os.Debug;
import android.os.Handler;
import android.os.HandlerThread;
import android.os.SystemClock;
import android.text.format.Formatter;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import java.text.NumberFormat;

public final class PerformanceActivity extends Activity {
    private static final long SAMPLE_MS = 2000;
    private HandlerThread samplingThread;
    private Handler worker;
    private TextView cpu;
    private TextView processMemory;
    private TextView deviceMemory;

    @Override protected void onCreate(Bundle saved) {
        super.onCreate(saved);
        ScrollView frame = new ScrollView(this);
        frame.setFillViewport(true);
        frame.setBackgroundColor(MainActivity.BACKGROUND);
        MainActivity.applySafeInsets(frame);
        LinearLayout body = column();
        body.setPadding(dp(20), dp(12), dp(20), dp(16));
        frame.addView(body);

        Button back = new Button(this);
        back.setText(R.string.traffic_back);
        back.setAllCaps(false);
        back.setOnClickListener(view -> finish());
        body.addView(back, new LinearLayout.LayoutParams(-2, -2));
        body.addView(text(R.string.performance_title, 25, MainActivity.TEXT));
        body.addView(text(R.string.performance_scope, 14, MainActivity.MUTED));
        cpu = addMetric(body, R.string.performance_cpu, R.string.performance_cpu_explanation, R.id.performance_cpu);
        processMemory = addMetric(body, R.string.performance_app_ram,
            R.string.performance_app_ram_explanation, R.id.performance_app_ram);
        deviceMemory = addMetric(body, R.string.performance_device_ram,
            R.string.performance_device_ram_explanation, R.id.performance_device_ram);
        setContentView(frame);
    }

    @Override protected void onStart() {
        super.onStart();
        HandlerThread thread = new HandlerThread("netscope-resource-sample");
        thread.start();
        samplingThread = thread;
        Handler sampler = new Handler(thread.getLooper());
        worker = sampler;
        ActivityManager manager = getSystemService(ActivityManager.class);
        sampler.post(new Runnable() {
            private long previousWall = -1;
            private long previousCpu = -1;
            private final ActivityManager.MemoryInfo memory = new ActivityManager.MemoryInfo();

            @Override public void run() {
                long wall = SystemClock.elapsedRealtime();
                long elapsedCpu = android.os.Process.getElapsedCpuTime();
                double utilization = cpuShare(previousWall, previousCpu, wall, elapsedCpu);
                previousWall = wall;
                previousCpu = elapsedCpu;
                long processBytes = Debug.getPss() * 1024L;
                if (manager != null) manager.getMemoryInfo(memory);
                long available = memory.availMem;
                long total = memory.totalMem;
                runOnUiThread(() -> {
                    if (samplingThread != thread) return;
                    render(utilization, processBytes, available, total);
                });
                sampler.postDelayed(this, SAMPLE_MS);
            }
        });
    }

    @Override protected void onStop() {
        HandlerThread old = samplingThread;
        samplingThread = null;
        if (worker != null) worker.removeCallbacksAndMessages(null);
        worker = null;
        if (old != null) old.quitSafely();
        super.onStop();
    }

    static double cpuShare(long previousWall, long previousCpu, long wall, long cpu) {
        if (previousWall < 0 || previousCpu < 0 || wall <= previousWall || cpu < previousCpu) {
            return Double.NaN;
        }
        return (double) (cpu - previousCpu) / (wall - previousWall);
    }

    private void render(double utilization, long processBytes, long available, long total) {
        if (Double.isNaN(utilization)) {
            cpu.setText(R.string.performance_waiting);
        } else {
            NumberFormat percent = NumberFormat.getPercentInstance(
                getResources().getConfiguration().getLocales().get(0));
            percent.setMaximumFractionDigits(1);
            cpu.setText(percent.format(utilization));
        }
        if (processBytes > 0) {
            processMemory.setText(Formatter.formatShortFileSize(this, processBytes));
        } else {
            processMemory.setText(R.string.performance_not_available);
        }
        if (total > 0) {
            deviceMemory.setText(getString(R.string.performance_available,
                Formatter.formatShortFileSize(this, available), Formatter.formatShortFileSize(this, total)));
        } else {
            deviceMemory.setText(R.string.performance_not_available);
        }
    }

    private TextView addMetric(LinearLayout body, int title, int detail, int id) {
        LinearLayout card = column();
        GradientDrawable background = new GradientDrawable();
        background.setColor(MainActivity.SURFACE);
        background.setCornerRadius(dp(16));
        background.setStroke(dp(1), MainActivity.BORDER);
        card.setBackground(background);
        card.setPadding(dp(16), dp(12), dp(16), dp(12));
        card.addView(text(title, 15, MainActivity.MUTED));
        TextView value = text(R.string.performance_waiting, 24, MainActivity.TEXT);
        value.setId(id);
        card.addView(value);
        card.addView(text(detail, 13, MainActivity.MUTED));
        LinearLayout.LayoutParams size = new LinearLayout.LayoutParams(-1, -2);
        size.topMargin = dp(12);
        body.addView(card, size);
        return value;
    }

    private LinearLayout column() {
        LinearLayout view = new LinearLayout(this);
        view.setOrientation(LinearLayout.VERTICAL);
        return view;
    }

    private TextView text(int label, int size, int color) {
        TextView view = new TextView(this);
        view.setText(label);
        view.setTextSize(size);
        view.setTextColor(color);
        return view;
    }

    private int dp(int size) {
        return Math.round(size * getResources().getDisplayMetrics().density);
    }
}
