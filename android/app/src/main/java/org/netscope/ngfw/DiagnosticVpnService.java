package org.netscope.ngfw;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Intent;
import android.content.pm.ServiceInfo;
import android.net.VpnService;
import android.os.Build;
import android.os.ParcelFileDescriptor;
import android.system.ErrnoException;
import android.system.Os;
import android.system.OsConstants;
import android.system.StructPollfd;
import java.io.IOException;
import java.util.concurrent.atomic.AtomicBoolean;

/** User-selected diagnostic or forwarding preview. One worker owns the TUN. */
public final class DiagnosticVpnService extends VpnService {
    public static final String START = "org.netscope.ngfw.START_DIAGNOSTIC";
    public static final String PREVIEW = "org.netscope.ngfw.START_PREVIEW";
    static final String STOP = "org.netscope.ngfw.STOP_DIAGNOSTIC";
    private static final String CHANNEL = "diagnostic-vpn";
    enum Status { IDLE, STARTING, FORWARDING, DIAGNOSTIC, STOPPING, FAILED }

    // Service callbacks and worker completion messages update this on the main thread.
    private static Status status = Status.IDLE;
    private static volatile TrafficObservations traffic;

    static java.util.List<TrafficObservations.Entry> trafficSnapshot() {
        TrafficObservations current = traffic;
        return current == null ? new java.util.ArrayList<>() : current.snapshot();
    }
    private static Reader activeWorker;
    private Reader reader;

    static Status status() { return status; }
    // Dormant native default-deny context, never used by the diagnostic packet loop.
    private volatile long udpSessionId;
    @Override public int onStartCommand(Intent intent, int flags, int id) {
        boolean forwarding = intent != null && PREVIEW.equals(intent.getAction());
        if (!forwarding && (intent == null || !START.equals(intent.getAction()))) { shutdown(); stopSelf(); return START_NOT_STICKY; }
        if (activeWorker != null) return START_NOT_STICKY;
        status = Status.STARTING;
        NotificationManager manager = getSystemService(NotificationManager.class);
        manager.createNotificationChannel(new NotificationChannel(CHANNEL, "Diagnostic VPN", NotificationManager.IMPORTANCE_LOW));
        PendingIntent stop = PendingIntent.getService(this, 0, new Intent(this, DiagnosticVpnService.class).setAction(STOP), PendingIntent.FLAG_IMMUTABLE | PendingIntent.FLAG_UPDATE_CURRENT);
        Notification notification = new Notification.Builder(this, CHANNEL)
            .setSmallIcon(android.R.drawable.ic_dialog_alert)
            .setContentTitle(forwarding ? "NetScope forwarding preview" : "Diagnostic VPN — traffic blocked")
            .setContentText(forwarding ? "TCP web and DNS allowed. Other routed traffic blocked." : "All routed packets are discarded. No forwarding.")
            .setOngoing(true).addAction(new Notification.Action.Builder(null, "Stop", stop).build()).build();
        ParcelFileDescriptor tun = null;
        try {
            if (Build.VERSION.SDK_INT >= 34) startForeground(1, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE);
            else startForeground(1, notification);
            if (NativeCore.inspect(new byte[0], 0) != -1) throw new IllegalStateException("Native bridge unavailable");
            if (VpnService.prepare(this) != null) throw new IllegalStateException("VPN consent required");
            if (!forwarding) {
                udpSessionId = NativeCore.startUdpSession(this);
                if (udpSessionId == 0) throw new IllegalStateException("Native UDP session unavailable");
            }
            tun = new Builder().setSession(forwarding ? "NetScope preview" : "NetScope diagnostic: blocks traffic")
                .setMtu(1500).addAddress("10.111.0.1", 32).addAddress("fd12:3456:789a::1", 128)
                .addRoute("0.0.0.0", 0).addRoute("::", 0)
                .addDnsServer(forwarding ? "1.1.1.1" : "192.0.2.53")
                .setBlocking(!forwarding).establish();
            if (tun == null) throw new IllegalStateException("TUN unavailable");
            reader = new Reader(tun, forwarding);
            reader.start();
            activeWorker = reader;
            tun = null; // reader owns the descriptor, including close on thread exit.
        } catch (RuntimeException | LinkageError error) {
            if (tun != null) try { tun.close(); } catch (IOException ignored) { }
            shutdown();
            status = Status.FAILED;
            stopSelf();
        }
        return START_NOT_STICKY;
    }
    private void shutdown() {
        long oldSession = udpSessionId;
        udpSessionId = 0;
        if (oldSession != 0) NativeCore.stopUdpSession(oldSession);
        Reader old = reader;
        reader = null;
        if (old != null) {
            if (activeWorker == old) status = Status.STOPPING;
            old.requestStop();
        }
        stopForeground(STOP_FOREGROUND_REMOVE);
    }
    @Override public void onRevoke() { shutdown(); stopSelf(); super.onRevoke(); }
    @Override public void onDestroy() { shutdown(); super.onDestroy(); }

    private final class Reader extends Thread {
        private final ParcelFileDescriptor descriptor;
        private final AtomicBoolean running = new AtomicBoolean(true);
        private final boolean forwarding;
        Reader(ParcelFileDescriptor descriptor, boolean forwarding) {
            super("netscope-tun");
            this.descriptor = descriptor;
            this.forwarding = forwarding;
        }
        void requestStop() { running.set(false); interrupt(); }
        @Override public void run() {
            try (ParcelFileDescriptor.AutoCloseInputStream input = new ParcelFileDescriptor.AutoCloseInputStream(descriptor)) {
                if (forwarding) {
                    runForwarding();
                    return;
                }
                reportReady(Status.DIAGNOSTIC);
                byte[] buffer = new byte[65575];
                StructPollfd poll = new StructPollfd();
                poll.fd = descriptor.getFileDescriptor();
                poll.events = (short) OsConstants.POLLIN;
                StructPollfd[] polls = new StructPollfd[]{poll};
                while (running.get()) {
                    poll.revents = 0;
                    int available = Os.poll(polls, 200);
                    if (!running.get()) break;
                    if ((poll.revents & (OsConstants.POLLERR | OsConstants.POLLHUP | OsConstants.POLLNVAL)) != 0) break;
                    if (available == 0 || (poll.revents & OsConstants.POLLIN) == 0) continue;
                    int count = input.read(buffer);
                    if (count <= 0) break;
                    int result = NativeCore.inspect(buffer, count);
                    if (result < 0) break;
                    int udpResult = NativeCore.inspectUdpSession(udpSessionId, buffer, count);
                    if (udpResult < 0) break;
                    // 0 and 1 both mean DROP. No TUN write, socket send or forward.
                }
            } catch (IOException | ErrnoException | RuntimeException | LinkageError error) {
                // No payload/address logging. Any bridge/I/O failure ends this diagnostic session.
            } finally {
                new android.os.Handler(getMainLooper()).post(() -> {
                    // Do not stop a newer session if an older reader finishes after cancellation.
                    if (activeWorker == this) {
                        activeWorker = null;
                        status = running.get() ? Status.FAILED : Status.IDLE;
                    }
                    if (reader == this) {
                        reader = null;
                        stopForeground(STOP_FOREGROUND_REMOVE);
                        stopSelf();
                    }
                });
            }
        }
        private void reportReady(Status ready) {
            new android.os.Handler(getMainLooper()).post(() -> {
                if (activeWorker == this && running.get()) status = ready;
            });
        }

        private void runForwarding() throws ErrnoException, IOException {
            AppBlockRules rules = AppBlockRules.open(DiagnosticVpnService.this);
            long session = NativeCore.startForwarding(DiagnosticVpnService.this, rules);
            if (session == 0) return;
            TrafficObservations observations = new TrafficObservations(getSystemService(android.net.ConnectivityManager.class));
            try {
                traffic = observations;
                reportReady(Status.FORWARDING);
                byte[] ingress = new byte[1500];
                byte[] egress = new byte[1500];
                byte[] metadata = new byte[TrafficObservations.METADATA_BYTES];
                int pending = 0;
                StructPollfd poll = new StructPollfd();
                poll.fd = descriptor.getFileDescriptor();
                StructPollfd[] polls = {poll};
                while (running.get()) {
                    poll.events = (short) (OsConstants.POLLIN | (pending > 0 ? OsConstants.POLLOUT : 0));
                    poll.revents = 0;
                    Os.poll(polls, 20);
                    if (!running.get()) break;
                    if ((poll.revents & (OsConstants.POLLERR | OsConstants.POLLHUP | OsConstants.POLLNVAL)) != 0) break;
                    if ((poll.revents & OsConstants.POLLIN) != 0) {
                        try {
                            int n = Os.read(poll.fd, ingress, 0, ingress.length);
                            if (n <= 0) break;
                            int result = NativeCore.forwardPacket(session, ingress, n, metadata);
                            if (result < 0) break;
                            if (result > 0) observations.observe(metadata, n, result);
                        } catch (ErrnoException error) {
                            if (error.errno != OsConstants.EAGAIN && error.errno != OsConstants.EINTR) throw error;
                        }
                    }
                    // Bound the work per wake and keep one complete packet on EAGAIN.
                    for (int i = 0; running.get() && i < 8; i++) {
                        if (pending == 0) pending = NativeCore.pollForwarding(session, egress);
                        if (pending < 0) return;
                        if (pending == 0) break;
                        try {
                            if (Os.write(poll.fd, egress, 0, pending) != pending) return;
                            pending = 0;
                        } catch (ErrnoException error) {
                            if (error.errno != OsConstants.EAGAIN && error.errno != OsConstants.EINTR) throw error;
                            break;
                        }
                    }
                }
            } finally {
                traffic = null;
                NativeCore.stopForwarding(session);
            }
        }

    }
}
