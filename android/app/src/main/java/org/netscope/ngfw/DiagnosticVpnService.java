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

/** Explicit drop-all diagnostic. Single reader owns/ closes the TUN; no transport sockets. */
public final class DiagnosticVpnService extends VpnService {
    public static final String START = "org.netscope.ngfw.START_DIAGNOSTIC";
    private static final String STOP = "org.netscope.ngfw.STOP_DIAGNOSTIC";
    private static final String CHANNEL = "diagnostic-vpn";
    private Reader reader;
    // Dormant native default-deny context, never used by the diagnostic packet loop.
    private volatile long udpSessionId;
    @Override public int onStartCommand(Intent intent, int flags, int id) {
        if (intent == null || !START.equals(intent.getAction())) { shutdown(); stopSelf(); return START_NOT_STICKY; }
        if (reader != null) return START_NOT_STICKY;
        NotificationManager manager = getSystemService(NotificationManager.class);
        manager.createNotificationChannel(new NotificationChannel(CHANNEL, "Diagnostic VPN", NotificationManager.IMPORTANCE_LOW));
        PendingIntent stop = PendingIntent.getService(this, 0, new Intent(this, DiagnosticVpnService.class).setAction(STOP), PendingIntent.FLAG_IMMUTABLE | PendingIntent.FLAG_UPDATE_CURRENT);
        Notification notification = new Notification.Builder(this, CHANNEL)
            .setSmallIcon(android.R.drawable.ic_dialog_alert)
            .setContentTitle("Diagnostic VPN — traffic blocked")
            .setContentText("All routed packets are discarded. No forwarding.")
            .setOngoing(true).addAction(new Notification.Action.Builder(null, "Stop", stop).build()).build();
        ParcelFileDescriptor tun = null;
        try {
            if (Build.VERSION.SDK_INT >= 34) startForeground(1, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE);
            else startForeground(1, notification);
            if (NativeCore.inspect(new byte[0], 0) != -1) throw new IllegalStateException("Native bridge unavailable");
            if (VpnService.prepare(this) != null) throw new IllegalStateException("VPN consent required");
            long newSession = NativeCore.startUdpSession(this);
            if (newSession == 0) throw new IllegalStateException("Native UDP session unavailable");
            udpSessionId = newSession;
            tun = new Builder().setSession("NetScope diagnostic: blocks traffic")
                .setMtu(1500).addAddress("10.111.0.1", 32).addAddress("fd12:3456:789a::1", 128)
                .addRoute("0.0.0.0", 0).addRoute("::", 0).addDnsServer("192.0.2.53")
                .setBlocking(true).establish();
            if (tun == null) throw new IllegalStateException("TUN unavailable");
            reader = new Reader(tun);
            reader.start();
            tun = null; // reader owns the descriptor, including close on thread exit.
        } catch (RuntimeException | LinkageError error) {
            if (tun != null) try { tun.close(); } catch (IOException ignored) { }
            shutdown(); stopSelf();
        }
        return START_NOT_STICKY;
    }
    private void shutdown() {
        long oldSession = udpSessionId;
        udpSessionId = 0;
        if (oldSession != 0) NativeCore.stopUdpSession(oldSession);
        Reader old = reader;
        reader = null;
        if (old != null) old.requestStop();
        stopForeground(STOP_FOREGROUND_REMOVE);
    }
    @Override public void onRevoke() { shutdown(); stopSelf(); super.onRevoke(); }
    @Override public void onDestroy() { shutdown(); super.onDestroy(); }

    private final class Reader extends Thread {
        private final ParcelFileDescriptor descriptor;
        private final AtomicBoolean running = new AtomicBoolean(true);
        Reader(ParcelFileDescriptor descriptor) { super("netscope-tun"); this.descriptor = descriptor; }
        void requestStop() { running.set(false); interrupt(); }
        @Override public void run() {
            try (ParcelFileDescriptor.AutoCloseInputStream input = new ParcelFileDescriptor.AutoCloseInputStream(descriptor)) {
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
                    if (reader == this) { reader = null; stopForeground(STOP_FOREGROUND_REMOVE); stopSelf(); }
                });
            }
        }
    }
}
