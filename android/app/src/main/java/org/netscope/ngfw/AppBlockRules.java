package org.netscope.ngfw;

import android.content.Context;
import android.content.pm.PackageManager;
import android.net.ConnectivityManager;
import android.os.Build;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

/** One session's immutable application deny list. */
final class AppBlockRules {
    static final int MAX_PACKAGES = 64;
    private static final String PREFERENCES = "app_rules";
    private static final String BLOCKED = "blocked_packages";

    private final ConnectivityManager connectivity;
    private final Set<Integer> blockedUids;

    private AppBlockRules(ConnectivityManager connectivity, Set<Integer> blockedUids) {
        this.connectivity = connectivity;
        this.blockedUids = Collections.unmodifiableSet(blockedUids);
    }

    static Set<String> saved(Context context) {
        return new HashSet<>(context.getSharedPreferences(PREFERENCES, Context.MODE_PRIVATE)
            .getStringSet(BLOCKED, Collections.emptySet()));
    }

    static boolean save(Context context, Set<String> packages) {
        if (packages.size() > MAX_PACKAGES) return false;
        return context.getSharedPreferences(PREFERENCES, Context.MODE_PRIVATE)
            .edit().putStringSet(BLOCKED, new HashSet<>(packages)).commit();
    }

    static AppBlockRules open(Context context) {
        Set<String> packages = saved(context);
        if (packages.isEmpty()) return null;
        if (Build.VERSION.SDK_INT < 29 || packages.size() > MAX_PACKAGES) {
            throw new IllegalStateException("Application rules unavailable");
        }
        PackageManager manager = context.getPackageManager();
        HashSet<Integer> uids = new HashSet<>();
        for (String name : packages) {
            try {
                uids.add(manager.getApplicationInfo(name, 0).uid);
            } catch (PackageManager.NameNotFoundException error) {
                throw new IllegalStateException("A saved app needs review", error);
            }
        }
        return new AppBlockRules(context.getSystemService(ConnectivityManager.class), uids);
    }

    /** Called by Rust only for a checked tuple that passed the outbound network profile. */
    public boolean allows(byte[] metadata) {
        // The expiring UID cache in TrafficObservations is only for display.
        int uid = TrafficObservations.lookupOwner(connectivity, metadata);
        return uid >= 0 && !blockedUids.contains(uid);
    }
}
