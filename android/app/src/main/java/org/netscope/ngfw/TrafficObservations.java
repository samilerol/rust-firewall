package org.netscope.ngfw;

import android.net.ConnectivityManager;
import android.os.Build;
import android.os.SystemClock;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;

/** Local, bounded outbound observations, owned by one forwarding session. */
final class TrafficObservations {
    static final int METADATA_BYTES = 38;
    static final int UNKNOWN_UID = -1;
    private static final int MAX_OWNERS = 128;
    private static final int CACHE_LIMIT = 256;
    private static final int LOOKUPS_PER_SECOND = 64;

    record Entry(int uid, long bytes, long packets, long blocked) {}
    private record Tuple(int header, int ports, long sourceHigh, long sourceLow,
                         long destinationHigh, long destinationLow) {}
    private record Owner(int uid, long expires) {}
    private static final class Counts {
        long bytes;
        long packets;
        long blocked;
    }

    private final ConnectivityManager connectivity;
    // The VPN worker alone reads and writes the lookup cache.
    private final LinkedHashMap<Tuple, Owner> owners = new LinkedHashMap<>();
    private final LinkedHashMap<Integer, Counts> counts = new LinkedHashMap<>();
    private long lookupSecond = -1;
    private int lookups;

    TrafficObservations(ConnectivityManager connectivity) {
        this.connectivity = connectivity;
    }

    void observe(byte[] metadata, int length, boolean blocked) {
        record(resolve(metadata), length, blocked);
    }

    private int resolve(byte[] bytes) {
        if (Build.VERSION.SDK_INT < 29 || connectivity == null) return UNKNOWN_UID;
        long now = SystemClock.elapsedRealtime();
        ByteBuffer buffer = ByteBuffer.wrap(bytes);
        Tuple key = new Tuple(buffer.getShort(), buffer.getInt(), buffer.getLong(),
            buffer.getLong(), buffer.getLong(), buffer.getLong());
        Owner old = owners.get(key);
        if (old != null && now < old.expires()) return old.uid();
        long second = now / 1000;
        if (second != lookupSecond) {
            lookupSecond = second;
            lookups = 0;
        }
        if (lookups >= LOOKUPS_PER_SECOND) return UNKNOWN_UID;
        lookups++;

        int uid = UNKNOWN_UID;
        try {
            int addressLength = bytes[1];
            InetAddress source = InetAddress.getByAddress(Arrays.copyOfRange(bytes, 6, 6 + addressLength));
            InetAddress destination = InetAddress.getByAddress(Arrays.copyOfRange(bytes, 22, 22 + addressLength));
            uid = connectivity.getConnectionOwnerUid(bytes[0],
                new InetSocketAddress(source, Short.toUnsignedInt(buffer.getShort(2))),
                new InetSocketAddress(destination, Short.toUnsignedInt(buffer.getShort(4))));
        } catch (UnknownHostException | RuntimeException ignored) {
            // Device support, disappeared sockets and revoked VPNs all use the unknown bucket.
        }
        owners.remove(key);
        if (owners.size() == CACHE_LIMIT) owners.remove(owners.keySet().iterator().next());
        owners.put(key, new Owner(uid, now + (uid < 0 ? 100 : 1000)));
        return uid;
    }

    synchronized void record(int uid, int length, boolean blocked) {
        if (uid < 0 || (!counts.containsKey(uid) && counts.size() >= MAX_OWNERS)) uid = UNKNOWN_UID;
        Counts value = counts.computeIfAbsent(uid, ignored -> new Counts());
        value.bytes += length;
        value.packets++;
        if (blocked) value.blocked++;
    }

    synchronized List<Entry> snapshot() {
        List<Entry> snapshot = new ArrayList<>(counts.size());
        counts.forEach((uid, value) -> snapshot.add(new Entry(uid, value.bytes, value.packets, value.blocked)));
        return snapshot;
    }
}
