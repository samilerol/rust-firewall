package org.netscope.ngfw;

import java.util.List;

record TrafficReport(long bytes, long packets, long blocked, int knownOwners, long unknownPackets) {
    static TrafficReport summarize(List<TrafficObservations.Entry> entries) {
        long bytes = 0;
        long packets = 0;
        long blocked = 0;
        int knownOwners = 0;
        long unknown = 0;
        for (var entry : entries) {
            bytes += entry.bytes();
            packets += entry.packets();
            blocked += entry.blocked();
            if (entry.uid() >= 0) knownOwners++;
            else unknown += entry.packets();
        }
        return new TrafficReport(bytes, packets, blocked, knownOwners, unknown);
    }
}
