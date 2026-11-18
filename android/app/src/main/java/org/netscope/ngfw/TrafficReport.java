package org.netscope.ngfw;

import java.util.List;

record TrafficReport(long bytes, long packets, long profileBlocks, long appBlocks,
                     int knownOwners, long unknownPackets) {
    long blocked() { return profileBlocks + appBlocks; }
    static TrafficReport summarize(List<TrafficObservations.Entry> entries) {
        long bytes = 0;
        long packets = 0;
        long profileBlocks = 0;
        long appBlocks = 0;
        int knownOwners = 0;
        long unknown = 0;
        for (var entry : entries) {
            bytes += entry.bytes();
            packets += entry.packets();
            profileBlocks += entry.profileBlocks();
            appBlocks += entry.appBlocks();
            if (entry.uid() >= 0) knownOwners++;
            else unknown += entry.packets();
        }
        return new TrafficReport(bytes, packets, profileBlocks, appBlocks, knownOwners, unknown);
    }
}
