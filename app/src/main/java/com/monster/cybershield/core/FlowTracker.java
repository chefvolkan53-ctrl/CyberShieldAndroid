package com.monster.cybershield.core;

import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;

public final class FlowTracker {
    private static final int MAX_FLOWS = 512;
    private static final long STALE_MS = 120_000L;
    private final LinkedHashMap<FlowKey, FlowStats> flows = new LinkedHashMap<>();

    public synchronized FlowStats record(PacketInfo packet) {
        long nowMs = System.currentTimeMillis();
        FlowKey key = FlowKey.from(packet);
        FlowStats stats = flows.get(key);
        if (stats == null) {
            stats = new FlowStats(key, nowMs);
            flows.put(key, stats);
        }
        stats.add(packet, nowMs);
        prune(nowMs);
        return stats;
    }

    private void prune(long nowMs) {
        Iterator<Map.Entry<FlowKey, FlowStats>> iterator = flows.entrySet().iterator();
        while (iterator.hasNext()) {
            Map.Entry<FlowKey, FlowStats> entry = iterator.next();
            if (nowMs - entry.getValue().lastSeenMs > STALE_MS || flows.size() > MAX_FLOWS) {
                iterator.remove();
            }
        }
    }
}
