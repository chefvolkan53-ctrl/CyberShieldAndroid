package com.monster.cybershield.core;

public final class FlowStats {
    public final FlowKey key;
    public long firstSeenMs;
    public long lastSeenMs;
    public long lastAnalyzedMs;
    public int packetCount;
    public int byteCount;
    public int minPacketBytes = Integer.MAX_VALUE;
    public int maxPacketBytes;
    public int tcpPackets;
    public int udpPackets;
    public int dnsPackets;
    public int dohPackets;
    public int synPackets;
    public int ackPackets;
    public int finPackets;
    public int rstPackets;
    public String lastQueryName = "";

    public FlowStats(FlowKey key, long nowMs) {
        this.key = key;
        this.firstSeenMs = nowMs;
        this.lastSeenMs = nowMs;
    }

    public void add(PacketInfo packet, long nowMs) {
        lastSeenMs = nowMs;
        packetCount++;
        byteCount += Math.max(packet.totalLength, packet.payloadLength);
        minPacketBytes = Math.min(minPacketBytes, Math.max(0, packet.totalLength));
        maxPacketBytes = Math.max(maxPacketBytes, Math.max(0, packet.totalLength));
        if (packet.protocol == 6) {
            tcpPackets++;
            if ((packet.tcpFlags & 0x02) != 0) synPackets++;
            if ((packet.tcpFlags & 0x10) != 0) ackPackets++;
            if ((packet.tcpFlags & 0x01) != 0) finPackets++;
            if ((packet.tcpFlags & 0x04) != 0) rstPackets++;
        } else if (packet.protocol == 17) {
            udpPackets++;
        }
        if (packet.isDns) {
            dnsPackets++;
        }
        if (packet.isDohLike) {
            dohPackets++;
        }
        if (packet.queryName != null && !packet.queryName.isEmpty()) {
            lastQueryName = packet.queryName;
        }
    }

    public boolean shouldAnalyze(long nowMs) {
        if (packetCount == 1) {
            return true;
        }
        if (dnsPackets > 0 || dohPackets > 0) {
            return nowMs - lastAnalyzedMs > 1500;
        }
        if (packetCount % 8 == 0) {
            return true;
        }
        return nowMs - lastAnalyzedMs > 5000;
    }

    public void markAnalyzed(long nowMs) {
        lastAnalyzedMs = nowMs;
    }

    public long durationMs() {
        return Math.max(1L, lastSeenMs - firstSeenMs);
    }

    public float packetsPerSecond() {
        return packetCount * 1000.0f / durationMs();
    }

    public float bytesPerSecond() {
        return byteCount * 1000.0f / durationMs();
    }

    public float averagePacketBytes() {
        return packetCount == 0 ? 0f : byteCount / (float) packetCount;
    }

    public String target() {
        if (lastQueryName != null && !lastQueryName.isEmpty()) {
            return lastQueryName;
        }
        return key.target();
    }
}
