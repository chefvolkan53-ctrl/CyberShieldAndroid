package com.monster.cybershield.core;

import java.util.HashSet;
import java.util.Set;

public final class FlowStats {
    public final FlowKey key;
    public long firstSeenMs;
    public long lastSeenMs;
    public long lastAnalyzedMs;
    public long lastPacketSeenMs;
    public long lastFwdSeenMs;
    public long lastBwdSeenMs;

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
    public int pshPackets;
    public int urgPackets;
    public int ecePackets;
    public int cwrPackets;
    public int fragmentedPackets;
    public int fwdPshPackets;
    public int bwdPshPackets;
    public int fwdUrgPackets;
    public int bwdUrgPackets;
    public int fwdActDataPackets;
    public String lastQueryName = "";

    public final DirectionStats fwd = new DirectionStats();
    public final DirectionStats bwd = new DirectionStats();
    public final RunningStats packetLengthStats = new RunningStats();
    public final RunningStats flowIatStats = new RunningStats();
    public final RunningStats fwdIatStats = new RunningStats();
    public final RunningStats bwdIatStats = new RunningStats();
    public final RunningStats activeStats = new RunningStats();
    public final RunningStats idleStats = new RunningStats();
    public final RunningStats headerLengthStats = new RunningStats();
    public final RunningStats ipFlagsStats = new RunningStats();
    public final RunningStats ttlStats = new RunningStats();
    public final RunningStats windowStats = new RunningStats();

    private final Set<String> allIps = new HashSet<>();
    private final Set<String> srcIps = new HashSet<>();
    private final Set<String> dstIps = new HashSet<>();
    private final Set<Integer> allPorts = new HashSet<>();
    private final Set<Integer> srcPorts = new HashSet<>();
    private final Set<Integer> dstPorts = new HashSet<>();
    private final Set<Integer> protocols = new HashSet<>();

    public FlowStats(FlowKey key, long nowMs) {
        this.key = key;
        this.firstSeenMs = nowMs;
        this.lastSeenMs = nowMs;
    }

    public void add(PacketInfo packet, long nowMs, boolean forward) {
        updateTiming(nowMs, forward);
        lastSeenMs = nowMs;
        packetCount++;
        int packetBytes = Math.max(0, packet.totalLength);
        int payloadBytes = Math.max(0, packet.payloadLength);
        byteCount += Math.max(packetBytes, payloadBytes);
        minPacketBytes = Math.min(minPacketBytes, packetBytes);
        maxPacketBytes = Math.max(maxPacketBytes, packetBytes);
        packetLengthStats.add(packetBytes);
        headerLengthStats.add(packet.ipHeaderLength + packet.transportHeaderLength);
        ipFlagsStats.add(packet.ipFlags);
        ttlStats.add(packet.ttl);
        windowStats.add(packet.tcpWindowSize);
        protocols.add(packet.protocol);
        allIps.add(packet.sourceAddress);
        allIps.add(packet.destinationAddress);
        srcIps.add(packet.sourceAddress);
        dstIps.add(packet.destinationAddress);
        allPorts.add(packet.sourcePort);
        allPorts.add(packet.destinationPort);
        srcPorts.add(packet.sourcePort);
        dstPorts.add(packet.destinationPort);

        DirectionStats direction = forward ? fwd : bwd;
        direction.add(packetBytes, payloadBytes, packet.ipHeaderLength + packet.transportHeaderLength, packet.tcpWindowSize, packet.ttl, packet.ipFlags);

        if (packet.fragmentOffset > 0 || (packet.ipFlags & 0x1) != 0) {
            fragmentedPackets++;
        }
        if (packet.protocol == 6) {
            tcpPackets++;
            if ((packet.tcpFlags & 0x02) != 0) synPackets++;
            if ((packet.tcpFlags & 0x10) != 0) ackPackets++;
            if ((packet.tcpFlags & 0x01) != 0) finPackets++;
            if ((packet.tcpFlags & 0x04) != 0) rstPackets++;
            if ((packet.tcpFlags & 0x08) != 0) {
                pshPackets++;
                if (forward) fwdPshPackets++; else bwdPshPackets++;
            }
            if ((packet.tcpFlags & 0x20) != 0) {
                urgPackets++;
                if (forward) fwdUrgPackets++; else bwdUrgPackets++;
            }
            if ((packet.tcpFlags & 0x40) != 0) ecePackets++;
            if ((packet.tcpFlags & 0x80) != 0) cwrPackets++;
            if (forward && payloadBytes > 0) {
                fwdActDataPackets++;
            }
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

    private void updateTiming(long nowMs, boolean forward) {
        if (lastPacketSeenMs > 0) {
            long delta = Math.max(0, nowMs - lastPacketSeenMs);
            flowIatStats.add(delta);
            if (delta > 1000) {
                idleStats.add(delta);
            } else {
                activeStats.add(delta);
            }
        }
        if (forward) {
            if (lastFwdSeenMs > 0) {
                fwdIatStats.add(Math.max(0, nowMs - lastFwdSeenMs));
            }
            lastFwdSeenMs = nowMs;
        } else {
            if (lastBwdSeenMs > 0) {
                bwdIatStats.add(Math.max(0, nowMs - lastBwdSeenMs));
            }
            lastBwdSeenMs = nowMs;
        }
        lastPacketSeenMs = nowMs;
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

    public float downUpRatio() {
        return fwd.packetCount == 0 ? bwd.packetCount : bwd.packetCount / (float) Math.max(1, fwd.packetCount);
    }

    public int allIpCount() {
        return allIps.size();
    }

    public int srcIpCount() {
        return srcIps.size();
    }

    public int dstIpCount() {
        return dstIps.size();
    }

    public int allPortCount() {
        return allPorts.size();
    }

    public int srcPortCount() {
        return srcPorts.size();
    }

    public int dstPortCount() {
        return dstPorts.size();
    }

    public int protocolCount() {
        return protocols.size();
    }

    public String target() {
        if (lastQueryName != null && !lastQueryName.isEmpty()) {
            return lastQueryName;
        }
        return key.target();
    }

    public static final class DirectionStats {
        public int packetCount;
        public int byteCount;
        public int payloadByteCount;
        public int minPacketBytes = Integer.MAX_VALUE;
        public int maxPacketBytes;
        public final RunningStats packetLength = new RunningStats();
        public final RunningStats payloadLength = new RunningStats();
        public final RunningStats headerLength = new RunningStats();
        public final RunningStats windowSize = new RunningStats();
        public final RunningStats ttl = new RunningStats();
        public final RunningStats ipFlags = new RunningStats();

        public void add(int packetBytes, int payloadBytes, int headerBytes, int window, int ttlValue, int flags) {
            packetCount++;
            byteCount += packetBytes;
            payloadByteCount += payloadBytes;
            minPacketBytes = Math.min(minPacketBytes, packetBytes);
            maxPacketBytes = Math.max(maxPacketBytes, packetBytes);
            packetLength.add(packetBytes);
            payloadLength.add(payloadBytes);
            headerLength.add(headerBytes);
            windowSize.add(window);
            ttl.add(ttlValue);
            ipFlags.add(flags);
        }

        public float packetsPerSecond(long durationMs) {
            return packetCount * 1000.0f / Math.max(1L, durationMs);
        }

        public float bytesPerSecond(long durationMs) {
            return byteCount * 1000.0f / Math.max(1L, durationMs);
        }
    }

    public static final class RunningStats {
        public int count;
        public double sum;
        public double sumSquares;
        public double min = Double.POSITIVE_INFINITY;
        public double max = Double.NEGATIVE_INFINITY;

        public void add(double value) {
            count++;
            sum += value;
            sumSquares += value * value;
            min = Math.min(min, value);
            max = Math.max(max, value);
        }

        public float mean() {
            return count == 0 ? 0f : (float) (sum / count);
        }

        public float std() {
            if (count <= 1) {
                return 0f;
            }
            double mean = sum / count;
            double variance = Math.max(0.0, (sumSquares / count) - (mean * mean));
            return (float) Math.sqrt(variance);
        }

        public float min() {
            return count == 0 ? 0f : (float) min;
        }

        public float max() {
            return count == 0 ? 0f : (float) max;
        }
    }
}
