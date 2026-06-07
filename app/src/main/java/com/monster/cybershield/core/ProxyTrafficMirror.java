package com.monster.cybershield.core;

import android.content.Context;

import java.util.Locale;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

public final class ProxyTrafficMirror implements AutoCloseable {
    private static final String VPN_SOURCE_IP = "10.88.0.2";
    private static final int MAX_QUEUED_EVENTS = 256;

    private final ThreatEngine engine;
    private final FlowTracker flowTracker = new FlowTracker();
    private final ExecutorService worker;
    private final AtomicInteger queuedEvents = new AtomicInteger();
    private final AtomicLong mirroredBytes = new AtomicLong();
    private final AtomicLong analyzedFlows = new AtomicLong();
    private final AtomicLong lastMirrorAt = new AtomicLong();

    public ProxyTrafficMirror(Context context) {
        this.engine = new ThreatEngine(context);
        this.worker = Executors.newSingleThreadExecutor(new ThreadFactory() {
            @Override
            public Thread newThread(Runnable runnable) {
                Thread thread = new Thread(runnable, "cybershield-proxy-mirror");
                thread.setDaemon(true);
                return thread;
            }
        });
    }

    public void recordTcpConnect(String host, int port) {
        enqueue(packet(host, port, 6, 60, 0, true, ""));
    }

    public void recordTcpBytes(String host, int port, int payloadBytes, boolean outbound) {
        if (payloadBytes <= 0) {
            return;
        }
        enqueue(packet(host, port, 6, payloadBytes + 40, payloadBytes, outbound, ""));
    }

    public void recordUdp(String host, int port, int payloadBytes, boolean outbound, String dnsQuery) {
        if (payloadBytes <= 0) {
            return;
        }
        enqueue(packet(host, port, 17, payloadBytes + 28, payloadBytes, outbound, dnsQuery));
    }

    public long mirroredBytes() {
        return mirroredBytes.get();
    }

    public long analyzedFlows() {
        return analyzedFlows.get();
    }

    public long lastMirrorAt() {
        return lastMirrorAt.get();
    }

    private void enqueue(final PacketInfo packet) {
        if (queuedEvents.incrementAndGet() > MAX_QUEUED_EVENTS) {
            queuedEvents.decrementAndGet();
            return;
        }
        worker.execute(new Runnable() {
            @Override
            public void run() {
                try {
                    mirroredBytes.addAndGet(Math.max(0, packet.payloadLength));
                    lastMirrorAt.set(System.currentTimeMillis());
                    engine.analyzePacket(packet);
                    FlowStats flow = flowTracker.record(packet);
                    long nowMs = System.currentTimeMillis();
                    if (flow.shouldAnalyze(nowMs)) {
                        flow.markAnalyzed(nowMs);
                        engine.analyzeFlow(flow);
                        analyzedFlows.incrementAndGet();
                    }
                } finally {
                    queuedEvents.decrementAndGet();
                }
            }
        });
    }

    private static PacketInfo packet(String host, int port, int protocol, int totalBytes, int payloadBytes, boolean outbound, String dnsQuery) {
        PacketInfo packet = new PacketInfo();
        String target = normalizeHost(host);
        int syntheticSourcePort = syntheticSourcePort(target, port, protocol);
        packet.protocol = protocol;
        packet.totalLength = Math.max(totalBytes, protocol == 6 ? 40 : 28);
        packet.ipHeaderLength = 20;
        packet.transportHeaderLength = protocol == 6 ? 20 : 8;
        packet.payloadLength = Math.max(0, payloadBytes);
        packet.ttl = 64;
        packet.tcpWindowSize = protocol == 6 ? 65535 : 0;
        packet.tcpFlags = protocol == 6 ? 0x18 : 0;
        if (outbound) {
            packet.sourceAddress = VPN_SOURCE_IP;
            packet.destinationAddress = target;
            packet.sourcePort = syntheticSourcePort;
            packet.destinationPort = port;
        } else {
            packet.sourceAddress = target;
            packet.destinationAddress = VPN_SOURCE_IP;
            packet.sourcePort = port;
            packet.destinationPort = syntheticSourcePort;
        }
        packet.isDns = protocol == 17 && port == 53;
        packet.isDohLike = protocol == 6 && (port == 853 || AlertNoisePolicy.isKnownDohHost(target));
        packet.queryName = dnsQuery == null ? "" : dnsQuery.toLowerCase(Locale.US);
        return packet;
    }

    private static int syntheticSourcePort(String host, int port, int protocol) {
        int hash = Math.abs((host + ":" + port + ":" + protocol).hashCode());
        return 20_000 + (hash % 40_000);
    }

    private static String normalizeHost(String host) {
        String value = host == null ? "" : host.trim().toLowerCase(Locale.US);
        return value.isEmpty() ? "0.0.0.0" : value;
    }

    @Override
    public void close() {
        worker.shutdownNow();
    }
}
