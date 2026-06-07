package com.monster.cybershield;

import android.content.Intent;
import android.net.VpnService;
import android.os.ParcelFileDescriptor;

import com.monster.cybershield.core.BlocklistStore;
import com.monster.cybershield.core.FeatureExtractor;
import com.monster.cybershield.core.FlowStats;
import com.monster.cybershield.core.FlowTracker;
import com.monster.cybershield.core.NativeVpnForwarder;
import com.monster.cybershield.core.PacketInfo;
import com.monster.cybershield.core.ThreatEngine;

import java.io.FileInputStream;
import java.io.IOException;

public class DefenseVpnService extends VpnService {
    private ParcelFileDescriptor vpnInterface;
    private Thread readerThread;
    private volatile boolean running;
    private volatile boolean nativeForwarding;

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        establishPlaceholderTunnel();
        return START_STICKY;
    }

    @Override
    public void onDestroy() {
        running = false;
        NativeVpnForwarder.stop();
        if (vpnInterface != null) {
            try {
                vpnInterface.close();
            } catch (IOException ignored) {
            }
        }
        super.onDestroy();
    }

    private void establishPlaceholderTunnel() {
        if (vpnInterface != null) {
            return;
        }
        boolean canForwardAllTraffic = NativeVpnForwarder.isAvailable();
        Builder builder = new Builder()
                .setSession("CyberShield Defense VPN")
                .addAddress("10.88.0.2", 32)
                .setMtu(1500);
        if (canForwardAllTraffic) {
            builder.addRoute("0.0.0.0", 0);
        } else {
            builder.addRoute("203.0.113.0", 24)
                    .addRoute("198.51.100.0", 24);
        }
        vpnInterface = builder.establish();
        if (vpnInterface == null) {
            return;
        }
        nativeForwarding = startNativeForwardingIfAvailable(canForwardAllTraffic);
        if (!nativeForwarding) {
            startReader();
        }
    }

    private boolean startNativeForwardingIfAvailable(boolean canForwardAllTraffic) {
        if (!canForwardAllTraffic || vpnInterface == null) {
            getSharedPreferences("vpn_status", MODE_PRIVATE)
                    .edit()
                    .putBoolean("native_forwarding", false)
                    .putString("mode", "safe_telemetry_routes")
                    .apply();
            return false;
        }
        try {
            int fd = vpnInterface.detachFd();
            int status = NativeVpnForwarder.start(fd, 1500);
            boolean ok = status == 0;
            getSharedPreferences("vpn_status", MODE_PRIVATE)
                    .edit()
                    .putBoolean("native_forwarding", ok)
                    .putString("mode", ok ? "full_device_forwarding" : "native_forwarder_failed")
                    .apply();
            return ok;
        } catch (Throwable throwable) {
            getSharedPreferences("vpn_status", MODE_PRIVATE)
                    .edit()
                    .putBoolean("native_forwarding", false)
                    .putString("mode", "native_forwarder_exception")
                    .apply();
            return false;
        }
    }

    private void startReader() {
        if (vpnInterface == null || readerThread != null) {
            return;
        }
        running = true;
        readerThread = new Thread(new Runnable() {
            @Override
            public void run() {
                readPackets();
            }
        }, "cybershield-vpn-reader");
        readerThread.start();
    }

    private void readPackets() {
        ThreatEngine engine = new ThreatEngine(this);
        BlocklistStore blocklist = new BlocklistStore(this);
        byte[] packet = new byte[32767];
        try (FileInputStream input = new FileInputStream(vpnInterface.getFileDescriptor())) {
            FlowTracker flowTracker = new FlowTracker();
            while (running) {
                int length = input.read(packet);
                if (length <= 0) {
                    continue;
                }
                PacketInfo info = FeatureExtractor.parsePacket(packet, length);
                if (blocklist.isBlocked(info.target()) || blocklist.isBlocked(info.destinationAddress) || blocklist.isBlocked(info.destinationAddress + ":" + info.destinationPort)) {
                    continue;
                }
                engine.analyzePacket(info);
                FlowStats flow = flowTracker.record(info);
                long nowMs = System.currentTimeMillis();
                if (flow.shouldAnalyze(nowMs)) {
                    flow.markAnalyzed(nowMs);
                    engine.analyzeFlow(flow);
                }
            }
        } catch (IOException ignored) {
        }
    }
}
