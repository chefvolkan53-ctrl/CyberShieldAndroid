package com.monster.cybershield;

import android.content.Intent;
import android.net.VpnService;
import android.os.ParcelFileDescriptor;

import com.monster.cybershield.core.BlocklistStore;
import com.monster.cybershield.core.DirectSocksProxy;
import com.monster.cybershield.core.FeatureExtractor;
import com.monster.cybershield.core.FlowStats;
import com.monster.cybershield.core.FlowTracker;
import com.monster.cybershield.core.NativeVpnForwarder;
import com.monster.cybershield.core.PacketInfo;
import com.monster.cybershield.core.ProtectionPolicyStore;
import com.monster.cybershield.core.ThreatEngine;

import java.io.File;
import java.io.FileOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

public class DefenseVpnService extends VpnService {
    private static final int VPN_MTU = 1500;
    private static final int SOCKS_PORT = 10808;

    private ParcelFileDescriptor vpnInterface;
    private DirectSocksProxy directSocksProxy;
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
        stopNativeForwarding();
        closeVpnInterface();
        super.onDestroy();
    }

    private void establishPlaceholderTunnel() {
        if (vpnInterface != null) {
            return;
        }
        boolean canForwardAllTraffic = NativeVpnForwarder.isAvailable();
        establishTunnel(canForwardAllTraffic);
        nativeForwarding = startNativeForwardingIfAvailable(canForwardAllTraffic);
        if (!nativeForwarding) {
            if (canForwardAllTraffic) {
                closeVpnInterface();
                establishTunnel(false);
            }
            startReader();
        }
    }

    private void establishTunnel(boolean fullDeviceRoute) {
        Builder builder = new Builder()
                .setSession("CyberShield Defense VPN")
                .addAddress("10.88.0.2", 32)
                .setMtu(VPN_MTU);
        if (fullDeviceRoute) {
            ProtectionPolicyStore policy = new ProtectionPolicyStore(this);
            builder.addRoute("0.0.0.0", 0)
                    .addDnsServer(policy.dnsProvider());
            String secondaryDns = policy.dnsProviderSecondary();
            if (!secondaryDns.isEmpty()) {
                builder.addDnsServer(secondaryDns);
            }
            try {
                builder.addDisallowedApplication(getPackageName());
            } catch (Exception ignored) {
            }
        } else {
            builder.addRoute("203.0.113.0", 24)
                    .addRoute("198.51.100.0", 24);
        }
        vpnInterface = builder.establish();
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
            directSocksProxy = new DirectSocksProxy(this, SOCKS_PORT);
            directSocksProxy.start();
            String configPath = writeForwarderConfig();
            int status = NativeVpnForwarder.start(configPath, vpnInterface.getFd(), VPN_MTU);
            boolean ok = status == 0;
            if (!ok) {
                stopNativeForwarding();
            }
            getSharedPreferences("vpn_status", MODE_PRIVATE)
                    .edit()
                    .putBoolean("native_forwarding", ok)
                    .putString("mode", ok ? "full_device_forwarding" : "native_forwarder_failed")
                    .putInt("socks_port", SOCKS_PORT)
                    .apply();
            return ok;
        } catch (Throwable throwable) {
            stopNativeForwarding();
            getSharedPreferences("vpn_status", MODE_PRIVATE)
                    .edit()
                    .putBoolean("native_forwarding", false)
                    .putString("mode", "native_forwarder_exception")
                    .apply();
            return false;
        }
    }

    private String writeForwarderConfig() throws IOException {
        File configFile = new File(getCacheDir(), "cybershield_tun2socks.yml");
        String config = "misc:\n"
                + "  task-stack-size: 24576\n"
                + "tunnel:\n"
                + "  mtu: " + VPN_MTU + "\n"
                + "socks5:\n"
                + "  port: " + SOCKS_PORT + "\n"
                + "  address: '127.0.0.1'\n"
                + "  udp: 'udp'\n";
        try (FileOutputStream output = new FileOutputStream(configFile, false)) {
            output.write(config.getBytes(StandardCharsets.UTF_8));
        }
        return configFile.getAbsolutePath();
    }

    private void stopNativeForwarding() {
        NativeVpnForwarder.stop();
        if (directSocksProxy != null) {
            try {
                directSocksProxy.close();
            } catch (Exception ignored) {
            }
            directSocksProxy = null;
        }
        nativeForwarding = false;
    }

    private void closeVpnInterface() {
        if (vpnInterface != null) {
            try {
                vpnInterface.close();
            } catch (IOException ignored) {
            }
            vpnInterface = null;
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
