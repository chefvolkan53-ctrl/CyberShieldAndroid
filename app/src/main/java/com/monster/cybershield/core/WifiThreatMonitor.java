package com.monster.cybershield.core;

import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.net.DhcpInfo;
import android.net.wifi.WifiInfo;
import android.net.wifi.WifiManager;
import android.os.Build;

import com.monster.cybershield.CyberDefenseService;
import com.monster.cybershield.model.ModelCatalog;
import com.monster.cybershield.model.ModelSpec;
import com.monster.cybershield.model.TfliteThreatModel;
import com.monster.cybershield.model.ThreatScore;

import java.io.BufferedReader;
import java.io.FileReader;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

public final class WifiThreatMonitor {
    private static final String PREF = "wifi_threat_monitor";
    private static final String MODEL_ID = "wifi_threat";
    private static final long ALERT_COOLDOWN_MS = 12 * 60 * 1000L;

    private final Context context;
    private final SharedPreferences prefs;

    public WifiThreatMonitor(Context context) {
        this.context = context.getApplicationContext();
        this.prefs = this.context.getSharedPreferences(PREF, Context.MODE_PRIVATE);
    }

    public void scanAndRaise() {
        Observation observation = observe();
        if (!observation.usable) {
            return;
        }
        float risk = Math.max(runModel(observation.features), observation.ruleScore);
        saveBaseline(observation, risk >= 0.65f);
        if (risk < 0.65f) {
            return;
        }
        long now = System.currentTimeMillis();
        String cooldownKey = "last_alert_" + observation.networkKey;
        if (now - prefs.getLong(cooldownKey, 0L) < ALERT_COOLDOWN_MS) {
            return;
        }
        prefs.edit().putLong(cooldownKey, now).apply();
        raise(observation, risk);
    }

    private Observation observe() {
        Observation o = new Observation();
        o.nowMs = System.currentTimeMillis();
        try {
            WifiManager wifi = (WifiManager) context.getApplicationContext().getSystemService(Context.WIFI_SERVICE);
            if (wifi == null) {
                return o;
            }
            WifiInfo info = wifi.getConnectionInfo();
            DhcpInfo dhcp = wifi.getDhcpInfo();
            if (info == null || dhcp == null) {
                return o;
            }
            o.ssid = clean(info.getSSID());
            o.bssid = clean(info.getBSSID());
            o.rssi = info.getRssi();
            o.frequency = info.getFrequency();
            o.securityType = currentSecurityType(info);
            o.gatewayIp = intToIp(dhcp.gateway);
            o.networkKey = (o.ssid + "|" + o.gatewayIp).toLowerCase(Locale.US);
            o.usable = !o.gatewayIp.isEmpty() && !"0.0.0.0".equals(o.gatewayIp);
            if (!o.usable) {
                return o;
            }

            ArpTable arp = readArpTable();
            o.arpEntryCount = arp.entryCount;
            o.uniqueMacCount = arp.uniqueMacs.size();
            o.gatewayMac = arp.ipToMac.get(o.gatewayIp);
            o.gatewayArpPresent = o.gatewayMac != null && !o.gatewayMac.isEmpty();
            o.gatewayMacKnown = o.gatewayArpPresent && !"00:00:00:00:00:00".equals(o.gatewayMac);
            o.gatewayMacMultiIpCount = o.gatewayMacKnown && arp.macToIps.containsKey(o.gatewayMac) ? arp.macToIps.get(o.gatewayMac).size() : 0;
            o.duplicateIpMacCount = arp.duplicateIpMacCount;

            String previousGatewayMac = prefs.getString("gateway_mac_" + o.networkKey, "");
            String previousBssid = prefs.getString("bssid_" + o.networkKey, "");
            int previousRssi = prefs.getInt("rssi_" + o.networkKey, o.rssi);
            long firstSeen = prefs.getLong("first_seen_" + o.networkKey, o.nowMs);
            long lastGatewayChange = prefs.getLong("last_gateway_change_" + o.networkKey, o.nowMs);
            o.gatewayMacChanged = o.gatewayMacKnown && !previousGatewayMac.isEmpty() && !previousGatewayMac.equals(o.gatewayMac);
            o.bssidChanged = !previousBssid.isEmpty() && !previousBssid.equals(o.bssid);
            o.rssiDropHint = previousRssi - o.rssi >= 18;
            o.secondsSinceGatewayChange = Math.min(7200f, Math.max(0f, (o.nowMs - lastGatewayChange) / 1000f));
            o.networkAgeMinutes = Math.min(1440f, Math.max(0f, (o.nowMs - firstSeen) / 60000f));

            Set<String> previousMacs = splitSet(prefs.getString("last_mac_set_" + o.networkKey, ""));
            o.newMacCount = differenceCount(arp.uniqueMacs, previousMacs);
            o.lostMacCount = differenceCount(previousMacs, arp.uniqueMacs);
            o.arpTableChurn = o.newMacCount + o.lostMacCount;
            o.currentMacSet = arp.uniqueMacs;
            fillFeatures(o);
        } catch (Throwable ignored) {
            o.usable = false;
        }
        return o;
    }

    private void fillFeatures(Observation o) {
        float[] f = o.features;
        f[0] = 1f;
        f[1] = o.gatewayIp.isEmpty() ? 0f : 1f;
        f[2] = o.gatewayArpPresent ? 1f : 0f;
        f[3] = o.gatewayMacKnown ? 1f : 0f;
        f[4] = o.gatewayMacChanged ? 1f : 0f;
        f[5] = Math.min(1f, o.gatewayMacMultiIpCount / 6f);
        f[6] = Math.min(1f, o.duplicateIpMacCount / 6f);
        f[7] = Math.min(1f, o.arpEntryCount / 64f);
        f[8] = Math.min(1f, o.uniqueMacCount / 64f);
        f[9] = Math.min(1f, o.arpTableChurn / 16f);
        f[10] = Math.min(1f, o.newMacCount / 16f);
        f[11] = Math.min(1f, o.lostMacCount / 16f);
        f[12] = o.bssidChanged ? 1f : 0f;
        f[13] = hash01(o.ssid);
        f[14] = hash01(o.bssid);
        f[15] = hash01(o.gatewayIp);
        f[16] = hash01(o.gatewayMac);
        f[17] = Math.min(1f, o.secondsSinceGatewayChange / 7200f);
        f[18] = isPrivateGateway(o.gatewayIp) ? 1f : 0f;
        f[19] = "00:00:00:00:00:00".equals(o.gatewayMac) ? 1f : 0f;
        f[20] = "ff:ff:ff:ff:ff:ff".equals(o.gatewayMac) ? 1f : 0f;
        f[21] = isLocalAdminMac(o.gatewayMac) ? 1f : 0f;
        f[22] = f[7];
        f[23] = o.arpEntryCount <= 0 ? 0f : Math.min(1f, o.duplicateIpMacCount / (float) o.arpEntryCount);
        f[24] = o.gatewayArpPresent ? 1f : 0f;
        f[25] = ruleScore(o);
        f[26] = 1f;
        f[27] = 0f;
        f[28] = 0f;
        f[29] = o.gatewayMacChanged || o.bssidChanged ? 1f : 0f;
        f[30] = Math.min(1f, o.networkAgeMinutes / 1440f);
        f[31] = 1f;
        f[32] = Math.max(0f, Math.min(1f, (o.rssi + 100f) / 75f));
        f[33] = o.rssiDropHint ? 1f : 0f;
        f[34] = o.securityType == 0 ? 1f : 0f;
        f[35] = o.securityType == 4 || o.securityType == 5 || o.securityType == 6 ? 1f : 0f;
        f[36] = o.bssidChanged ? 1f : 0f;
        f[37] = 0f;
        f[38] = 0f;
        f[39] = 0f;
        f[40] = 0f;
        f[41] = 0f;
        f[42] = 0f;
        f[43] = o.bssidChanged && (o.rssiDropHint || o.gatewayMacChanged) ? 1f : 0f;
        f[44] = 0f;
        f[45] = 0f;
        f[46] = o.arpTableChurn >= 4 || o.bssidChanged ? 1f : 0f;
        f[47] = 0f;
        o.ruleScore = f[25];
    }

    private float runModel(float[] features) {
        ModelSpec spec = ModelCatalog.load(context).byId(MODEL_ID);
        if (spec == null) {
            return 0f;
        }
        try (TfliteThreatModel model = new TfliteThreatModel(context, spec)) {
            ThreatScore score = model.run(features);
            return Math.max(score.risk, score.confidence);
        } catch (Throwable ignored) {
            return 0f;
        }
    }

    private void raise(Observation observation, float risk) {
        Intent intent = new Intent(context, CyberDefenseService.class);
        intent.setAction(CyberDefenseService.ACTION_RAISE_THREAT);
        intent.putExtra(CyberDefenseService.EXTRA_MODEL_ID, MODEL_ID);
        intent.putExtra(CyberDefenseService.EXTRA_TITLE, "Wi-Fi saldırı riski");
        intent.putExtra(CyberDefenseService.EXTRA_SOURCE, "wifi_threat_guard");
        intent.putExtra(CyberDefenseService.EXTRA_TARGET, observation.ssid + " | " + observation.bssid + " | gateway " + observation.gatewayIp);
        intent.putExtra(CyberDefenseService.EXTRA_SEVERITY, risk >= 0.85f ? "critical" : "high");
        intent.putExtra(CyberDefenseService.EXTRA_PROBABILITY, (double) risk);
        intent.putExtra(CyberDefenseService.EXTRA_RECOMMENDED_ACTION, risk >= 0.85f ? "temporary_block" : "require_vpn");
        if (Build.VERSION.SDK_INT >= 26) {
            context.startForegroundService(intent);
        } else {
            context.startService(intent);
        }
    }

    private void saveBaseline(Observation o, boolean suspicious) {
        SharedPreferences.Editor editor = prefs.edit();
        if (!prefs.contains("first_seen_" + o.networkKey)) {
            editor.putLong("first_seen_" + o.networkKey, o.nowMs);
        }
        String oldGateway = prefs.getString("gateway_mac_" + o.networkKey, "");
        if (o.gatewayMacKnown) {
            if (!oldGateway.isEmpty() && !oldGateway.equals(o.gatewayMac)) {
                editor.putLong("last_gateway_change_" + o.networkKey, o.nowMs);
            }
            if (!suspicious || oldGateway.isEmpty()) {
                editor.putString("gateway_mac_" + o.networkKey, o.gatewayMac);
            }
        }
        if (!o.bssid.isEmpty() && (!suspicious || !prefs.contains("bssid_" + o.networkKey))) {
            editor.putString("bssid_" + o.networkKey, o.bssid);
        }
        editor.putInt("rssi_" + o.networkKey, o.rssi);
        editor.putString("last_mac_set_" + o.networkKey, joinSet(o.currentMacSet));
        editor.apply();
    }

    private static float ruleScore(Observation o) {
        float score = 0f;
        if (o.gatewayMacChanged) score += 0.32f;
        if (o.bssidChanged) score += 0.24f;
        if (o.rssiDropHint) score += 0.10f;
        if (o.gatewayMacMultiIpCount >= 2) score += 0.12f;
        if (o.duplicateIpMacCount > 0) score += 0.12f;
        if (o.arpTableChurn >= 6) score += 0.14f;
        else if (o.arpTableChurn >= 3) score += 0.07f;
        if (isLocalAdminMac(o.gatewayMac)) score += 0.05f;
        return Math.min(1f, score);
    }

    private ArpTable readArpTable() {
        ArpTable table = new ArpTable();
        try (BufferedReader reader = new BufferedReader(new FileReader("/proc/net/arp"))) {
            String line;
            boolean header = true;
            while ((line = reader.readLine()) != null) {
                if (header) {
                    header = false;
                    continue;
                }
                String[] parts = line.trim().split("\\s+");
                if (parts.length < 4) {
                    continue;
                }
                String ip = parts[0];
                String mac = parts[3].toLowerCase(Locale.US);
                if (mac.length() < 11) {
                    continue;
                }
                table.entryCount++;
                table.uniqueMacs.add(mac);
                table.ipToMac.put(ip, mac);
                Set<String> ips = table.macToIps.get(mac);
                if (ips == null) {
                    ips = new HashSet<>();
                    table.macToIps.put(mac, ips);
                }
                ips.add(ip);
                Set<String> macs = table.ipToMacs.get(ip);
                if (macs == null) {
                    macs = new HashSet<>();
                    table.ipToMacs.put(ip, macs);
                }
                macs.add(mac);
            }
        } catch (Throwable ignored) {
        }
        for (Set<String> macs : table.ipToMacs.values()) {
            if (macs.size() > 1) {
                table.duplicateIpMacCount += macs.size() - 1;
            }
        }
        table.uniqueMacs = new TreeSet<>(table.uniqueMacs);
        return table;
    }

    private static int currentSecurityType(WifiInfo info) {
        if (Build.VERSION.SDK_INT < 31) {
            return -1;
        }
        try {
            return info.getCurrentSecurityType();
        } catch (Throwable ignored) {
            return -1;
        }
    }

    private static int differenceCount(Set<String> left, Set<String> right) {
        if (left == null || left.isEmpty()) return 0;
        int count = 0;
        for (String value : left) {
            if (right == null || !right.contains(value)) count++;
        }
        return count;
    }

    private static Set<String> splitSet(String value) {
        TreeSet<String> set = new TreeSet<>();
        if (value == null || value.trim().isEmpty()) return set;
        for (String item : value.split(",")) {
            String clean = item.trim();
            if (!clean.isEmpty()) set.add(clean);
        }
        return set;
    }

    private static String joinSet(Set<String> values) {
        if (values == null || values.isEmpty()) return "";
        StringBuilder builder = new StringBuilder();
        for (String value : values) {
            if (builder.length() > 0) builder.append(',');
            builder.append(value);
        }
        return builder.toString();
    }

    private static boolean isPrivateGateway(String ip) {
        return ip.startsWith("10.") || ip.startsWith("192.168.") || ip.matches("172\\.(1[6-9]|2[0-9]|3[0-1])\\..*");
    }

    private static boolean isLocalAdminMac(String mac) {
        try {
            if (mac == null || mac.length() < 2) return false;
            int first = Integer.parseInt(mac.substring(0, 2), 16);
            return (first & 0x02) != 0;
        } catch (Exception e) {
            return false;
        }
    }

    private static String intToIp(int value) {
        return (value & 0xff) + "." + ((value >> 8) & 0xff) + "." + ((value >> 16) & 0xff) + "." + ((value >> 24) & 0xff);
    }

    private static float hash01(String value) {
        return ((clean(value).hashCode() & 0x7fffffff) % 10000) / 10000f;
    }

    private static String clean(String value) {
        if (value == null) return "";
        return value.replace("\"", "").trim().toLowerCase(Locale.US);
    }

    private static final class ArpTable {
        int entryCount;
        int duplicateIpMacCount;
        Set<String> uniqueMacs = new TreeSet<>();
        Map<String, String> ipToMac = new HashMap<>();
        Map<String, Set<String>> ipToMacs = new HashMap<>();
        Map<String, Set<String>> macToIps = new HashMap<>();
    }

    private static final class Observation {
        boolean usable;
        long nowMs;
        String ssid = "";
        String bssid = "";
        String gatewayIp = "";
        String gatewayMac = "";
        String networkKey = "";
        int rssi;
        int frequency;
        int securityType;
        boolean gatewayArpPresent;
        boolean gatewayMacKnown;
        boolean gatewayMacChanged;
        boolean bssidChanged;
        boolean rssiDropHint;
        int gatewayMacMultiIpCount;
        int duplicateIpMacCount;
        int arpEntryCount;
        int uniqueMacCount;
        int arpTableChurn;
        int newMacCount;
        int lostMacCount;
        float secondsSinceGatewayChange;
        float networkAgeMinutes;
        float ruleScore;
        Set<String> currentMacSet = new TreeSet<>();
        final float[] features = new float[48];
    }
}
