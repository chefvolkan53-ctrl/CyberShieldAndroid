package com.monster.cybershield.core;

import android.content.Context;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.nio.charset.StandardCharsets;
import java.util.HashSet;
import java.util.Locale;
import java.util.Set;

public final class ThreatIntelStore {
    private final Set<String> domains = new HashSet<>();
    private final Set<String> ips = new HashSet<>();
    private final Set<String> cidrs = new HashSet<>();
    private final Set<String> phishingPatterns = new HashSet<>();
    private final Set<String> dohEndpoints = new HashSet<>();
    private final Set<Integer> riskyPorts = new HashSet<>();

    public ThreatIntelStore(Context context) {
        load(new SecurityUpdateStore(context).feedFile("threat_intel"));
    }

    public boolean isKnownMaliciousTarget(String target) {
        String host = AlertNoisePolicy.normalizedHost(target);
        if (host.isEmpty()) {
            return false;
        }
        if (BuiltInThreatTargets.isKnownTestThreat(target)) {
            return true;
        }
        if (ips.contains(host) || domains.contains(host) || matchesCidr(host)) {
            return true;
        }
        for (String domain : domains) {
            if (host.endsWith("." + domain)) {
                return true;
            }
        }
        return false;
    }

    public boolean isKnownPhishingUrl(String url) {
        String value = safe(url).toLowerCase(Locale.US);
        if (BuiltInThreatTargets.isKnownTestThreatUrl(value)) {
            return true;
        }
        if (isKnownMaliciousTarget(value)) {
            return true;
        }
        for (String pattern : phishingPatterns) {
            if (!pattern.isEmpty() && value.contains(pattern)) {
                return true;
            }
        }
        return false;
    }

    public boolean isKnownDohEndpoint(String target) {
        String host = AlertNoisePolicy.normalizedHost(target);
        return !host.isEmpty() && dohEndpoints.contains(host);
    }

    public boolean isRiskyPort(int port) {
        return riskyPorts.contains(port);
    }

    private void load(File file) {
        if (file == null || !file.isFile()) {
            return;
        }
        try {
            JSONObject root = new JSONObject(read(file));
            readStrings(root.optJSONArray("malicious_domains"), domains);
            readStrings(root.optJSONArray("malicious_ips"), ips);
            readStrings(root.optJSONArray("malicious_cidrs"), cidrs);
            readStrings(root.optJSONArray("phishing_patterns"), phishingPatterns);
            readStrings(root.optJSONArray("doh_endpoints"), dohEndpoints);
            JSONArray ports = root.optJSONArray("risky_ports");
            if (ports != null) {
                for (int i = 0; i < ports.length(); i++) {
                    int port = ports.optInt(i, -1);
                    if (port > 0 && port <= 65535) {
                        riskyPorts.add(port);
                    }
                }
            }
        } catch (Exception ignored) {
        }
    }

    private boolean matchesCidr(String host) {
        long ip = ipv4ToLong(host);
        if (ip < 0) {
            return false;
        }
        for (String cidr : cidrs) {
            if (cidrContains(cidr, ip)) {
                return true;
            }
        }
        return false;
    }

    private static boolean cidrContains(String cidr, long ip) {
        try {
            String[] parts = safe(cidr).split("/");
            if (parts.length != 2) {
                return false;
            }
            long base = ipv4ToLong(parts[0]);
            int prefix = Integer.parseInt(parts[1]);
            if (base < 0 || prefix < 0 || prefix > 32) {
                return false;
            }
            long mask = prefix == 0 ? 0 : (0xFFFFFFFFL << (32 - prefix)) & 0xFFFFFFFFL;
            return (ip & mask) == (base & mask);
        } catch (Exception e) {
            return false;
        }
    }

    private static long ipv4ToLong(String value) {
        String[] parts = safe(value).split("\\.");
        if (parts.length != 4) {
            return -1L;
        }
        long result = 0L;
        for (String part : parts) {
            try {
                int octet = Integer.parseInt(part);
                if (octet < 0 || octet > 255) {
                    return -1L;
                }
                result = (result << 8) | octet;
            } catch (Exception e) {
                return -1L;
            }
        }
        return result;
    }

    private static void readStrings(JSONArray array, Set<String> out) {
        if (array == null) {
            return;
        }
        for (int i = 0; i < array.length(); i++) {
            String value = safe(array.optString(i)).toLowerCase(Locale.US);
            if (!value.isEmpty()) {
                out.add(value);
            }
        }
    }

    private static String read(File file) throws Exception {
        try (FileInputStream input = new FileInputStream(file);
             ByteArrayOutputStream output = new ByteArrayOutputStream()) {
            byte[] buffer = new byte[8192];
            int read;
            while ((read = input.read(buffer)) != -1) {
                output.write(buffer, 0, read);
            }
            return output.toString(StandardCharsets.UTF_8.name());
        }
    }

    private static String safe(String value) {
        return value == null ? "" : value.trim();
    }
}
