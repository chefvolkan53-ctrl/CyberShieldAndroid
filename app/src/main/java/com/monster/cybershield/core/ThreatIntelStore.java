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
        if (ips.contains(host) || domains.contains(host)) {
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
