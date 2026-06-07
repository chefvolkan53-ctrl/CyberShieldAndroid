package com.monster.cybershield.core;

import android.content.Context;
import android.content.SharedPreferences;

import org.json.JSONObject;

public final class ProtectionPolicyStore {
    private static final String PREF = "protection_policy";
    private static final String KEY_STRICT_UNTIL = "strict_until";
    private static final String KEY_STRICT_REASON = "strict_reason";
    private static final String KEY_LAST_HTTP_ALERT = "last_http_alert";
    private static final String KEY_LAST_DNS_LEAK_ALERT = "last_dns_leak_alert";
    private static final String KEY_DNS_LEAK_PROTECTION = "dns_leak_protection";
    private static final String KEY_DNS_PROVIDER = "dns_provider";
    private static final String KEY_BLOCK_DOH_WHEN_STRICT = "block_doh_when_strict";
    private static final long HTTP_ALERT_COOLDOWN_MS = 10 * 60 * 1000L;
    private static final long DNS_LEAK_ALERT_COOLDOWN_MS = 10 * 60 * 1000L;
    public static final String DNS_CLOUDFLARE = "1.1.1.1";
    public static final String DNS_CLOUDFLARE_SECONDARY = "1.0.0.1";
    public static final String DNS_QUAD9 = "9.9.9.9";
    public static final String DNS_GOOGLE = "8.8.8.8";
    public static final String DNS_ADGUARD = "94.140.14.14";

    private final SharedPreferences prefs;

    public ProtectionPolicyStore(Context context) {
        prefs = context.getApplicationContext().getSharedPreferences(PREF, Context.MODE_PRIVATE);
    }

    public void requireStrictVpn(String reason, long durationMs) {
        long until = System.currentTimeMillis() + Math.max(durationMs, 5 * 60 * 1000L);
        prefs.edit()
                .putLong(KEY_STRICT_UNTIL, until)
                .putString(KEY_STRICT_REASON, safe(reason))
                .apply();
    }

    public boolean isStrictVpnRequired() {
        return prefs.getLong(KEY_STRICT_UNTIL, 0L) > System.currentTimeMillis();
    }

    public String strictReason() {
        return prefs.getString(KEY_STRICT_REASON, "");
    }

    public void markSuspiciousWifi(String networkKey, String ssid, String gatewayIp, float risk) {
        try {
            JSONObject root = new JSONObject(prefs.getString("suspicious_wifi", "{}"));
            JSONObject entry = new JSONObject();
            entry.put("ssid", safe(ssid));
            entry.put("gatewayIp", safe(gatewayIp));
            entry.put("risk", risk);
            entry.put("lastSeen", System.currentTimeMillis());
            root.put(safe(networkKey), entry);
            prefs.edit().putString("suspicious_wifi", root.toString()).apply();
        } catch (Exception ignored) {
        }
    }

    public boolean shouldBlockCleartextHttp() {
        return isStrictVpnRequired();
    }

    public void setDnsLeakProtection(boolean enabled) {
        prefs.edit().putBoolean(KEY_DNS_LEAK_PROTECTION, enabled).apply();
    }

    public boolean isDnsLeakProtectionEnabled() {
        return prefs.getBoolean(KEY_DNS_LEAK_PROTECTION, true);
    }

    public void setDnsProvider(String providerIp) {
        prefs.edit().putString(KEY_DNS_PROVIDER, safe(providerIp)).apply();
    }

    public String dnsProvider() {
        String value = prefs.getString(KEY_DNS_PROVIDER, DNS_CLOUDFLARE);
        return isAllowedResolver(value) ? value : DNS_CLOUDFLARE;
    }

    public String dnsProviderSecondary() {
        String primary = dnsProvider();
        if (DNS_CLOUDFLARE.equals(primary)) {
            return DNS_CLOUDFLARE_SECONDARY;
        }
        return "";
    }

    public boolean isAllowedResolver(String host) {
        String value = safe(host);
        return DNS_CLOUDFLARE.equals(value)
                || DNS_CLOUDFLARE_SECONDARY.equals(value)
                || DNS_QUAD9.equals(value)
                || DNS_GOOGLE.equals(value)
                || DNS_ADGUARD.equals(value);
    }

    public boolean shouldAllowDnsResolver(String host) {
        if (!isDnsLeakProtectionEnabled()) {
            return true;
        }
        String value = safe(host);
        return value.equals(dnsProvider()) || value.equals(dnsProviderSecondary());
    }

    public boolean shouldBlockDohEndpoint(String host, int port) {
        if (!isDnsLeakProtectionEnabled() || port != 443) {
            return false;
        }
        String value = safe(host).toLowerCase();
        boolean blockDoh = prefs.getBoolean(KEY_BLOCK_DOH_WHEN_STRICT, true);
        return blockDoh && (containsDohHost(value) || isStrictVpnRequired() && isAllowedResolver(value));
    }

    public String dnsLeakProtectionSummary() {
        return "DNS leak protection: " + (isDnsLeakProtectionEnabled() ? "ACIK" : "KAPALI")
                + " | Resolver: " + dnsProvider();
    }

    private static boolean containsDohHost(String host) {
        return host.contains("cloudflare-dns.com")
                || host.contains("dns.google")
                || host.contains("quad9.net")
                || host.contains("nextdns.io")
                || host.contains("dns.adguard")
                || host.contains("doh.")
                || host.contains("/dns-query");
    }

    public boolean shouldRaiseHttpDowngradeAlert() {
        long now = System.currentTimeMillis();
        long last = prefs.getLong(KEY_LAST_HTTP_ALERT, 0L);
        if (now - last < HTTP_ALERT_COOLDOWN_MS) {
            return false;
        }
        prefs.edit().putLong(KEY_LAST_HTTP_ALERT, now).apply();
        return true;
    }

    public boolean shouldRaiseDnsLeakAlert() {
        long now = System.currentTimeMillis();
        long last = prefs.getLong(KEY_LAST_DNS_LEAK_ALERT, 0L);
        if (now - last < DNS_LEAK_ALERT_COOLDOWN_MS) {
            return false;
        }
        prefs.edit().putLong(KEY_LAST_DNS_LEAK_ALERT, now).apply();
        return true;
    }

    private static String safe(String value) {
        return value == null ? "" : value.trim();
    }
}
