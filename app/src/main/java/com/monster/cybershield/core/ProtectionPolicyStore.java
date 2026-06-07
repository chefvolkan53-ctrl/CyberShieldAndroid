package com.monster.cybershield.core;

import android.content.Context;
import android.content.SharedPreferences;

import org.json.JSONObject;

public final class ProtectionPolicyStore {
    private static final String PREF = "protection_policy";
    private static final String KEY_STRICT_UNTIL = "strict_until";
    private static final String KEY_STRICT_REASON = "strict_reason";
    private static final String KEY_LAST_HTTP_ALERT = "last_http_alert";
    private static final long HTTP_ALERT_COOLDOWN_MS = 10 * 60 * 1000L;

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

    public boolean shouldRaiseHttpDowngradeAlert() {
        long now = System.currentTimeMillis();
        long last = prefs.getLong(KEY_LAST_HTTP_ALERT, 0L);
        if (now - last < HTTP_ALERT_COOLDOWN_MS) {
            return false;
        }
        prefs.edit().putLong(KEY_LAST_HTTP_ALERT, now).apply();
        return true;
    }

    private static String safe(String value) {
        return value == null ? "" : value.trim();
    }
}
