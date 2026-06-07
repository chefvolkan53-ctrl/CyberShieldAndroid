package com.monster.cybershield.core;

import android.content.Context;
import android.content.SharedPreferences;
import android.net.Uri;

import org.json.JSONArray;
import org.json.JSONObject;

import java.util.ArrayDeque;
import java.util.HashSet;
import java.util.Set;

public final class BlocklistStore {
    private static final String PREF = "blocklist";
    private static final String KEY_TARGETS = "targets";
    private static final String KEY_ALLOW = "allow";
    private static final String KEY_TEMP = "temporary";
    private static final String KEY_UNDO = "undo";
    private final SharedPreferences prefs;

    public BlocklistStore(Context context) {
        prefs = context.getSharedPreferences(PREF, Context.MODE_PRIVATE);
    }

    public void block(String target) {
        if (target == null || target.trim().isEmpty()) {
            return;
        }
        Set<String> values = all();
        String normalized = normalize(target);
        values.add(normalized);
        pushUndo("block", normalized);
        save(KEY_TARGETS, values);
    }

    public void temporaryBlock(String target, long durationMs) {
        String normalized = normalize(target);
        if (normalized.isEmpty()) {
            return;
        }
        try {
            JSONObject root = new JSONObject(prefs.getString(KEY_TEMP, "{}"));
            root.put(normalized, System.currentTimeMillis() + durationMs);
            prefs.edit().putString(KEY_TEMP, root.toString()).apply();
            pushUndo("temporary", normalized);
        } catch (Exception ignored) {
        }
    }

    public void allow(String target) {
        String normalized = normalize(target);
        if (normalized.isEmpty()) {
            return;
        }
        Set<String> values = allowList();
        values.add(normalized);
        Set<String> blocked = all();
        blocked.remove(normalized);
        save(KEY_ALLOW, values);
        save(KEY_TARGETS, blocked);
        pushUndo("allow", normalized);
    }

    public void remove(String target) {
        String normalized = normalize(target);
        Set<String> blocked = all();
        Set<String> allowed = allowList();
        blocked.remove(normalized);
        allowed.remove(normalized);
        save(KEY_TARGETS, blocked);
        save(KEY_ALLOW, allowed);
    }

    public boolean isAllowed(String target) {
        return matchesAny(allowList(), target);
    }

    public boolean isBlocked(String target) {
        if (isAllowed(target)) {
            return false;
        }
        return matchesAny(all(), target) || isTemporaryBlocked(target);
    }

    public boolean isTemporaryBlocked(String target) {
        cleanupTemporary();
        try {
            JSONObject root = new JSONObject(prefs.getString(KEY_TEMP, "{}"));
            String normalized = normalize(target);
            if (root.has(normalized)) {
                return root.optLong(normalized) > System.currentTimeMillis();
            }
            for (String key : jsonKeys(root)) {
                if (targetMatches(key, normalized) && root.optLong(key) > System.currentTimeMillis()) {
                    return true;
                }
            }
        } catch (Exception ignored) {
        }
        return false;
    }

    public Set<String> all() {
        return readSet(KEY_TARGETS);
    }

    public Set<String> allowList() {
        return readSet(KEY_ALLOW);
    }

    public String undoLast() {
        try {
            JSONArray undo = new JSONArray(prefs.getString(KEY_UNDO, "[]"));
            if (undo.length() == 0) {
                return "";
            }
            JSONObject last = undo.getJSONObject(undo.length() - 1);
            JSONArray next = new JSONArray();
            for (int i = 0; i < undo.length() - 1; i++) {
                next.put(undo.get(i));
            }
            prefs.edit().putString(KEY_UNDO, next.toString()).apply();
            String target = last.optString("target");
            remove(target);
            return target;
        } catch (Exception ignored) {
            return "";
        }
    }

    private Set<String> readSet(String key) {
        HashSet<String> values = new HashSet<>();
        try {
            JSONArray array = new JSONArray(prefs.getString(key, "[]"));
            for (int i = 0; i < array.length(); i++) {
                values.add(array.optString(i));
            }
        } catch (Exception ignored) {
        }
        return values;
    }

    private void save(String key, Set<String> values) {
        JSONArray array = new JSONArray();
        for (String value : values) {
            array.put(value);
        }
        prefs.edit().putString(key, array.toString()).apply();
    }

    private void pushUndo(String action, String target) {
        try {
            JSONArray undo = new JSONArray(prefs.getString(KEY_UNDO, "[]"));
            JSONObject entry = new JSONObject();
            entry.put("action", action);
            entry.put("target", target);
            entry.put("time", System.currentTimeMillis());
            undo.put(entry);
            while (undo.length() > 20) {
                JSONArray trimmed = new JSONArray();
                for (int i = 1; i < undo.length(); i++) {
                    trimmed.put(undo.get(i));
                }
                undo = trimmed;
            }
            prefs.edit().putString(KEY_UNDO, undo.toString()).apply();
        } catch (Exception ignored) {
        }
    }

    private void cleanupTemporary() {
        try {
            JSONObject root = new JSONObject(prefs.getString(KEY_TEMP, "{}"));
            JSONObject clean = new JSONObject();
            long now = System.currentTimeMillis();
            for (String key : jsonKeys(root)) {
                long expiresAt = root.optLong(key);
                if (expiresAt > now) {
                    clean.put(key, expiresAt);
                }
            }
            prefs.edit().putString(KEY_TEMP, clean.toString()).apply();
        } catch (Exception ignored) {
        }
    }

    private static Set<String> jsonKeys(JSONObject object) {
        HashSet<String> keys = new HashSet<>();
        JSONArray names = object.names();
        if (names == null) {
            return keys;
        }
        for (int i = 0; i < names.length(); i++) {
            keys.add(names.optString(i));
        }
        return keys;
    }

    private static boolean matchesAny(Set<String> values, String target) {
        String normalized = normalize(target);
        for (String value : values) {
            if (targetMatches(value, normalized)) {
                return true;
            }
        }
        return false;
    }

    private static boolean targetMatches(String rule, String target) {
        if (target == null) {
            return false;
        }
        String normalizedRule = normalize(rule);
        String normalizedTarget = normalize(target);
        return normalizedTarget.equals(normalizedRule)
                || normalizedTarget.endsWith("." + normalizedRule)
                || normalizedTarget.contains(normalizedRule)
                || normalizedRule.contains(":") && normalizedTarget.startsWith(normalizedRule);
    }

    private static String normalize(String target) {
        if (target == null) {
            return "";
        }
        String value = target.trim().toLowerCase();
        if (value.startsWith("http://") || value.startsWith("https://")) {
            try {
                Uri uri = Uri.parse(value);
                String host = uri.getHost();
                if (host != null && !host.trim().isEmpty()) {
                    int port = uri.getPort();
                    return port > 0 ? host.toLowerCase() + ":" + port : host.toLowerCase();
                }
            } catch (Exception ignored) {
            }
        }
        if (value.startsWith("www.")) {
            return value.substring(4);
        }
        int slash = value.indexOf('/');
        if (slash > 0 && value.indexOf(' ') < 0) {
            value = value.substring(0, slash);
        }
        return value;
    }
}
