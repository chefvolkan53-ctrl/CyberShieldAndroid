package com.monster.cybershield.core;

import android.content.Context;
import android.content.SharedPreferences;

import org.json.JSONArray;
import org.json.JSONObject;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.UUID;

public final class ThreatStore {
    private static final String PREF = "threat_store";
    private static final String KEY_EVENTS = "events";
    private static final int MAX_EVENTS = 100;
    private static final int MAX_ACTIVE_EVENTS = 12;

    private final SharedPreferences prefs;

    public ThreatStore(Context context) {
        this.prefs = context.getSharedPreferences(PREF, Context.MODE_PRIVATE);
    }

    public ThreatEvent add(String modelId, String title, String source, String target, String severity, double probability) {
        return add(modelId, title, source, target, severity, probability, "warn");
    }

    public ThreatEvent add(String modelId, String title, String source, String target, String severity, double probability, String recommendedAction) {
        ThreatEvent event = new ThreatEvent(
                UUID.randomUUID().toString(),
                modelId,
                title,
                source,
                target,
                severity,
                probability,
                System.currentTimeMillis(),
                "new",
                recommendedAction
        );
        ArrayList<ThreatEvent> events = new ArrayList<>(list());
        events.add(event);
        save(events);
        return event;
    }

    public ThreatEvent find(String id) {
        for (ThreatEvent event : list()) {
            if (event.id.equals(id)) {
                return event;
            }
        }
        return null;
    }

    public boolean hasRecentTarget(String target, long windowMs) {
        String normalized = AlertNoisePolicy.normalizedTarget(target);
        if (normalized.isEmpty()) {
            return false;
        }
        long minCreatedAt = System.currentTimeMillis() - Math.max(windowMs, 1000L);
        for (ThreatEvent event : list()) {
            if (event.createdAt < minCreatedAt) {
                continue;
            }
            if (normalized.equals(AlertNoisePolicy.normalizedTarget(event.target))) {
                return true;
            }
        }
        return false;
    }

    public boolean hasRecentModelTarget(String modelId, String target, long windowMs) {
        String normalized = AlertNoisePolicy.normalizedTarget(target);
        if (normalized.isEmpty()) {
            return false;
        }
        long minCreatedAt = System.currentTimeMillis() - Math.max(windowMs, 1000L);
        for (ThreatEvent event : list()) {
            if (event.createdAt < minCreatedAt) {
                continue;
            }
            if (event.modelId.equals(modelId) && normalized.equals(AlertNoisePolicy.normalizedTarget(event.target))) {
                return true;
            }
        }
        return false;
    }

    public List<ThreatEvent> list() {
        ArrayList<ThreatEvent> events = new ArrayList<>();
        try {
            JSONArray array = new JSONArray(prefs.getString(KEY_EVENTS, "[]"));
            for (int i = 0; i < array.length(); i++) {
                events.add(ThreatEvent.fromJson(array.getJSONObject(i)));
            }
        } catch (Exception ignored) {
        }
        Collections.sort(events, new Comparator<ThreatEvent>() {
            @Override
            public int compare(ThreatEvent a, ThreatEvent b) {
                return Long.compare(b.createdAt, a.createdAt);
            }
        });
        return events;
    }

    public List<ThreatEvent> activeList() {
        ArrayList<ThreatEvent> compacted = compact(list());
        save(compacted);
        ArrayList<ThreatEvent> active = new ArrayList<>();
        for (ThreatEvent event : compacted) {
            if (isActive(event)) {
                active.add(event);
            }
        }
        return active;
    }

    public List<ThreatEvent> historyList() {
        ArrayList<ThreatEvent> history = new ArrayList<>();
        for (ThreatEvent event : compact(list())) {
            if (!isActive(event)) {
                history.add(event);
            }
        }
        return history;
    }

    public void mark(String id, String status) {
        ArrayList<ThreatEvent> updated = new ArrayList<>();
        ThreatEvent resolved = null;
        for (ThreatEvent event : list()) {
            if (event.id.equals(id)) {
                resolved = event;
                updated.add(withStatus(event, status));
            } else {
                updated.add(event);
            }
        }
        if (resolved != null && !"new".equals(status)) {
            updated = resolveRelated(updated, resolved, status);
        }
        save(compact(updated));
    }

    public void clearResolved() {
        ArrayList<ThreatEvent> active = new ArrayList<>();
        for (ThreatEvent event : list()) {
            if (isActive(event)) {
                active.add(event);
            }
        }
        save(active);
    }

    public void clearAllActive() {
        ArrayList<ThreatEvent> updated = new ArrayList<>();
        for (ThreatEvent event : list()) {
            updated.add(isActive(event) ? withStatus(event, "dismissed") : event);
        }
        save(compact(updated));
    }

    private void save(List<ThreatEvent> events) {
        JSONArray array = new JSONArray();
        int count = 0;
        for (ThreatEvent event : compact(events)) {
            if (count++ >= MAX_EVENTS) {
                break;
            }
            array.put(event.toJson());
        }
        prefs.edit().putString(KEY_EVENTS, array.toString()).apply();
    }

    private ArrayList<ThreatEvent> compact(List<ThreatEvent> events) {
        ArrayList<ThreatEvent> sorted = new ArrayList<>(events);
        Collections.sort(sorted, new Comparator<ThreatEvent>() {
            @Override
            public int compare(ThreatEvent a, ThreatEvent b) {
                return Long.compare(b.createdAt, a.createdAt);
            }
        });
        ArrayList<ThreatEvent> result = new ArrayList<>();
        ArrayList<String> activeKeys = new ArrayList<>();
        int activeCount = 0;
        for (ThreatEvent event : sorted) {
            if ("new".equals(event.status) && isInternalVpnTarget(event.target)) {
                result.add(withStatus(event, "filtered"));
                continue;
            }
            if (isActive(event)) {
                String key = activeKey(event);
                if (activeKeys.contains(key)) {
                    result.add(withStatus(event, "superseded"));
                    continue;
                }
                if (activeCount >= MAX_ACTIVE_EVENTS) {
                    result.add(withStatus(event, "archived"));
                    continue;
                }
                activeKeys.add(key);
                activeCount++;
            }
            result.add(event);
        }
        return result;
    }

    private static ArrayList<ThreatEvent> resolveRelated(List<ThreatEvent> events, ThreatEvent resolved, String status) {
        ArrayList<ThreatEvent> updated = new ArrayList<>();
        String target = AlertNoisePolicy.normalizedTarget(resolved.target);
        for (ThreatEvent event : events) {
            if (!event.id.equals(resolved.id)
                    && isActive(event)
                    && event.modelId.equals(resolved.modelId)
                    && target.equals(AlertNoisePolicy.normalizedTarget(event.target))) {
                updated.add(withStatus(event, status));
            } else {
                updated.add(event);
            }
        }
        return updated;
    }

    private static boolean isActive(ThreatEvent event) {
        return "new".equals(event.status);
    }

    private static boolean isInternalVpnTarget(String target) {
        String host = AlertNoisePolicy.normalizedHost(target);
        return host.startsWith("10.88.")
                || "10.88.0.1".equals(host)
                || "10.88.0.2".equals(host);
    }

    private static String activeKey(ThreatEvent event) {
        return event.modelId + "|" + AlertNoisePolicy.normalizedTarget(event.target);
    }

    private static ThreatEvent withStatus(ThreatEvent event, String status) {
        return new ThreatEvent(event.id, event.modelId, event.title, event.source, event.target, event.severity, event.probability, event.createdAt, status, event.recommendedAction);
    }
}
