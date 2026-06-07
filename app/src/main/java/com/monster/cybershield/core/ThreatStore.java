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

    public void mark(String id, String status) {
        ArrayList<ThreatEvent> updated = new ArrayList<>();
        for (ThreatEvent event : list()) {
            if (event.id.equals(id)) {
                updated.add(new ThreatEvent(event.id, event.modelId, event.title, event.source, event.target, event.severity, event.probability, event.createdAt, status, event.recommendedAction));
            } else {
                updated.add(event);
            }
        }
        save(updated);
    }

    private void save(List<ThreatEvent> events) {
        JSONArray array = new JSONArray();
        int count = 0;
        for (ThreatEvent event : events) {
            if (count++ >= 100) {
                break;
            }
            array.put(event.toJson());
        }
        prefs.edit().putString(KEY_EVENTS, array.toString()).apply();
    }
}
