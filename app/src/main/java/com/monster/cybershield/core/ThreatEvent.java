package com.monster.cybershield.core;

import org.json.JSONObject;

public final class ThreatEvent {
    public final String id;
    public final String modelId;
    public final String title;
    public final String source;
    public final String target;
    public final String severity;
    public final double probability;
    public final long createdAt;
    public final String status;

    public ThreatEvent(
            String id,
            String modelId,
            String title,
            String source,
            String target,
            String severity,
            double probability,
            long createdAt,
            String status
    ) {
        this.id = id;
        this.modelId = modelId;
        this.title = title;
        this.source = source;
        this.target = target;
        this.severity = severity;
        this.probability = probability;
        this.createdAt = createdAt;
        this.status = status;
    }

    public JSONObject toJson() {
        JSONObject json = new JSONObject();
        try {
            json.put("id", id);
            json.put("modelId", modelId);
            json.put("title", title);
            json.put("source", source);
            json.put("target", target);
            json.put("severity", severity);
            json.put("probability", probability);
            json.put("createdAt", createdAt);
            json.put("status", status);
        } catch (Exception ignored) {
        }
        return json;
    }

    public static ThreatEvent fromJson(JSONObject json) {
        return new ThreatEvent(
                json.optString("id"),
                json.optString("modelId"),
                json.optString("title"),
                json.optString("source"),
                json.optString("target"),
                json.optString("severity"),
                json.optDouble("probability"),
                json.optLong("createdAt"),
                json.optString("status", "new")
        );
    }
}
