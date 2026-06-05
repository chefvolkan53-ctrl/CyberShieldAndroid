package com.monster.cybershield.model;

public final class ThreatScore {
    public final String modelId;
    public final String modelTitle;
    public final float risk;
    public final float confidence;
    public final boolean actionable;
    public final double threshold;

    public ThreatScore(String modelId, String modelTitle, float risk, float confidence, boolean actionable, double threshold) {
        this.modelId = modelId;
        this.modelTitle = modelTitle;
        this.risk = risk;
        this.confidence = confidence;
        this.actionable = actionable;
        this.threshold = threshold;
    }
}
