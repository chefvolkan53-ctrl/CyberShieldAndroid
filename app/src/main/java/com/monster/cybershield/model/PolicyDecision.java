package com.monster.cybershield.model;

public final class PolicyDecision {
    public final String action;
    public final float confidence;

    public PolicyDecision(String action, float confidence) {
        this.action = action;
        this.confidence = confidence;
    }
}
