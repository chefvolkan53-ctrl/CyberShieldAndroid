package com.monster.cybershield.core;

import android.content.Context;
import android.content.SharedPreferences;

public final class ModelCalibrationStore {
    private static final String PREF = "model_calibration";
    private static final String THRESHOLD_PREFIX = "threshold:";
    private final SharedPreferences preferences;

    public ModelCalibrationStore(Context context) {
        this.preferences = context.getApplicationContext().getSharedPreferences(PREF, Context.MODE_PRIVATE);
    }

    public double threshold(String modelId, double fallback) {
        String key = THRESHOLD_PREFIX + normalize(modelId);
        if (!preferences.contains(key)) {
            return fallback;
        }
        return Double.longBitsToDouble(preferences.getLong(key, Double.doubleToLongBits(fallback)));
    }

    public void setThreshold(String modelId, double threshold) {
        double clipped = Math.max(0.01, Math.min(0.99, threshold));
        preferences.edit().putLong(THRESHOLD_PREFIX + normalize(modelId), Double.doubleToLongBits(clipped)).apply();
    }

    public void recordOutcome(String modelId, boolean expectedMalicious, boolean predictedMalicious) {
        String prefix = "outcome:" + normalize(modelId) + ":";
        String key;
        if (expectedMalicious && predictedMalicious) key = prefix + "tp";
        else if (!expectedMalicious && predictedMalicious) key = prefix + "fp";
        else if (expectedMalicious) key = prefix + "fn";
        else key = prefix + "tn";
        preferences.edit().putInt(key, preferences.getInt(key, 0) + 1).apply();
    }

    public String summary(String modelId) {
        String prefix = "outcome:" + normalize(modelId) + ":";
        int tp = preferences.getInt(prefix + "tp", 0);
        int fp = preferences.getInt(prefix + "fp", 0);
        int fn = preferences.getInt(prefix + "fn", 0);
        int tn = preferences.getInt(prefix + "tn", 0);
        return "tp=" + tp + ", fp=" + fp + ", fn=" + fn + ", tn=" + tn;
    }

    private static String normalize(String value) {
        return value == null ? "" : value.trim().toLowerCase(java.util.Locale.US);
    }
}
