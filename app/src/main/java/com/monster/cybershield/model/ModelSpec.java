package com.monster.cybershield.model;

import org.json.JSONArray;
import org.json.JSONObject;

import java.util.ArrayList;
import java.util.List;

public final class ModelSpec {
    public final String id;
    public final String title;
    public final String asset;
    public final int inputSize;
    public final double threshold;
    public final double accuracy;
    public final double recall;
    public final List<String> outputs;
    public final List<String> interventions;

    private ModelSpec(
            String id,
            String title,
            String asset,
            int inputSize,
            double threshold,
            double accuracy,
            double recall,
            List<String> outputs,
            List<String> interventions
    ) {
        this.id = id;
        this.title = title;
        this.asset = asset;
        this.inputSize = inputSize;
        this.threshold = threshold;
        this.accuracy = accuracy;
        this.recall = recall;
        this.outputs = outputs;
        this.interventions = interventions;
    }

    public static ModelSpec fromJson(JSONObject json) {
        return new ModelSpec(
                json.optString("id"),
                json.optString("title"),
                json.optString("asset"),
                json.optInt("input_size"),
                json.optDouble("threshold", 0.5),
                json.optDouble("accuracy", 0.0),
                json.optDouble("recall", 0.0),
                readStringList(json.optJSONArray("outputs")),
                readStringList(json.optJSONArray("interventions"))
        );
    }

    private static List<String> readStringList(JSONArray array) {
        ArrayList<String> values = new ArrayList<>();
        if (array == null) {
            return values;
        }
        for (int i = 0; i < array.length(); i++) {
            values.add(array.optString(i));
        }
        return values;
    }
}
