package com.monster.cybershield.model;

import android.content.Context;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public final class ModelCatalog {
    private final List<ModelSpec> models;

    private ModelCatalog(List<ModelSpec> models) {
        this.models = models;
    }

    public static ModelCatalog load(Context context) {
        ArrayList<ModelSpec> specs = new ArrayList<>();
        try {
            String text = readAsset(context, "model_catalog.json");
            JSONObject root = new JSONObject(text);
            JSONArray array = root.getJSONArray("models");
            for (int i = 0; i < array.length(); i++) {
                specs.add(ModelSpec.fromJson(array.getJSONObject(i)));
            }
        } catch (Exception e) {
            throw new IllegalStateException("Model catalog could not be loaded", e);
        }
        return new ModelCatalog(specs);
    }

    public List<ModelSpec> all() {
        return Collections.unmodifiableList(models);
    }

    public ModelSpec byId(String id) {
        for (ModelSpec spec : models) {
            if (spec.id.equals(id)) {
                return spec;
            }
        }
        return null;
    }

    private static String readAsset(Context context, String path) throws Exception {
        try (InputStream input = context.getAssets().open(path);
             ByteArrayOutputStream output = new ByteArrayOutputStream()) {
            byte[] buffer = new byte[8192];
            int read;
            while ((read = input.read(buffer)) != -1) {
                output.write(buffer, 0, read);
            }
            return output.toString(StandardCharsets.UTF_8.name());
        }
    }
}
