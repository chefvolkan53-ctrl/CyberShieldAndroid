package com.monster.cybershield.model;

import android.content.Context;
import android.content.res.AssetFileDescriptor;

import org.json.JSONObject;
import org.tensorflow.lite.Interpreter;

import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.InputStream;
import java.nio.MappedByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;

public final class PolicyInterventionModel implements AutoCloseable {
    private static final String MODEL_ASSET = "models/cybershield_policy_intervention_model.tflite";
    private static final String METADATA_ASSET = "metadata/cybershield_policy_metadata.json";

    private final Interpreter interpreter;
    private final Map<Integer, String> actions;
    private final double[] scalerMean;
    private final double[] scalerScale;

    public PolicyInterventionModel(Context context) {
        try {
            JSONObject metadata = new JSONObject(readAsset(context, METADATA_ASSET));
            this.actions = readActions(metadata.getJSONObject("actions"));
            this.scalerMean = readDoubleArray(metadata.getJSONArray("scaler_mean"));
            this.scalerScale = readDoubleArray(metadata.getJSONArray("scaler_scale"));
            this.interpreter = loadInterpreter(context);
        } catch (Exception e) {
            throw new IllegalStateException("Policy intervention model could not be loaded: " + describe(e), e);
        }
    }

    public PolicyDecision recommend(ModelCatalog catalog, ModelSpec spec, ThreatScore score, String source) {
        float probability = Math.max(score.risk, score.confidence);
        float[] raw = new float[]{
                sourceId(source),
                modelIndex(catalog, spec.id),
                targetTypeId(spec.id),
                probability,
                (float) spec.threshold,
                probability >= spec.threshold ? 1f : 0f,
                (float) spec.accuracy,
                (float) spec.recall,
                requiresUserConfirmation(spec, probability) ? 1f : 0f,
                severityId(probability)
        };
        float[] scaled = new float[raw.length];
        for (int i = 0; i < raw.length; i++) {
            double scale = i < scalerScale.length && scalerScale[i] != 0.0 ? scalerScale[i] : 1.0;
            double mean = i < scalerMean.length ? scalerMean[i] : 0.0;
            scaled[i] = (float) ((raw[i] - mean) / scale);
        }

        float[][] output = new float[1][actions.size()];
        interpreter.run(new float[][]{scaled}, output);
        int best = 0;
        float confidence = output[0][0];
        for (int i = 1; i < output[0].length; i++) {
            if (output[0][i] > confidence) {
                confidence = output[0][i];
                best = i;
            }
        }
        String action = actions.containsKey(best) ? actions.get(best) : fallbackAction(spec, probability);
        return new PolicyDecision(action, confidence);
    }

    @Override
    public void close() {
        interpreter.close();
    }

    private static boolean requiresUserConfirmation(ModelSpec spec, float probability) {
        if (probability >= 0.75f) {
            return true;
        }
        for (String intervention : spec.interventions) {
            if (intervention.contains("block") || intervention.contains("quarantine") || intervention.contains("uninstall")) {
                return probability >= 0.50f;
            }
        }
        return false;
    }

    private static String fallbackAction(ModelSpec spec, float probability) {
        if (probability < 0.35f) {
            return "warn";
        }
        for (String intervention : spec.interventions) {
            String lower = intervention.toLowerCase(Locale.US);
            if (lower.contains("quarantine")) {
                return "quarantine";
            }
            if (lower.contains("block")) {
                return "block_flow";
            }
            if (lower.contains("uninstall")) {
                return "uninstall_prompt";
            }
        }
        return "warn";
    }

    private static int sourceId(String source) {
        if ("sms".equals(source)) return 0;
        if ("shared_link".equals(source)) return 1;
        if ("apk_monitor".equals(source)) return 2;
        if ("vpn_dns".equals(source)) return 3;
        if ("vpn_doh".equals(source)) return 4;
        if ("vpn_flow".equals(source)) return 5;
        if ("vpn_iot".equals(source)) return 6;
        if ("vpn_tls".equals(source)) return 7;
        if ("vpn_pqc".equals(source)) return 8;
        return 5;
    }

    private static int targetTypeId(String modelId) {
        if ("social_text".equals(modelId)) return 0;
        if ("social_url".equals(modelId) || "phishing_html".equals(modelId)) return 1;
        if ("dns_stateful".equals(modelId)) return 2;
        if ("network_attack".equals(modelId) || "doh_l1".equals(modelId) || "doh_l2".equals(modelId)) return 4;
        if ("android_malware".equals(modelId)) return 5;
        if ("mirai".equals(modelId) || "iot_attack".equals(modelId)) return 6;
        if ("attack_anomaly".equals(modelId) || modelId.startsWith("post_quantum")) return 7;
        return 4;
    }

    private static int modelIndex(ModelCatalog catalog, String modelId) {
        int index = 0;
        for (ModelSpec spec : catalog.all()) {
            if (spec.id.equals(modelId)) {
                return index;
            }
            index++;
        }
        return 0;
    }

    private static int severityId(float probability) {
        if (probability >= 0.85f) return 4;
        if (probability >= 0.65f) return 3;
        if (probability >= 0.40f) return 2;
        if (probability >= 0.20f) return 1;
        return 0;
    }

    private static Map<Integer, String> readActions(JSONObject json) {
        HashMap<Integer, String> values = new HashMap<>();
        for (int i = 0; i < 16; i++) {
            String key = String.valueOf(i);
            if (json.has(key)) {
                values.put(i, json.optString(key));
            }
        }
        return values;
    }

    private static double[] readDoubleArray(org.json.JSONArray array) {
        double[] values = new double[array.length()];
        for (int i = 0; i < array.length(); i++) {
            values[i] = array.optDouble(i);
        }
        return values;
    }

    private static MappedByteBuffer loadModel(Context context, String assetPath) throws Exception {
        try (AssetFileDescriptor descriptor = context.getAssets().openFd(assetPath);
             FileInputStream input = new FileInputStream(descriptor.getFileDescriptor());
             FileChannel channel = input.getChannel()) {
            return channel.map(FileChannel.MapMode.READ_ONLY, descriptor.getStartOffset(), descriptor.getDeclaredLength());
        }
    }

    private static String readAsset(Context context, String path) throws Exception {
        try (InputStream input = context.getAssets().open(path);
             ByteArrayOutputStream output = new ByteArrayOutputStream()) {
            byte[] buffer = new byte[4096];
            int read;
            while ((read = input.read(buffer)) != -1) {
                output.write(buffer, 0, read);
            }
            return output.toString(StandardCharsets.UTF_8.name());
        }
    }

    private static Interpreter loadInterpreter(Context context) throws Exception {
        try {
            return new Interpreter(loadModel(context, MODEL_ASSET), options(true));
        } catch (Throwable acceleratedError) {
            try {
                return new Interpreter(loadModel(context, MODEL_ASSET), options(false));
            } catch (Throwable cpuError) {
                throw new IllegalStateException(
                        "accelerated=" + describe(acceleratedError) + " | cpu=" + describe(cpuError),
                        cpuError
                );
            }
        }
    }

    private static Interpreter.Options options(boolean useXnnpack) {
        Interpreter.Options options = new Interpreter.Options();
        options.setNumThreads(1);
        options.setUseXNNPACK(useXnnpack);
        return options;
    }

    private static String describe(Throwable throwable) {
        StringBuilder builder = new StringBuilder();
        Throwable current = throwable;
        while (current != null) {
            if (builder.length() > 0) {
                builder.append(" <- ");
            }
            builder.append(current.getClass().getSimpleName()).append(": ").append(current.getMessage());
            current = current.getCause();
        }
        return builder.toString();
    }
}
