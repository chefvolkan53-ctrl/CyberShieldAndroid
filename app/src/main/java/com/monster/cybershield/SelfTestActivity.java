package com.monster.cybershield;

import android.app.Activity;
import android.content.Intent;
import android.graphics.Color;
import android.os.Bundle;
import android.util.Log;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

import com.monster.cybershield.core.BlocklistStore;
import com.monster.cybershield.core.InterventionActions;
import com.monster.cybershield.core.ThreatEvent;
import com.monster.cybershield.core.ThreatStore;
import com.monster.cybershield.model.ModelCatalog;
import com.monster.cybershield.model.ModelSpec;
import com.monster.cybershield.model.PolicyDecision;
import com.monster.cybershield.model.PolicyInterventionModel;
import com.monster.cybershield.model.TfliteThreatModel;
import com.monster.cybershield.model.ThreatScore;

import org.json.JSONArray;
import org.json.JSONObject;

import java.util.Locale;

public class SelfTestActivity extends Activity {
    private static final String TAG = "CyberShieldSelfTest";
    private LinearLayout root;

    @Override
    protected void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        renderShell();
        new Thread(new Runnable() {
            @Override
            public void run() {
                JSONObject result = runSelfTest();
                Log.i(TAG, "CYBERSHIELD_SELFTEST_SUMMARY " + result);
                getSharedPreferences("self_test", MODE_PRIVATE).edit().putString("last_result", result.toString()).apply();
                runOnUiThread(new Runnable() {
                    @Override
                    public void run() {
                        renderResult(result);
                    }
                });
            }
        }, "cybershield-self-test").start();
    }

    private JSONObject runSelfTest() {
        JSONObject rootJson = new JSONObject();
        JSONArray modelResults = new JSONArray();
        int ok = 0;
        int failed = 0;
        try {
            ModelCatalog catalog = ModelCatalog.load(this);
            for (ModelSpec spec : catalog.all()) {
                JSONObject item = new JSONObject();
                item.put("id", spec.id);
                item.put("title", spec.title);
                item.put("inputSize", spec.inputSize);
                long start = System.nanoTime();
                try (TfliteThreatModel model = new TfliteThreatModel(this, spec)) {
                    float[] features = new float[spec.inputSize];
                    ThreatScore score = model.run(features);
                    long elapsedMs = (System.nanoTime() - start) / 1_000_000L;
                    item.put("status", "OK");
                    item.put("elapsedMs", elapsedMs);
                    item.put("accelerated", model.isAccelerated());
                    item.put("risk", score.risk);
                    item.put("confidence", score.confidence);
                    item.put("threshold", score.threshold);
                    ok++;
                } catch (Throwable t) {
                    item.put("status", "FAIL");
                    item.put("error", t.getClass().getSimpleName() + ": " + t.getMessage());
                    failed++;
                }
                modelResults.put(item);
            }

            JSONObject policyItem = new JSONObject();
            policyItem.put("id", "cybershield_policy_intervention");
            policyItem.put("title", "CyberShield Intervention Policy");
            long policyStart = System.nanoTime();
            try (PolicyInterventionModel policy = new PolicyInterventionModel(this)) {
                ModelSpec spec = catalog.byId("network_attack");
                ThreatScore synthetic = new ThreatScore("network_attack", "Network Attack", 0.82f, 0.82f, true, 0.72);
                PolicyDecision decision = policy.recommend(catalog, spec, synthetic, "vpn_flow");
                policyItem.put("status", "OK");
                policyItem.put("elapsedMs", (System.nanoTime() - policyStart) / 1_000_000L);
                policyItem.put("risk", decision.confidence);
                policyItem.put("action", decision.action);
                ok++;
            } catch (Throwable t) {
                policyItem.put("status", "FAIL");
                policyItem.put("error", describe(t));
                failed++;
            }
            modelResults.put(policyItem);

            ThreatStore store = new ThreatStore(this);
            ThreatEvent event = store.add("self_test", "Self-test threat", "diagnostic", "selftest.invalid", "medium", 0.91);
            InterventionActions.block(this, event);
            new BlocklistStore(this).block("selftest-block.invalid");

            Intent start = new Intent(this, CyberDefenseService.class);
            start.setAction(CyberDefenseService.ACTION_START);
            startService(start);

            Intent alert = new Intent(this, CyberDefenseService.class);
            alert.setAction(CyberDefenseService.ACTION_RAISE_THREAT);
            alert.putExtra(CyberDefenseService.EXTRA_MODEL_ID, "self_test");
            alert.putExtra(CyberDefenseService.EXTRA_TITLE, "Self-test notification");
            alert.putExtra(CyberDefenseService.EXTRA_SOURCE, "diagnostic");
            alert.putExtra(CyberDefenseService.EXTRA_TARGET, "selftest-notification.invalid");
            alert.putExtra(CyberDefenseService.EXTRA_SEVERITY, "medium");
            alert.putExtra(CyberDefenseService.EXTRA_PROBABILITY, 0.93);
            startService(alert);

            rootJson.put("modelsOk", ok);
            rootJson.put("modelsFailed", failed);
            rootJson.put("storeStatus", "OK");
            rootJson.put("serviceStatus", "START_REQUESTED");
        } catch (Throwable t) {
            try {
                rootJson.put("fatal", t.getClass().getSimpleName() + ": " + t.getMessage());
            } catch (Exception ignored) {
            }
        }
        try {
            rootJson.put("models", modelResults);
            rootJson.put("timestamp", System.currentTimeMillis());
        } catch (Exception ignored) {
        }
        return rootJson;
    }

    private void renderShell() {
        ScrollView scroll = new ScrollView(this);
        root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(dp(18), dp(18), dp(18), dp(18));
        root.setBackgroundColor(Color.rgb(16, 20, 24));
        scroll.addView(root);
        root.addView(text("CyberShield Self Test", 24, Color.WHITE, true));
        root.addView(text("Modeller yukleniyor ve tek tek inference deneniyor...", 14, Color.rgb(169, 182, 194), false));
        setContentView(scroll);
    }

    private void renderResult(JSONObject result) {
        root.removeAllViews();
        root.addView(text("CyberShield Self Test", 24, Color.WHITE, true));
        root.addView(text("OK: " + result.optInt("modelsOk") + " | FAIL: " + result.optInt("modelsFailed"), 18, result.optInt("modelsFailed") == 0 ? Color.rgb(32, 201, 151) : Color.rgb(239, 68, 68), true));
        JSONArray models = result.optJSONArray("models");
        if (models != null) {
            for (int i = 0; i < models.length(); i++) {
                JSONObject item = models.optJSONObject(i);
                if (item == null) {
                    continue;
                }
                String line = item.optString("id") + " | " + item.optString("status")
                        + " | " + item.optLong("elapsedMs") + " ms"
                        + " | risk " + String.format(Locale.US, "%.4f", item.optDouble("risk"));
                if (item.has("error")) {
                    line += "\n" + item.optString("error");
                }
                root.addView(text(line, 13, Color.rgb(245, 247, 250), "OK".equals(item.optString("status"))));
            }
        }
    }

    private TextView text(String value, int sp, int color, boolean bold) {
        TextView text = new TextView(this);
        text.setText(value);
        text.setTextColor(color);
        text.setTextSize(sp);
        text.setPadding(0, dp(5), 0, dp(5));
        if (bold) {
            text.setTypeface(android.graphics.Typeface.DEFAULT_BOLD);
        }
        return text;
    }

    private int dp(int value) {
        return Math.round(value * getResources().getDisplayMetrics().density);
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
