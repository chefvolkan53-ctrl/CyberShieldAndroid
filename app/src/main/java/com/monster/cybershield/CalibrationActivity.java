package com.monster.cybershield;

import android.app.Activity;
import android.os.Bundle;
import android.widget.TextView;

import com.monster.cybershield.core.ModelCalibrationStore;

public class CalibrationActivity extends Activity {
    @Override
    protected void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        String modelId = getIntent().getStringExtra("model_id");
        double threshold = getIntent().getDoubleExtra("threshold", -1.0);
        boolean hasOutcome = getIntent().hasExtra("expected_malicious") && getIntent().hasExtra("predicted_malicious");
        ModelCalibrationStore store = new ModelCalibrationStore(this);
        StringBuilder result = new StringBuilder();
        if (modelId != null && !modelId.trim().isEmpty()) {
            if (threshold > 0.0) {
                store.setThreshold(modelId, threshold);
                result.append("Threshold updated: ").append(modelId).append(" -> ").append(threshold).append('\n');
            }
            if (hasOutcome) {
                boolean expected = getIntent().getBooleanExtra("expected_malicious", false);
                boolean predicted = getIntent().getBooleanExtra("predicted_malicious", false);
                store.recordOutcome(modelId, expected, predicted);
                result.append("Outcome recorded: ").append(modelId).append('\n');
            }
            result.append("Calibration: ").append(store.summary(modelId));
        } else {
            result.append("Missing model_id extra.");
        }
        TextView text = new TextView(this);
        text.setText(result.toString());
        text.setTextSize(16);
        text.setPadding(24, 24, 24, 24);
        setContentView(text);
    }
}
