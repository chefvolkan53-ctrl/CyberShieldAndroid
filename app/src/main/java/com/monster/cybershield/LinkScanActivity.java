package com.monster.cybershield;

import android.app.Activity;
import android.content.Intent;
import android.graphics.Color;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

import com.monster.cybershield.core.FeatureExtractor;
import com.monster.cybershield.core.AlertNoisePolicy;
import com.monster.cybershield.core.ThreatEngine;

public class LinkScanActivity extends Activity {
    @Override
    protected void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        String input = extractInput(getIntent());
        render(input);
        if (new AlertNoisePolicy(this).shouldRaiseHighRiskLink(input)) {
            raiseHighRiskLink(input);
        }
        new Thread(() -> {
            if (input.startsWith("http://") || input.startsWith("https://") || input.contains(".")) {
                new ThreatEngine(this).analyzeUrl(input, "link_intent");
            } else {
                new ThreatEngine(this).analyzeText(input, "shared_text");
            }
        }, "link-threat-analysis").start();
    }

    private String extractInput(Intent intent) {
        if (intent == null) {
            return "";
        }
        Uri data = intent.getData();
        if (data != null) {
            return data.toString();
        }
        CharSequence extra = intent.getCharSequenceExtra(Intent.EXTRA_TEXT);
        if (extra != null) {
            String text = extra.toString();
            String url = FeatureExtractor.firstUrl(text);
            return url.isEmpty() ? text : url;
        }
        return "";
    }

    private void raiseHighRiskLink(String target) {
        Intent intent = new Intent(this, CyberDefenseService.class);
        intent.setAction(CyberDefenseService.ACTION_RAISE_THREAT);
        intent.putExtra(CyberDefenseService.EXTRA_MODEL_ID, "social_url");
        intent.putExtra(CyberDefenseService.EXTRA_TITLE, "Supheli baglanti riski");
        intent.putExtra(CyberDefenseService.EXTRA_SOURCE, "link_intent");
        intent.putExtra(CyberDefenseService.EXTRA_TARGET, target);
        intent.putExtra(CyberDefenseService.EXTRA_SEVERITY, "high");
        intent.putExtra(CyberDefenseService.EXTRA_PROBABILITY, 0.88);
        intent.putExtra(CyberDefenseService.EXTRA_RECOMMENDED_ACTION, "block_domain");
        if (Build.VERSION.SDK_INT >= 26) {
            startForegroundService(intent);
        } else {
            startService(intent);
        }
    }

    private void render(String input) {
        ScrollView scroll = new ScrollView(this);
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(dp(18), dp(18), dp(18), dp(18));
        root.setBackgroundColor(Color.rgb(16, 20, 24));
        scroll.addView(root);
        root.addView(text("CyberShield link taraması", 24, Color.WHITE, true));
        root.addView(text(input.isEmpty() ? "Taranacak bağlantı/metin bulunamadı." : input, 14, Color.rgb(245, 247, 250), false));
        root.addView(text("Risk varsa bildirim ve müdahale ekranı otomatik açılacak.", 14, Color.rgb(169, 182, 194), false));
        setContentView(scroll);
    }

    private TextView text(String value, int sp, int color, boolean bold) {
        TextView view = new TextView(this);
        view.setText(value);
        view.setTextColor(color);
        view.setTextSize(sp);
        view.setPadding(0, dp(6), 0, dp(6));
        if (bold) {
            view.setTypeface(android.graphics.Typeface.DEFAULT_BOLD);
        }
        return view;
    }

    private int dp(int value) {
        return Math.round(value * getResources().getDisplayMetrics().density);
    }
}
