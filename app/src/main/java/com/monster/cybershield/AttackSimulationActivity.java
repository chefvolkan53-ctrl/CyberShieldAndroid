package com.monster.cybershield;

import android.app.Activity;
import android.content.Intent;
import android.graphics.Color;
import android.os.Bundle;
import android.util.Log;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

import org.json.JSONArray;
import org.json.JSONObject;

public class AttackSimulationActivity extends Activity {
    private static final String TAG = "CyberShieldAttackSim";

    private static final Object[][] SCENARIOS = new Object[][]{
            {"android_malware", "Android zararlı uygulama simülasyonu", "apk_monitor", "com.test.fakebanker", 0.97},
            {"mirai", "Mirai botnet davranışı simülasyonu", "iot_monitor", "192.0.2.10", 0.96},
            {"network_attack", "Ağ saldırısı simülasyonu", "vpn_flow", "198.51.100.44:1883", 0.94},
            {"dns_stateful", "DNS tünelleme/saldırı simülasyonu", "dns_guard", "malicious-dns.test", 0.91},
            {"doh_l1", "DoH trafiği simülasyonu", "doh_l1", "doh-provider.test", 0.88},
            {"doh_l2", "Zararlı DoH simülasyonu", "doh_l2", "exfil-doh.test", 0.99},
            {"social_text", "Sosyal mühendislik metin simülasyonu", "sms_email_guard", "urgent-password-reset.test", 0.95},
            {"social_url", "Sosyal mühendislik URL simülasyonu", "link_guard", "secure-login-verify.test", 0.93},
            {"phishing_html", "HTML phishing simülasyonu", "browser_guard", "fake-bank-login.test", 0.92},
            {"iot_attack", "IoT/IIoT saldırı simülasyonu", "iot_guard", "iot-camera-01.test", 0.96},
            {"attack_anomaly", "TLS/session anomali simülasyonu", "tls_guard", "tls-anomaly.test", 0.87},
            {"post_quantum", "Post-kuantum anomali simülasyonu", "pqc_guard", "pqc-handshake.test", 0.90},
            {"post_quantum_taxonomy", "Post-kuantum taxonomy açıklama simülasyonu", "pqc_explain", "pqc-taxonomy.test", 0.82},
            {"post_quantum_subtype", "Post-kuantum subtype açıklama simülasyonu", "pqc_explain", "pqc-subtype.test", 0.81}
    };

    @Override
    protected void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        render();
        new Thread(new Runnable() {
            @Override
            public void run() {
                JSONObject result = runSimulation();
                Log.i(TAG, "CYBERSHIELD_ATTACK_SIM_SUMMARY " + result);
                getSharedPreferences("attack_sim", MODE_PRIVATE).edit().putString("last_result", result.toString()).apply();
            }
        }, "cybershield-attack-sim").start();
    }

    private JSONObject runSimulation() {
        JSONArray array = new JSONArray();
        for (Object[] scenario : SCENARIOS) {
            Intent intent = new Intent(this, CyberDefenseService.class);
            intent.setAction(CyberDefenseService.ACTION_RAISE_THREAT);
            intent.putExtra(CyberDefenseService.EXTRA_MODEL_ID, (String) scenario[0]);
            intent.putExtra(CyberDefenseService.EXTRA_TITLE, (String) scenario[1]);
            intent.putExtra(CyberDefenseService.EXTRA_SOURCE, (String) scenario[2]);
            intent.putExtra(CyberDefenseService.EXTRA_TARGET, (String) scenario[3]);
            intent.putExtra(CyberDefenseService.EXTRA_SEVERITY, "high");
            intent.putExtra(CyberDefenseService.EXTRA_PROBABILITY, (Double) scenario[4]);
            startService(intent);

            JSONObject item = new JSONObject();
            try {
                item.put("modelId", scenario[0]);
                item.put("title", scenario[1]);
                item.put("target", scenario[3]);
                item.put("probability", scenario[4]);
                item.put("status", "NOTIFICATION_REQUESTED");
            } catch (Exception ignored) {
            }
            array.put(item);

            try {
                Thread.sleep(120L);
            } catch (InterruptedException ignored) {
            }
        }

        JSONObject root = new JSONObject();
        try {
            root.put("scenarioCount", SCENARIOS.length);
            root.put("mode", "safe_synthetic_no_real_attack");
            root.put("scenarios", array);
            root.put("timestamp", System.currentTimeMillis());
        } catch (Exception ignored) {
        }
        return root;
    }

    private void render() {
        ScrollView scroll = new ScrollView(this);
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(dp(18), dp(18), dp(18), dp(18));
        root.setBackgroundColor(Color.rgb(16, 20, 24));
        scroll.addView(root);
        root.addView(text("CyberShield Saldırı Simülasyonu", 24, Color.WHITE, true));
        root.addView(text("Gerçek saldırı yapılmıyor. Her model için güvenli sentetik olay üretilecek ve müdahale bildirimi tetiklenecek.", 14, Color.rgb(169, 182, 194), false));
        for (Object[] scenario : SCENARIOS) {
            root.addView(text("• " + scenario[1] + " -> " + scenario[3], 13, Color.rgb(245, 247, 250), false));
        }
        setContentView(scroll);
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
}
