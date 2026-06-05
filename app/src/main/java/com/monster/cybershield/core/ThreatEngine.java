package com.monster.cybershield.core;

import android.content.Context;
import android.content.Intent;
import android.os.Build;

import com.monster.cybershield.CyberDefenseService;
import com.monster.cybershield.model.ModelCatalog;
import com.monster.cybershield.model.ModelSpec;
import com.monster.cybershield.model.TfliteThreatModel;
import com.monster.cybershield.model.ThreatScore;

public final class ThreatEngine {
    private final Context context;
    private final ModelCatalog catalog;
    private final FeatureSchema dnsSchema;
    private final FeatureSchema dohL1Schema;
    private final FeatureSchema dohL2Schema;
    private final FeatureSchema networkSchema;
    private final FeatureSchema iotSchema;
    private final FeatureSchema pqcSchema;
    private final FeatureSchema socialUrlSchema;

    public ThreatEngine(Context context) {
        this.context = context.getApplicationContext();
        this.catalog = ModelCatalog.load(context);
        this.dnsSchema = FeatureSchema.load(context, "dns_stateful_feature_metadata.json", 27);
        this.dohL1Schema = FeatureSchema.load(context, "doh_l1_feature_metadata.json", 29);
        this.dohL2Schema = FeatureSchema.load(context, "doh_l2_feature_metadata.json", 29);
        this.networkSchema = FeatureSchema.load(context, "network_labels.json", 79);
        this.iotSchema = FeatureSchema.load(context, "iot_labels.json", 71);
        this.pqcSchema = FeatureSchema.load(context, "post_quantum_binary_labels.json", 32);
        this.socialUrlSchema = FeatureSchema.load(context, "social_url_metadata.json", 48);
    }

    public ThreatScore analyze(String modelId, float[] features, String source, String target, String title) {
        ModelSpec spec = catalog.byId(modelId);
        if (spec == null) {
            return null;
        }
        try (TfliteThreatModel model = new TfliteThreatModel(context, spec)) {
            ThreatScore score = model.run(features);
            if (score.actionable || shouldTreatAsActionable(spec, score)) {
                raise(modelId, title, source, target, "high", Math.max(score.risk, score.confidence));
            }
            return score;
        }
    }

    public void analyzeText(String text, String source) {
        String url = FeatureExtractor.firstUrl(text);
        analyze("social_text", FeatureExtractor.socialText(text), source, url.isEmpty() ? "message" : url, "Sosyal muhendislik riski");
        if (!url.isEmpty()) {
            analyzeUrl(url, source);
        }
    }

    public void analyzeUrl(String url, String source) {
        analyze("social_url", socialUrlSchema.url(url, 48), source, url, "Supheli baglanti riski");
        analyze("phishing_html", FeatureExtractor.phishingHtml(url), source, url, "Phishing baglanti riski");
    }

    public void analyzeApk(String packageName) {
        analyze("android_malware", FeatureExtractor.apk(context, packageName), "apk_monitor", packageName, "Android zararli yazilim riski");
    }

    public void analyzePacket(PacketInfo packet) {
        if (packet == null) {
            return;
        }
        if (packet.isDns) {
            analyze("dns_stateful", dnsSchema.packet(packet, 27), "vpn_dns", packet.target(), "DNS saldiri riski");
        }
        if (packet.isDohLike) {
            ThreatScore l1 = analyze("doh_l1", dohL1Schema.packet(packet, 29), "vpn_doh", packet.target(), "DoH trafigi algilandi");
            if (l1 != null && (l1.actionable || l1.confidence >= 0.5f)) {
                analyze("doh_l2", dohL2Schema.packet(packet, 29), "vpn_doh", packet.target(), "Zararli DoH riski");
            }
            analyze("attack_anomaly", pqcSchema.pqc(packet.target(), 32), "vpn_tls", packet.target(), "TLS/session anomali riski");
            analyze("post_quantum", pqcSchema.pqc(packet.target(), 32), "vpn_pqc", packet.target(), "Post-kuantum anomali riski");
        }
    }

    public void analyzeFlow(FlowStats flow) {
        if (flow == null) {
            return;
        }
        String target = flow.target();
        analyze("network_attack", networkSchema.flow(flow, 79), "vpn_flow", target, "Ag saldirisi riski");
        analyze("iot_attack", iotSchema.flow(flow, 71), "vpn_iot", target, "IoT/IIoT saldirisi riski");
        if (flow.dohPackets > 0 || flow.key.destinationPort == 443 || flow.key.sourcePort == 443) {
            analyze("attack_anomaly", pqcSchema.pqc(target, 32), "vpn_tls", target, "TLS/session anomali riski");
            analyze("post_quantum", pqcSchema.pqc(target, 32), "vpn_pqc", target, "Post-kuantum anomali riski");
        }
    }

    private void raise(String modelId, String title, String source, String target, String severity, double probability) {
        Intent intent = new Intent(context, CyberDefenseService.class);
        intent.setAction(CyberDefenseService.ACTION_RAISE_THREAT);
        intent.putExtra(CyberDefenseService.EXTRA_MODEL_ID, modelId);
        intent.putExtra(CyberDefenseService.EXTRA_TITLE, title);
        intent.putExtra(CyberDefenseService.EXTRA_SOURCE, source);
        intent.putExtra(CyberDefenseService.EXTRA_TARGET, target);
        intent.putExtra(CyberDefenseService.EXTRA_SEVERITY, severity);
        intent.putExtra(CyberDefenseService.EXTRA_PROBABILITY, probability);
        if (Build.VERSION.SDK_INT >= 26) {
            context.startForegroundService(intent);
        } else {
            context.startService(intent);
        }
    }

    private static boolean shouldTreatAsActionable(ModelSpec spec, ThreatScore score) {
        if (spec.threshold <= 0.0) {
            return false;
        }
        return score.risk == 0f && score.confidence >= spec.threshold;
    }
}
