package com.monster.cybershield.core;

import android.content.Context;
import android.content.Intent;
import android.os.Build;

import com.monster.cybershield.CyberDefenseService;
import com.monster.cybershield.model.ModelCatalog;
import com.monster.cybershield.model.ModelSpec;
import com.monster.cybershield.model.PolicyDecision;
import com.monster.cybershield.model.PolicyInterventionModel;
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
    private final ModelCalibrationStore calibrationStore;
    private final PolicyInterventionModel policyModel;

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
        this.calibrationStore = new ModelCalibrationStore(context);
        PolicyInterventionModel loadedPolicy;
        try {
            loadedPolicy = new PolicyInterventionModel(context);
        } catch (Throwable ignored) {
            loadedPolicy = null;
        }
        this.policyModel = loadedPolicy;
    }

    public ThreatScore analyze(String modelId, float[] features, String source, String target, String title) {
        ModelSpec spec = catalog.byId(modelId);
        if (spec == null) {
            return null;
        }
        try (TfliteThreatModel model = new TfliteThreatModel(context, spec)) {
            ThreatScore score = model.run(features);
            if (isActionable(spec, score)) {
                float probability = Math.max(score.risk, score.confidence);
                PolicyDecision decision = decide(spec, score, source);
                raise(modelId, title, source, target, severity(probability), probability, decision.action);
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
        analyze("stealth_phisher_2025", FeatureExtractor.stealthPhisher2025(url), source, url, "Stealth phishing riski");
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

    private PolicyDecision decide(ModelSpec spec, ThreatScore score, String source) {
        if (policyModel != null) {
            try {
                return policyModel.recommend(catalog, spec, score, source, calibrationStore.threshold(spec.id, spec.threshold));
            } catch (Throwable ignored) {
            }
        }
        float probability = Math.max(score.risk, score.confidence);
        if (probability >= 0.80f) {
            return new PolicyDecision("block_flow", 1.0f);
        }
        if (probability >= 0.55f) {
            return new PolicyDecision("temporary_block", 1.0f);
        }
        return new PolicyDecision("warn", 1.0f);
    }

    private void raise(String modelId, String title, String source, String target, String severity, double probability, String recommendedAction) {
        Intent intent = new Intent(context, CyberDefenseService.class);
        intent.setAction(CyberDefenseService.ACTION_RAISE_THREAT);
        intent.putExtra(CyberDefenseService.EXTRA_MODEL_ID, modelId);
        intent.putExtra(CyberDefenseService.EXTRA_TITLE, title);
        intent.putExtra(CyberDefenseService.EXTRA_SOURCE, source);
        intent.putExtra(CyberDefenseService.EXTRA_TARGET, target);
        intent.putExtra(CyberDefenseService.EXTRA_SEVERITY, severity);
        intent.putExtra(CyberDefenseService.EXTRA_PROBABILITY, probability);
        intent.putExtra(CyberDefenseService.EXTRA_RECOMMENDED_ACTION, recommendedAction);
        if (Build.VERSION.SDK_INT >= 26) {
            context.startForegroundService(intent);
        } else {
            context.startService(intent);
        }
    }

    private boolean isActionable(ModelSpec spec, ThreatScore score) {
        double threshold = calibrationStore.threshold(spec.id, spec.threshold);
        if (threshold <= 0.0) {
            return false;
        }
        float probability = Math.max(score.risk, score.confidence);
        return score.actionable || probability >= threshold;
    }

    private static String severity(float probability) {
        if (probability >= 0.85f) {
            return "critical";
        }
        if (probability >= 0.65f) {
            return "high";
        }
        if (probability >= 0.40f) {
            return "medium";
        }
        return "low";
    }
}
