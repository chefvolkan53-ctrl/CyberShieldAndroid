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
    private final FeatureSchema androidMalwareFlowSchema;
    private final FeatureSchema iotSchema;
    private final FeatureSchema honeypotThreatIntelSchema;
    private final FeatureSchema pqcSchema;
    private final FeatureSchema socialUrlSchema;
    private final ModelCalibrationStore calibrationStore;
    private final PolicyInterventionModel policyModel;
    private final AlertNoisePolicy alertNoisePolicy;

    public ThreatEngine(Context context) {
        this.context = context.getApplicationContext();
        this.catalog = ModelCatalog.load(context);
        this.dnsSchema = FeatureSchema.load(context, "dns_stateful_feature_metadata.json", 27);
        this.dohL1Schema = FeatureSchema.load(context, "doh_l1_feature_metadata.json", 29);
        this.dohL2Schema = FeatureSchema.load(context, "doh_l2_feature_metadata.json", 29);
        this.networkSchema = FeatureSchema.load(context, "network_labels.json", 79);
        this.androidMalwareFlowSchema = FeatureSchema.load(context, "android_malware_flow_feature_metadata.json", 80);
        this.iotSchema = FeatureSchema.load(context, "iot_labels.json", 71);
        this.honeypotThreatIntelSchema = FeatureSchema.load(context, "honeypot_threat_intel_feature_metadata.json", 32);
        this.pqcSchema = FeatureSchema.load(context, "post_quantum_binary_labels.json", 32);
        this.socialUrlSchema = FeatureSchema.load(context, "social_url_metadata.json", 48);
        this.calibrationStore = new ModelCalibrationStore(context);
        this.alertNoisePolicy = new AlertNoisePolicy(context);
        PolicyInterventionModel loadedPolicy;
        try {
            loadedPolicy = new PolicyInterventionModel(context);
        } catch (Throwable ignored) {
            loadedPolicy = null;
        }
        this.policyModel = loadedPolicy;
    }

    public ThreatScore analyze(String modelId, float[] features, String source, String target, String title) {
        if (alertNoisePolicy.shouldSuppressModelEvent(modelId, source, target)) {
            return null;
        }
        return analyzeInternal(modelId, features, source, target, title, true);
    }

    private ThreatScore scoreOnly(String modelId, float[] features) {
        return analyzeInternal(modelId, features, "", "", "", false);
    }

    private ThreatScore analyzeInternal(String modelId, float[] features, String source, String target, String title, boolean raiseActionable) {
        ModelSpec spec = catalog.byId(modelId);
        if (spec == null) {
            return null;
        }
        try (TfliteThreatModel model = new TfliteThreatModel(context, spec)) {
            ThreatScore score = model.run(features);
            if (raiseActionable && isActionable(spec, score)) {
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
        if (alertNoisePolicy.shouldRaiseHighRiskLink(url)) {
            raise("social_url", "Supheli baglanti riski", source, url, "high", 0.88, "block_domain");
        }
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
            if (alertNoisePolicy.isSuspiciousDnsQuery(packet.target())) {
                analyze("dns_stateful", dnsSchema.packet(packet, 27), "vpn_dns", packet.target(), "DNS saldiri riski");
            } else {
                scoreOnly("dns_stateful", dnsSchema.packet(packet, 27));
            }
        }
        if (packet.isDohLike && alertNoisePolicy.isLikelyEncryptedDnsTarget(packet.target())) {
            ThreatScore l1 = scoreOnly("doh_l1", dohL1Schema.packet(packet, 29));
            if (l1 != null && (l1.actionable || l1.confidence >= 0.5f)
                    && !alertNoisePolicy.isTrustedNetworkTarget(packet.target())) {
                analyze("doh_l2", dohL2Schema.packet(packet, 29), "vpn_doh", packet.target(), "Zararli DoH riski");
            }
        }
    }

    public void analyzeFlow(FlowStats flow) {
        if (flow == null) {
            return;
        }
        String target = flow.target();
        if (alertNoisePolicy.shouldScoreOnlyNetworkFlow(flow)) {
            scoreOnly("network_attack", networkSchema.flow(flow, 79));
        } else {
            analyze("network_attack", networkSchema.flow(flow, 79), "vpn_flow", target, "Ag saldirisi riski");
        }
        scoreOnly("honeypot_threat_intel", honeypotThreatIntelSchema.flow(flow, 32));
        scoreOnly("android_malware_flow", androidMalwareFlowSchema.flow(flow, 80));
        scoreOnly("iot_attack", iotSchema.flow(flow, 71));
        if (flow.dohPackets > 0 && alertNoisePolicy.isLikelyEncryptedDnsTarget(target) && !alertNoisePolicy.isTrustedNetworkTarget(target)) {
            scoreOnly("attack_anomaly", pqcSchema.pqc(target, 32));
            scoreOnly("post_quantum", pqcSchema.pqc(target, 32));
        }
    }

    private PolicyDecision decide(ModelSpec spec, ThreatScore score, String source) {
        if (policyModel != null) {
            try {
                PolicyDecision decision = policyModel.recommend(catalog, spec, score, source, calibrationStore.threshold(spec.id, spec.threshold));
                return hardenDecision(spec, score, decision);
            } catch (Throwable ignored) {
            }
        }
        PolicyDecision hardened = hardenDecision(spec, score, null);
        if (hardened != null) {
            return hardened;
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

    private PolicyDecision hardenDecision(ModelSpec spec, ThreatScore score, PolicyDecision decision) {
        float probability = Math.max(score.risk, score.confidence);
        String current = decision == null ? "" : decision.action;
        if ("android_malware".equals(spec.id) && probability >= 0.70f) {
            return new PolicyDecision("uninstall_prompt", 1.0f);
        }
        if (("social_url".equals(spec.id) || "phishing_html".equals(spec.id) || "stealth_phisher_2025".equals(spec.id))
                && probability >= 0.60f) {
            return new PolicyDecision("block_domain", 1.0f);
        }
        if ("social_text".equals(spec.id) && probability >= 0.70f) {
            return new PolicyDecision("quarantine", 1.0f);
        }
        if ("dns_stateful".equals(spec.id) && probability >= 0.70f) {
            return new PolicyDecision("block_domain", 1.0f);
        }
        if ("android_malware_flow".equals(spec.id) && probability >= 0.78f) {
            return new PolicyDecision("block_flow", 1.0f);
        }
        if ("honeypot_threat_intel".equals(spec.id) && probability >= 0.90f) {
            return new PolicyDecision("explain_only", 1.0f);
        }
        if (("network_attack".equals(spec.id) || "iot_attack".equals(spec.id) || "doh_l2".equals(spec.id)
                || "post_quantum".equals(spec.id)) && probability >= 0.75f) {
            return new PolicyDecision("block_flow", 1.0f);
        }
        if (decision != null && current != null && !current.trim().isEmpty()) {
            return decision;
        }
        return null;
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
        if ("android_malware_flow".equals(spec.id) || "iot_attack".equals(spec.id)) {
            threshold = Math.max(threshold, 0.995);
            return probability >= threshold;
        } else if ("attack_anomaly".equals(spec.id) || "post_quantum".equals(spec.id)) {
            threshold = Math.max(threshold, 0.90);
            return probability >= threshold;
        } else if ("doh_l1".equals(spec.id)) {
            return false;
        } else if ("social_text".equals(spec.id)) {
            threshold = Math.max(threshold, 0.55);
            return probability >= threshold;
        } else if ("social_url".equals(spec.id) || "phishing_html".equals(spec.id) || "stealth_phisher_2025".equals(spec.id)) {
            threshold = Math.max(threshold, 0.60);
            return probability >= threshold;
        }
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
