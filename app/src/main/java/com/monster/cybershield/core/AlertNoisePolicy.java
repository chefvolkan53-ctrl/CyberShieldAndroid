package com.monster.cybershield.core;

import android.content.Context;
import android.net.Uri;

import java.util.Locale;

public final class AlertNoisePolicy {
    private static final long DEFAULT_DEDUP_WINDOW_MS = 5 * 60 * 1000L;

    private final ProtectionPolicyStore protectionPolicy;

    public AlertNoisePolicy(Context context) {
        this.protectionPolicy = new ProtectionPolicyStore(context);
    }

    public long dedupWindowMs() {
        return DEFAULT_DEDUP_WINDOW_MS;
    }

    public boolean shouldSuppressModelEvent(String modelId, String source, String target) {
        String id = safe(modelId);
        String src = safe(source);
        String host = normalizedHost(target);
        int port = normalizedPort(target);

        if (host.isEmpty()) {
            return false;
        }
        if ("doh_l1".equals(id)) {
            return true;
        }
        if ("android_malware_flow".equals(id)
                || "iot_attack".equals(id)
                || "attack_anomaly".equals(id)
                || "post_quantum".equals(id)) {
            return true;
        }
        if (isVpnInternalHost(host)) {
            return true;
        }
        if (isTrustedResolver(host, port) && isVpnSource(src)) {
            return true;
        }
        if (isTrustedGoogleBackgroundTarget(host, port) && isVpnSource(src)) {
            return true;
        }
        if (isTrustedPlatformService(host, port) && isVpnSource(src)) {
            return true;
        }
        if (isLinkPhishingModel(id) && isLinkSource(src) && isBenignTrustedLinkTarget(target, host, port)) {
            return true;
        }
        if ("dns_stateful".equals(id) && "vpn_dns_leak_guard".equals(src) && isPrivateLanHost(host) && port == 53) {
            return true;
        }
        if ("network_attack".equals(id) && isVpnSource(src) && isRoutineConsumerNetworkTarget(host, port)) {
            return true;
        }
        if (isSupportOnlyModel(id) && isRoutineInfrastructure(host, port)) {
            return true;
        }
        return false;
    }

    public boolean isTrustedNetworkTarget(String target) {
        String host = normalizedHost(target);
        int port = normalizedPort(target);
        return isVpnInternalHost(host)
                || isTrustedResolver(host, port)
                || isTrustedGoogleBackgroundTarget(host, port)
                || isTrustedMessagingOrCdnTarget(host, port)
                || isTrustedPlatformService(host, port)
                || isRoutineInfrastructure(host, port);
    }

    public boolean shouldScoreOnlyNetworkFlow(FlowStats flow) {
        if (flow == null) {
            return true;
        }
        String host = normalizedHost(flow.target());
        int port = normalizedPort(flow.target());
        if (host.isEmpty()) {
            return true;
        }
        if (isTrustedNetworkTarget(flow.target()) && !isAbusiveFlow(flow)) {
            return true;
        }
        if (isRoutineConsumerNetworkTarget(host, port) && !isAbusiveFlow(flow)) {
            return true;
        }
        if (isStandardWebOrPushPort(port) && !isKnownRiskServicePort(port) && !hasTransportAttackSignature(flow)) {
            return true;
        }
        if (isPrivateLanHost(host) && isEphemeralOrConsumerPort(port) && !isAbusiveFlow(flow)) {
            return true;
        }
        if (port >= 1024 && !isKnownRiskServicePort(port) && !hasTransportAttackSignature(flow)) {
            return true;
        }
        if (isEphemeralOrConsumerPort(port) && flow.packetCount < 32 && flow.synPackets < 8 && flow.rstPackets < 8) {
            return true;
        }
        return false;
    }

    public boolean isLikelyEncryptedDnsTarget(String target) {
        String host = normalizedHost(target);
        int port = normalizedPort(target);
        return port == 853 || isKnownDohHost(host);
    }

    public boolean isSuspiciousDnsQuery(String query) {
        String host = normalizedHost(query);
        if (host.isEmpty()) {
            return false;
        }
        if (isTrustedNetworkTarget(host)) {
            return false;
        }
        int length = host.length();
        String[] labels = host.split("\\.");
        int maxLabel = 0;
        for (String label : labels) {
            maxLabel = Math.max(maxLabel, label.length());
            if (label.startsWith("xn--")) {
                return true;
            }
            if (label.length() >= 18 && looksRandom(label)) {
                return true;
            }
        }
        if (length >= 72) {
            return true;
        }
        if (labels.length >= 5 && length >= 45) {
            return true;
        }
        if (maxLabel >= 32) {
            return true;
        }
        if (length >= 32 && entropy(host) >= 4.25f) {
            return true;
        }
        if (length >= 25 && digitRatio(host) >= 0.25f) {
            return true;
        }
        return hasRiskyTld(host) && (length >= 24 || digitRatio(host) > 0.12f || host.contains("-"));
    }

    public boolean shouldRaiseHighRiskLink(String target) {
        String host = normalizedHost(target);
        int port = normalizedPort(target);
        if (host.isEmpty() || isBenignTrustedLinkTarget(target, host, port)) {
            return false;
        }
        boolean suspiciousContext = hasSuspiciousUrlContext(target);
        if (isIpLiteral(host) && suspiciousContext) {
            return true;
        }
        String value = safe(target).toLowerCase(Locale.US);
        if (value.startsWith("http://") && suspiciousContext) {
            return true;
        }
        if (isRiskyPhishingInfrastructure(host) && suspiciousContext) {
            return true;
        }
        if (hasRiskyTld(host) && (suspiciousContext || host.length() >= 24 || digitRatio(host) > 0.12f)) {
            return true;
        }
        String[] labels = host.split("\\.");
        for (String label : labels) {
            if (label.length() >= 20 && looksRandom(label)) {
                return true;
            }
        }
        return host.contains("login")
                || host.contains("verify")
                || host.contains("secure")
                || host.contains("account")
                || host.contains("wallet")
                || host.contains("bank");
    }

    public static int notificationIdFor(String target) {
        String key = normalizedTarget(target);
        return key.isEmpty() ? 1000 : 1000 + Math.abs(key.hashCode());
    }

    public static String normalizedTarget(String target) {
        String host = normalizedHost(target);
        int port = normalizedPort(target);
        if (host.isEmpty()) {
            return "";
        }
        return port > 0 ? host + ":" + port : host;
    }

    public static String normalizedHost(String target) {
        String value = safe(target).toLowerCase(Locale.US);
        if (value.isEmpty()) {
            return "";
        }
        if (value.startsWith("http://") || value.startsWith("https://")) {
            try {
                String host = Uri.parse(value).getHost();
                return host == null ? "" : trimWww(host.toLowerCase(Locale.US));
            } catch (Exception ignored) {
            }
        }
        int slash = value.indexOf('/');
        if (slash > 0) {
            value = value.substring(0, slash);
        }
        if (value.startsWith("[") && value.contains("]")) {
            return value.substring(1, value.indexOf(']'));
        }
        int colon = value.lastIndexOf(':');
        if (colon > 0 && value.indexOf(':') == colon) {
            String possiblePort = value.substring(colon + 1);
            if (isInteger(possiblePort)) {
                value = value.substring(0, colon);
            }
        }
        return trimWww(value);
    }

    public static int normalizedPort(String target) {
        String value = safe(target).toLowerCase(Locale.US);
        if (value.startsWith("http://") || value.startsWith("https://")) {
            try {
                return Uri.parse(value).getPort();
            } catch (Exception ignored) {
                return -1;
            }
        }
        int slash = value.indexOf('/');
        if (slash > 0) {
            value = value.substring(0, slash);
        }
        int colon = value.lastIndexOf(':');
        if (colon > 0 && value.indexOf(':') == colon) {
            String possiblePort = value.substring(colon + 1);
            if (isInteger(possiblePort)) {
                try {
                    return Integer.parseInt(possiblePort);
                } catch (Exception ignored) {
                }
            }
        }
        return -1;
    }

    private boolean isTrustedResolver(String host, int port) {
        if (host.equals(protectionPolicy.dnsProvider()) || host.equals(protectionPolicy.dnsProviderSecondary())) {
            return port <= 0 || port == 53 || port == 443 || port == 853;
        }
        return protectionPolicy.isAllowedResolver(host) && (port <= 0 || port == 53 || port == 443 || port == 853);
    }

    private static boolean isVpnInternalHost(String host) {
        return host.startsWith("10.88.")
                || "10.88.0.1".equals(host)
                || "10.88.0.2".equals(host);
    }

    private static boolean isTrustedGoogleBackgroundTarget(String host, int port) {
        if ("mtalk.google.com".equals(host) || host.endsWith(".mtalk.google.com")) {
            return true;
        }
        if ((port == 5228 || port == 5229 || port == 5230) && (isGoogleIp(host) || host.endsWith(".google.com"))) {
            return true;
        }
        if ((port == 443 || port <= 0) && isGoogleIp(host)) {
            return true;
        }
        return host.endsWith(".metric.gstatic.com")
                || host.endsWith(".gstatic.com") && host.contains("dnsotls-ds");
    }

    private static boolean isTrustedPlatformService(String host, int port) {
        if (!isStandardPlatformPort(port)) {
            return false;
        }
        return isGooglePlayOrAndroidSystemHost(host)
                || isSamsungSystemHost(host);
    }

    public static boolean isKnownDohHost(String host) {
        String value = safe(host).toLowerCase(Locale.US);
        return value.contains("cloudflare-dns.com")
                || value.contains("dns.google")
                || value.contains("quad9.net")
                || value.contains("nextdns.io")
                || value.contains("dns.adguard")
                || value.contains("doh.")
                || value.contains("dns-query");
    }

    private static boolean isGooglePlayOrAndroidSystemHost(String host) {
        return host.equals("play.google.com")
                || host.equals("play.googleapis.com")
                || host.equals("play-fe.googleapis.com")
                || host.equals("android.clients.google.com")
                || host.equals("android.googleapis.com")
                || host.equals("android.apis.google.com")
                || host.equals("www.googleapis.com")
                || host.equals("oauth2.googleapis.com")
                || host.equals("firebaseinstallations.googleapis.com")
                || host.equals("firebase-settings.crashlytics.com")
                || host.equals("clients1.google.com")
                || host.equals("clients2.google.com")
                || host.equals("clients3.google.com")
                || host.equals("clients4.google.com")
                || host.equals("clients5.google.com")
                || host.equals("clients6.google.com")
                || host.equals("connectivitycheck.gstatic.com")
                || host.equals("www.gstatic.com")
                || host.endsWith(".gvt1.com")
                || host.endsWith(".gvt2.com")
                || host.endsWith(".ggpht.com")
                || host.endsWith(".googleusercontent.com")
                || host.endsWith(".googleapis.com")
                || host.endsWith(".gstatic.com")
                || host.endsWith(".google.com") && (host.contains("play") || host.contains("android") || host.contains("safebrowsing"));
    }

    private static boolean isSamsungSystemHost(String host) {
        return host.equals("galaxy.store")
                || host.equals("www.galaxystore.com")
                || host.equals("galaxystore.samsung.com")
                || host.equals("apps.samsung.com")
                || host.equals("vas.samsungapps.com")
                || host.equals("samsungapps.com")
                || host.equals("account.samsung.com")
                || host.equals("api.samsungcloud.com")
                || host.equals("samsungcloud.com")
                || host.equals("samsungdm.com")
                || host.equals("fota-cloud-dn.ospserver.net")
                || host.endsWith(".galaxystore.com")
                || host.endsWith(".samsungapps.com")
                || host.endsWith(".samsungcloud.com")
                || host.endsWith(".samsungdm.com")
                || host.endsWith(".samsungosp.com")
                || host.endsWith(".ospserver.net")
                || host.endsWith(".samsung.com") && (host.contains("account") || host.contains("galaxy") || host.contains("apps") || host.contains("fota") || host.contains("update"));
    }

    private static boolean isStandardPlatformPort(int port) {
        return port <= 0 || port == 80 || port == 443 || port == 5228 || port == 5229 || port == 5230 || port == 853;
    }

    private static boolean isRoutineInfrastructure(String host, int port) {
        return port == 853
                || port == 5228
                || port == 5229
                || port == 5230
                || port == 5222
                || port == 5223
                || port == 3478
                || port == 3479
                || port == 3480
                || host.endsWith(".gstatic.com")
                || host.endsWith(".googleapis.com")
                || isTrustedMessagingOrCdnTarget(host, port)
                || isTrustedPlatformService(host, port);
    }

    private static boolean isRoutineConsumerNetworkTarget(String host, int port) {
        return isTrustedMessagingOrCdnTarget(host, port)
                || isTrustedGoogleBackgroundTarget(host, port)
                || isStandardWebOrPushPort(port) && (isGoogleIp(host) || isMetaIp(host))
                || isPrivateLanHost(host) && isEphemeralOrConsumerPort(port);
    }

    private static boolean isTrustedMessagingOrCdnTarget(String host, int port) {
        if (!isStandardWebOrPushPort(port) && port != 3478 && port != 3479 && port != 3480) {
            return false;
        }
        return host.equals("g.whatsapp.net")
                || host.endsWith(".whatsapp.net")
                || host.endsWith(".whatsapp.com")
                || host.endsWith(".facebook.com")
                || host.endsWith(".fbcdn.net")
                || host.endsWith(".messenger.com")
                || host.endsWith(".instagram.com")
                || host.endsWith(".cdninstagram.com")
                || isMetaIp(host);
    }

    private static boolean isStandardWebOrPushPort(int port) {
        return port <= 0 || port == 80 || port == 443 || port == 5222 || port == 5223 || port == 5228 || port == 5229 || port == 5230;
    }

    private static boolean isLinkPhishingModel(String modelId) {
        return "social_url".equals(modelId)
                || "phishing_html".equals(modelId)
                || "stealth_phisher_2025".equals(modelId);
    }

    private static boolean isLinkSource(String source) {
        return "link_intent".equals(source)
                || "shared_text".equals(source)
                || "browser_guard".equals(source)
                || "sms_email_guard".equals(source);
    }

    private static boolean isBenignTrustedLinkTarget(String target, String host, int port) {
        if (!(port <= 0 || port == 80 || port == 443)) {
            return false;
        }
        if (!isTrustedRootLinkHost(host) && !isTrustedPlatformService(host, port)) {
            return false;
        }
        return !hasSuspiciousUrlContext(target);
    }

    private static boolean isTrustedRootLinkHost(String host) {
        return "google.com".equals(host)
                || "play.google.com".equals(host)
                || "g.co".equals(host)
                || "youtube.com".equals(host)
                || "youtu.be".equals(host)
                || "samsung.com".equals(host)
                || "galaxy.store".equals(host)
                || "cloudflare.com".equals(host)
                || "cloudflare-dns.com".equals(host)
                || "quad9.net".equals(host)
                || "whatsapp.com".equals(host)
                || "whatsapp.net".equals(host);
    }

    private static boolean isRiskyPhishingInfrastructure(String host) {
        return host.contains("duckdns")
                || host.contains("ddns")
                || host.contains("ipfs")
                || host.endsWith(".workers.dev")
                || host.endsWith(".pages.dev")
                || host.endsWith(".web.app")
                || host.endsWith(".firebaseapp.com")
                || host.endsWith(".github.io")
                || host.endsWith(".netlify.app")
                || host.endsWith(".vercel.app")
                || host.endsWith(".glitch.me")
                || host.endsWith(".repl.co")
                || host.endsWith(".ngrok.io")
                || host.endsWith(".trycloudflare.com")
                || host.equals("bit.ly")
                || host.equals("tinyurl.com")
                || host.equals("t.co")
                || host.equals("goo.gl")
                || host.equals("qrco.de")
                || host.equals("cutt.ly")
                || host.equals("is.gd")
                || host.equals("s.id");
    }

    private static boolean isIpLiteral(String host) {
        String[] parts = host.split("\\.");
        if (parts.length != 4) {
            return false;
        }
        for (String part : parts) {
            if (!isInteger(part)) {
                return false;
            }
            int value = Integer.parseInt(part);
            if (value < 0 || value > 255) {
                return false;
            }
        }
        return true;
    }

    private static boolean hasSuspiciousUrlContext(String target) {
        String value = safe(target).toLowerCase(Locale.US);
        if (value.isEmpty()) {
            return false;
        }
        String pathAndQuery = value;
        if (value.startsWith("http://") || value.startsWith("https://")) {
            try {
                Uri uri = Uri.parse(value);
                pathAndQuery = safe(uri.getPath()) + "?" + safe(uri.getQuery());
            } catch (Exception ignored) {
            }
        }
        return pathAndQuery.contains("login")
                || pathAndQuery.contains("signin")
                || pathAndQuery.contains("verify")
                || pathAndQuery.contains("password")
                || pathAndQuery.contains("passwd")
                || pathAndQuery.contains("wallet")
                || pathAndQuery.contains("bank")
                || pathAndQuery.contains("otp")
                || pathAndQuery.contains("token")
                || pathAndQuery.contains("session")
                || pathAndQuery.contains("forms/")
                || pathAndQuery.contains("/form")
                || pathAndQuery.contains("docs.google.com/forms");
    }

    private static boolean isEphemeralOrConsumerPort(int port) {
        return port <= 0 || port == 80 || port == 443 || port == 853 || port == 3478 || port == 3479 || port == 3480
                || port == 5222 || port == 5223 || port == 5228 || port == 5229 || port == 5230 || port >= 1024;
    }

    private static boolean isAbusiveFlow(FlowStats flow) {
        if (hasTransportAttackSignature(flow)) {
            return true;
        }
        if (flow.packetCount >= 160) {
            return true;
        }
        if (flow.durationMs() >= 1000 && flow.packetCount >= 64 && flow.packetsPerSecond() >= 200f) {
            return true;
        }
        return false;
    }

    private static boolean hasTransportAttackSignature(FlowStats flow) {
        float synRatio = flow.tcpPackets == 0 ? 0f : flow.synPackets / (float) flow.tcpPackets;
        float ackRatio = flow.tcpPackets == 0 ? 0f : flow.ackPackets / (float) flow.tcpPackets;
        if (flow.synPackets >= 20 && synRatio >= 0.55f && ackRatio <= 0.35f) {
            return true;
        }
        return flow.rstPackets >= 24 || flow.fragmentedPackets >= 4;
    }

    private static boolean isKnownRiskServicePort(int port) {
        return port == 21
                || port == 22
                || port == 23
                || port == 25
                || port == 110
                || port == 135
                || port == 139
                || port == 143
                || port == 389
                || port == 445
                || port == 587
                || port == 993
                || port == 995
                || port == 1433
                || port == 1521
                || port == 3306
                || port == 3389
                || port == 5432
                || port == 5900
                || port == 6379
                || port == 8080
                || port == 8443
                || port == 9200
                || port == 11211
                || port == 27017;
    }

    private static boolean isPrivateLanHost(String host) {
        if (host.startsWith("192.168.") || host.startsWith("10.")) {
            return true;
        }
        if (host.startsWith("172.")) {
            String[] parts = host.split("\\.");
            if (parts.length > 1 && isInteger(parts[1])) {
                int second = Integer.parseInt(parts[1]);
                return second >= 16 && second <= 31;
            }
        }
        return false;
    }

    private static boolean isGoogleIp(String host) {
        return host.startsWith("66.102.")
                || host.startsWith("64.233.")
                || host.startsWith("74.125.")
                || host.startsWith("108.177.")
                || host.startsWith("142.250.")
                || host.startsWith("142.251.")
                || host.startsWith("172.217.")
                || host.startsWith("172.253.")
                || host.startsWith("209.85.")
                || host.startsWith("216.58.");
    }

    private static boolean isMetaIp(String host) {
        return host.startsWith("31.13.")
                || host.startsWith("57.144.")
                || host.startsWith("157.240.")
                || host.startsWith("163.70.")
                || host.startsWith("179.60.")
                || host.startsWith("185.60.");
    }

    private static boolean hasRiskyTld(String host) {
        return host.endsWith(".top")
                || host.endsWith(".xyz")
                || host.endsWith(".click")
                || host.endsWith(".zip")
                || host.endsWith(".mov")
                || host.endsWith(".quest")
                || host.endsWith(".country")
                || host.endsWith(".kim")
                || host.endsWith(".work")
                || host.endsWith(".rest")
                || host.endsWith(".gq")
                || host.endsWith(".tk")
                || host.endsWith(".ml")
                || host.endsWith(".cf");
    }

    private static boolean looksRandom(String value) {
        return entropy(value) >= 3.75f && digitRatio(value) >= 0.15f
                || value.matches(".*[0-9a-f]{16,}.*")
                || value.matches(".*[a-z0-9]{20,}.*");
    }

    private static float digitRatio(String value) {
        if (value == null || value.isEmpty()) {
            return 0f;
        }
        int digits = 0;
        for (int i = 0; i < value.length(); i++) {
            if (Character.isDigit(value.charAt(i))) {
                digits++;
            }
        }
        return digits / (float) value.length();
    }

    private static float entropy(String value) {
        if (value == null || value.isEmpty()) {
            return 0f;
        }
        int[] counts = new int[128];
        int total = 0;
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (c < counts.length) {
                counts[c]++;
                total++;
            }
        }
        float result = 0f;
        for (int count : counts) {
            if (count > 0) {
                float p = count / (float) total;
                result -= p * (Math.log(p) / Math.log(2));
            }
        }
        return result;
    }

    private static boolean isVpnSource(String source) {
        return source.startsWith("vpn_");
    }

    private static boolean isSupportOnlyModel(String modelId) {
        return "android_malware_flow".equals(modelId)
                || "iot_attack".equals(modelId)
                || "attack_anomaly".equals(modelId)
                || "post_quantum".equals(modelId)
                || "honeypot_threat_intel".equals(modelId);
    }

    private static String trimWww(String value) {
        return value.startsWith("www.") ? value.substring(4) : value;
    }

    private static boolean isInteger(String value) {
        if (value == null || value.isEmpty()) {
            return false;
        }
        for (int i = 0; i < value.length(); i++) {
            if (!Character.isDigit(value.charAt(i))) {
                return false;
            }
        }
        return true;
    }

    private static String safe(String value) {
        return value == null ? "" : value.trim();
    }
}
