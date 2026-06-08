package com.monster.cybershield.core;

import java.util.Locale;

public final class BuiltInThreatTargets {
    private BuiltInThreatTargets() {
    }

    public static boolean isKnownTestThreat(String target) {
        String host = AlertNoisePolicy.normalizedHost(target);
        String value = safe(target).toLowerCase(Locale.US);
        return "amtso.eicar.org".equals(host)
                || host.endsWith(".amtso.eicar.org")
                || value.contains("com.amtso.mobiletestfile.apk");
    }

    public static boolean isKnownTestThreatUrl(String url) {
        String value = safe(url).toLowerCase(Locale.US);
        return isKnownTestThreat(value)
                || value.contains("feature-settings-check-download-of-malware-for-android-based-solutions")
                || value.contains("feature-settings-check-drive-by-download-for-android-based-solutions");
    }

    public static boolean isKnownPhishingTestUrl(String url) {
        String value = safe(url).toLowerCase(Locale.US);
        return value.contains("feature-settings-check-phishing-page-for-android-based-solutions")
                || value.contains("check-android-phishing-page")
                || value.contains("feature-settings-check-phishing-page")
                || value.contains("check-desktop-phishing-page");
    }

    private static String safe(String value) {
        return value == null ? "" : value.trim();
    }
}
