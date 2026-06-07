package com.monster.cybershield.core;

import android.content.Context;
import android.content.SharedPreferences;

import java.io.File;
import java.util.Locale;

public final class SecurityUpdateStore {
    private static final String PREF = "security_updates";
    private static final String DEFAULT_MANIFEST_URL =
            "https://raw.githubusercontent.com/chefvolkan53-ctrl/CyberShieldAndroid/main/security-updates/model_update_manifest.json";

    private final Context context;
    private final SharedPreferences prefs;

    public SecurityUpdateStore(Context context) {
        this.context = context.getApplicationContext();
        this.prefs = this.context.getSharedPreferences(PREF, Context.MODE_PRIVATE);
    }

    public boolean autoUpdatesEnabled() {
        return prefs.getBoolean("auto_updates_enabled", true);
    }

    public boolean wifiOnly() {
        return prefs.getBoolean("wifi_only", true);
    }

    public boolean chargingOnly() {
        return prefs.getBoolean("charging_only", false);
    }

    public boolean allowMobileModelUpdates() {
        return prefs.getBoolean("allow_mobile_model_updates", false);
    }

    public String manifestUrl() {
        return prefs.getString("manifest_url", DEFAULT_MANIFEST_URL);
    }

    public void setLastCheck(String status, String error) {
        long now = System.currentTimeMillis();
        prefs.edit()
                .putLong("last_check_ms", now)
                .putString("last_status", status == null ? "" : status)
                .putString("last_error", error == null ? "" : error)
                .apply();
    }

    public void setLastSuccess(String status) {
        long now = System.currentTimeMillis();
        prefs.edit()
                .putLong("last_check_ms", now)
                .putLong("last_success_ms", now)
                .putString("last_status", status == null ? "guncel" : status)
                .putString("last_error", "")
                .apply();
    }

    public long lastCheckMs() {
        return prefs.getLong("last_check_ms", 0L);
    }

    public long lastSuccessMs() {
        return prefs.getLong("last_success_ms", 0L);
    }

    public boolean isDue(long intervalMs) {
        return System.currentTimeMillis() - lastCheckMs() >= intervalMs;
    }

    public File rootDir() {
        return new File(context.getFilesDir(), "security_updates");
    }

    public File stagingDir() {
        return new File(rootDir(), "staging");
    }

    public File activeDir() {
        return new File(rootDir(), "active");
    }

    public File modelFile(String modelId) {
        return new File(new File(activeDir(), "models"), normalize(modelId) + ".tflite");
    }

    public File metadataFile(String metadataName) {
        return new File(new File(activeDir(), "metadata"), normalizeFileName(metadataName));
    }

    public File feedFile(String feedId) {
        return new File(new File(activeDir(), "feeds"), normalize(feedId) + ".json");
    }

    public File catalogFile() {
        return new File(activeDir(), "model_catalog.json");
    }

    public File activeModelIfPresent(String modelId) {
        File file = modelFile(modelId);
        return file.isFile() && file.length() > 0 ? file : null;
    }

    public File activeMetadataIfPresent(String metadataName) {
        File file = metadataFile(metadataName);
        return file.isFile() && file.length() > 0 ? file : null;
    }

    public File activeCatalogIfPresent() {
        File file = catalogFile();
        return file.isFile() && file.length() > 0 ? file : null;
    }

    public void recordModelVersion(String modelId, String version) {
        prefs.edit().putString("model_version:" + normalize(modelId), safe(version)).apply();
    }

    public void recordFeedVersion(String feedId, String version) {
        prefs.edit().putString("feed_version:" + normalize(feedId), safe(version)).apply();
    }

    public void recordFeedSummary(String feedId, String version, int domains, int ips, int cidrs, int phishingPatterns, int dohEndpoints, int riskyPorts, int cves) {
        prefs.edit()
                .putString("last_feed_id", safe(feedId))
                .putString("last_feed_version", safe(version))
                .putInt("last_feed_domains", domains)
                .putInt("last_feed_ips", ips)
                .putInt("last_feed_cidrs", cidrs)
                .putInt("last_feed_phishing_patterns", phishingPatterns)
                .putInt("last_feed_doh_endpoints", dohEndpoints)
                .putInt("last_feed_risky_ports", riskyPorts)
                .putInt("last_feed_cves", cves)
                .apply();
    }

    public String updateDetails() {
        String feedId = prefs.getString("last_feed_id", "");
        String version = prefs.getString("last_feed_version", "");
        if (feedId == null || feedId.isEmpty()) {
            return "Henuz indirilen guncelleme paketi yok.";
        }
        return "Paket: " + readablePackage(feedId)
                + "\nSurum: " + version
                + "\nDijital imza: dogrulandi"
                + "\nDurum: aktif";
    }

    public String updateCoverageDetails() {
        String feedId = prefs.getString("last_feed_id", "");
        if (feedId == null || feedId.isEmpty()) {
            return "Guncelleme alindiginda domain, IP, phishing ve riskli servis kapsami burada gorunur.";
        }
        return "Zararli domain: " + prefs.getInt("last_feed_domains", 0)
                + "\nZararli IP: " + prefs.getInt("last_feed_ips", 0)
                + "\nZararli IP bloklari: " + prefs.getInt("last_feed_cidrs", 0)
                + "\nPhishing URL kalibi: " + prefs.getInt("last_feed_phishing_patterns", 0)
                + "\nDoH endpoint: " + prefs.getInt("last_feed_doh_endpoints", 0)
                + "\nRiskli servis portu: " + prefs.getInt("last_feed_risky_ports", 0)
                + "\nAktif somurulen CVE: " + prefs.getInt("last_feed_cves", 0);
    }

    public String updateImpactDetails() {
        String feedId = prefs.getString("last_feed_id", "");
        if (feedId == null || feedId.isEmpty()) {
            return "Yeni feed indirildiginde link, DNS, VPN ve ag akis kontrolleri bu veriyi kullanir.";
        }
        return "Link ve SMS taramasi phishing kaliplarini kullanir."
                + "\nDNS/VPN korumasi zararli domain ve IP hedeflerini kontrol eder."
                + "\nAg akis motoru riskli port ve IP bloklarini ek sinyal olarak kullanir."
                + "\nDoH korumasi bilinen sifreli DNS endpointlerini sinirlayabilir.";
    }

    public String updateSourcesDetails() {
        String feedId = prefs.getString("last_feed_id", "");
        if (feedId == null || feedId.isEmpty()) {
            return "Kaynak bilgisi ilk basarili guncellemeden sonra gorunur.";
        }
        return "URLhaus / abuse.ch: malware URL ve domain sinyalleri"
                + "\nSpamhaus DROP: kotu niyetli IP bloklari"
                + "\nCISA KEV: aktif somurulen guvenlik aciklari"
                + "\nPhishTank: secret ekliyse phishing URL feed'i";
    }

    private static String readablePackage(String feedId) {
        if ("threat_intel".equals(feedId)) {
            return "Tehdit istihbarati veritabani";
        }
        return feedId;
    }

    public String summary() {
        String status = prefs.getString("last_status", "henuz kontrol edilmedi");
        String error = prefs.getString("last_error", "");
        long success = lastSuccessMs();
        String when = success <= 0 ? "basarili guncelleme yok" : minutesAgo(success) + " dk once";
        if (error != null && !error.isEmpty()) {
            return status + " | hata: " + error;
        }
        return status + " | son basari: " + when;
    }

    private static String minutesAgo(long timestamp) {
        long diff = Math.max(0L, System.currentTimeMillis() - timestamp);
        return String.valueOf(Math.max(0L, diff / 60000L));
    }

    private static String normalize(String value) {
        return safe(value).toLowerCase(Locale.US).replaceAll("[^a-z0-9_.-]", "_");
    }

    private static String normalizeFileName(String value) {
        String file = safe(value).replace('\\', '/');
        int slash = file.lastIndexOf('/');
        if (slash >= 0) {
            file = file.substring(slash + 1);
        }
        return normalize(file);
    }

    private static String safe(String value) {
        return value == null ? "" : value.trim();
    }
}
