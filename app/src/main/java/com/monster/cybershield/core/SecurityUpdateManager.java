package com.monster.cybershield.core;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.pm.PackageInfo;
import android.net.ConnectivityManager;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.os.BatteryManager;
import android.os.Build;

import com.monster.cybershield.R;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Locale;

import javax.net.ssl.HttpsURLConnection;

public final class SecurityUpdateManager {
    private static final int MAX_MANIFEST_BYTES = 1024 * 1024;
    private static final int MAX_FEED_BYTES = 8 * 1024 * 1024;
    private static final int MAX_MODEL_BYTES = 96 * 1024 * 1024;
    private static final String CHANNEL_ID = "security_updates";

    private final Context context;
    private final SecurityUpdateStore store;
    private boolean manifestSigned;

    public SecurityUpdateManager(Context context) {
        this.context = context.getApplicationContext();
        this.store = new SecurityUpdateStore(context);
    }

    public synchronized Result checkNow(boolean userInitiated) {
        try {
            if (!userInitiated && !store.autoUpdatesEnabled()) {
                return finish(false, "otomatik guncelleme kapali", "");
            }
            if (!userInitiated && store.wifiOnly() && !isWifiActive()) {
                return finish(false, "Wi-Fi bekleniyor", "");
            }
            if (!userInitiated && store.chargingOnly() && !isCharging()) {
                return finish(false, "sarj bekleniyor", "");
            }
            if (!userInitiated && isBatteryLow()) {
                return finish(false, "pil dusuk, ertelendi", "");
            }

            String manifestUrl = store.manifestUrl();
            manifestSigned = false;
            byte[] manifestBytes = downloadHttps(manifestUrl, MAX_MANIFEST_BYTES);
            JSONObject manifest = parseManifest(manifestBytes);
            int minVersionCode = manifest.optInt("min_app_version_code", 1);
            if (appVersionCode() < minVersionCode) {
                return finish(false, "uygulama guncellemesi gerekiyor", "");
            }

            int applied = 0;
            applied += applyFeeds(manifest.optJSONArray("feeds"));
            applied += applyModels(manifest.optJSONArray("models"));
            applied += applyMetadata(manifest.optJSONArray("metadata"));
            applied += applyCatalog(manifest.optJSONObject("catalog"));
            if (manifestSigned) {
                applied += applyThresholds(manifest.optJSONArray("thresholds"));
            }

            String status = applied > 0 ? "guncellendi: " + applied + " paket" : "guncel";
            store.setLastSuccess(status);
            if (applied > 0) {
                notifyUpdated(status);
            }
            return new Result(true, status, "");
        } catch (Exception e) {
            return finish(false, "guncelleme reddedildi", e.getClass().getSimpleName() + ": " + safe(e.getMessage()));
        }
    }

    private JSONObject parseManifest(byte[] bytes) throws Exception {
        JSONObject root = new JSONObject(new String(bytes, StandardCharsets.UTF_8));
        String signedPayload = root.optString("signed_payload", "");
        if (!signedPayload.isEmpty()) {
            byte[] payloadBytes = signedPayload.getBytes(StandardCharsets.UTF_8);
            if (!SecurityUpdateVerifier.signatureMatches(payloadBytes, root.optString("signature", ""))) {
                throw new SecurityException("manifest signature mismatch");
            }
            manifestSigned = true;
            return new JSONObject(signedPayload);
        }
        return root;
    }

    private int applyFeeds(JSONArray feeds) throws Exception {
        if (feeds == null) {
            return 0;
        }
        int applied = 0;
        for (int i = 0; i < feeds.length(); i++) {
            JSONObject item = feeds.optJSONObject(i);
            if (item == null) {
                continue;
            }
            File target = store.feedFile(item.optString("id"));
            if (downloadVerifyAndInstall(item, target, MAX_FEED_BYTES)) {
                store.recordFeedVersion(item.optString("id"), item.optString("version"));
                applied++;
            }
        }
        return applied;
    }

    private int applyModels(JSONArray models) throws Exception {
        if (models == null) {
            return 0;
        }
        int applied = 0;
        for (int i = 0; i < models.length(); i++) {
            JSONObject item = models.optJSONObject(i);
            if (item == null) {
                continue;
            }
            boolean modelOverMobile = item.optBoolean("allow_mobile", false);
            if (!isWifiActive() && !store.allowMobileModelUpdates() && !modelOverMobile) {
                continue;
            }
            String id = item.optString("id");
            if (downloadVerifyAndInstall(item, store.modelFile(id), MAX_MODEL_BYTES)) {
                store.recordModelVersion(id, item.optString("version"));
                applied++;
            }
            JSONObject metadata = item.optJSONObject("metadata");
            if (metadata != null) {
                String name = metadata.optString("name", id + "_metadata.json");
                if (downloadVerifyAndInstall(metadata, store.metadataFile(name), MAX_FEED_BYTES)) {
                    applied++;
                }
            }
        }
        return applied;
    }

    private int applyMetadata(JSONArray metadata) throws Exception {
        if (metadata == null) {
            return 0;
        }
        int applied = 0;
        for (int i = 0; i < metadata.length(); i++) {
            JSONObject item = metadata.optJSONObject(i);
            if (item == null) {
                continue;
            }
            String name = item.optString("name", item.optString("id", "metadata_" + i + ".json"));
            if (downloadVerifyAndInstall(item, store.metadataFile(name), MAX_FEED_BYTES)) {
                applied++;
            }
        }
        return applied;
    }

    private int applyCatalog(JSONObject catalog) throws Exception {
        if (catalog == null) {
            return 0;
        }
        return downloadVerifyAndInstall(catalog, store.catalogFile(), MAX_FEED_BYTES) ? 1 : 0;
    }

    private int applyThresholds(JSONArray thresholds) {
        if (thresholds == null) {
            return 0;
        }
        ModelCalibrationStore calibration = new ModelCalibrationStore(context);
        int applied = 0;
        for (int i = 0; i < thresholds.length(); i++) {
            JSONObject item = thresholds.optJSONObject(i);
            if (item == null) {
                continue;
            }
            String modelId = item.optString("model_id", item.optString("id", ""));
            if (modelId.isEmpty() || !item.has("threshold")) {
                continue;
            }
            calibration.setThreshold(modelId, item.optDouble("threshold", 0.5));
            applied++;
        }
        return applied;
    }

    private boolean downloadVerifyAndInstall(JSONObject item, File target, int maxBytes) throws Exception {
        String url = item.optString("url", "");
        String sha256 = item.optString("sha256", "");
        String signature = item.optString("signature", "");
        if (url.isEmpty() || sha256.isEmpty() || signature.isEmpty()) {
            return false;
        }
        byte[] data = downloadHttps(url, maxBytes);
        if (!SecurityUpdateVerifier.sha256Matches(data, sha256)) {
            throw new SecurityException("sha256 mismatch for " + target.getName());
        }
        if (!SecurityUpdateVerifier.signatureMatches(data, signature)) {
            throw new SecurityException("signature mismatch for " + target.getName());
        }
        installAtomically(data, target);
        return true;
    }

    private void installAtomically(byte[] data, File target) throws Exception {
        File parent = target.getParentFile();
        if (parent != null && !parent.exists() && !parent.mkdirs()) {
            throw new IllegalStateException("cannot create " + parent);
        }
        File staging = new File(store.stagingDir(), target.getName() + ".tmp");
        File stagingParent = staging.getParentFile();
        if (stagingParent != null && !stagingParent.exists() && !stagingParent.mkdirs()) {
            throw new IllegalStateException("cannot create " + stagingParent);
        }
        try (FileOutputStream output = new FileOutputStream(staging)) {
            output.write(data);
            output.getFD().sync();
        }
        File backup = new File(target.getAbsolutePath() + ".bak");
        if (target.exists()) {
            if (backup.exists() && !backup.delete()) {
                throw new IllegalStateException("cannot clear backup");
            }
            if (!target.renameTo(backup)) {
                throw new IllegalStateException("cannot backup active file");
            }
        }
        if (!staging.renameTo(target)) {
            if (backup.exists()) {
                backup.renameTo(target);
            }
            throw new IllegalStateException("cannot activate update");
        }
        if (backup.exists()) {
            backup.delete();
        }
    }

    private byte[] downloadHttps(String address, int maxBytes) throws Exception {
        URL url = new URL(address);
        if (!"https".equalsIgnoreCase(url.getProtocol())) {
            throw new SecurityException("only https update urls are allowed");
        }
        HttpsURLConnection connection = (HttpsURLConnection) url.openConnection();
        connection.setConnectTimeout(12000);
        connection.setReadTimeout(20000);
        connection.setInstanceFollowRedirects(false);
        int code = connection.getResponseCode();
        if (code < 200 || code >= 300) {
            throw new IllegalStateException("http " + code);
        }
        try (ByteArrayOutputStream output = new ByteArrayOutputStream()) {
            byte[] buffer = new byte[8192];
            int read;
            while ((read = connection.getInputStream().read(buffer)) != -1) {
                output.write(buffer, 0, read);
                if (output.size() > maxBytes) {
                    throw new SecurityException("update file too large");
                }
            }
            return output.toByteArray();
        } finally {
            connection.disconnect();
        }
    }

    private boolean isWifiActive() {
        try {
            ConnectivityManager manager = (ConnectivityManager) context.getSystemService(Context.CONNECTIVITY_SERVICE);
            if (manager == null) {
                return false;
            }
            Network network = manager.getActiveNetwork();
            NetworkCapabilities caps = manager.getNetworkCapabilities(network);
            return caps != null && caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI);
        } catch (Exception e) {
            return false;
        }
    }

    private boolean isCharging() {
        Intent battery = context.registerReceiver(null, new IntentFilter(Intent.ACTION_BATTERY_CHANGED));
        int plugged = battery == null ? 0 : battery.getIntExtra(BatteryManager.EXTRA_PLUGGED, 0);
        return plugged == BatteryManager.BATTERY_PLUGGED_AC
                || plugged == BatteryManager.BATTERY_PLUGGED_USB
                || plugged == BatteryManager.BATTERY_PLUGGED_WIRELESS;
    }

    private boolean isBatteryLow() {
        Intent battery = context.registerReceiver(null, new IntentFilter(Intent.ACTION_BATTERY_CHANGED));
        if (battery == null) {
            return false;
        }
        int level = battery.getIntExtra(BatteryManager.EXTRA_LEVEL, 100);
        int scale = battery.getIntExtra(BatteryManager.EXTRA_SCALE, 100);
        return scale > 0 && (level * 100 / scale) < 20 && !isCharging();
    }

    private int appVersionCode() {
        try {
            PackageInfo info = context.getPackageManager().getPackageInfo(context.getPackageName(), 0);
            if (Build.VERSION.SDK_INT >= 28) {
                return (int) info.getLongVersionCode();
            }
            return info.versionCode;
        } catch (Exception e) {
            return 1;
        }
    }

    private Result finish(boolean ok, String status, String error) {
        store.setLastCheck(status, error);
        return new Result(ok, status, error);
    }

    private void notifyUpdated(String status) {
        try {
            NotificationManager manager = (NotificationManager) context.getSystemService(Context.NOTIFICATION_SERVICE);
            if (manager == null) {
                return;
            }
            if (Build.VERSION.SDK_INT >= 26) {
                NotificationChannel channel = new NotificationChannel(CHANNEL_ID, "Guvenlik guncellemeleri", NotificationManager.IMPORTANCE_LOW);
                manager.createNotificationChannel(channel);
            }
            Notification notification = new Notification.Builder(context, CHANNEL_ID)
                    .setSmallIcon(R.mipmap.ic_launcher)
                    .setContentTitle("CyberShield guncellendi")
                    .setContentText("Guvenlik veritabani ve modeller kontrol edildi: " + status)
                    .setAutoCancel(true)
                    .build();
            manager.notify(8801, notification);
        } catch (Exception ignored) {
        }
    }

    private static String safe(String value) {
        return value == null ? "" : value.trim().replace('\n', ' ');
    }

    public static final class Result {
        public final boolean success;
        public final String status;
        public final String error;

        Result(boolean success, String status, String error) {
            this.success = success;
            this.status = status == null ? "" : status.toLowerCase(Locale.US);
            this.error = error == null ? "" : error;
        }
    }
}
