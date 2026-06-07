package com.monster.cybershield;

import android.Manifest;
import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.app.Service;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.net.VpnService;
import android.os.Handler;
import android.os.HandlerThread;
import android.os.IBinder;

import com.monster.cybershield.core.ThreatEvent;
import com.monster.cybershield.core.ThreatStore;
import com.monster.cybershield.core.AlertNoisePolicy;
import com.monster.cybershield.core.BlocklistStore;
import com.monster.cybershield.core.MitmArpMonitor;
import com.monster.cybershield.core.PolicyAssistantText;
import com.monster.cybershield.core.ProtectionPolicyStore;
import com.monster.cybershield.core.WifiThreatMonitor;
import com.monster.cybershield.model.ModelCatalog;

import java.util.Locale;

public class CyberDefenseService extends Service {
    private static final String GROUP_THREATS = "cybershield_threats";
    private static final int NOTIFICATION_THREAT_SUMMARY = 11;
    public static final String ACTION_START = "com.monster.cybershield.START";
    public static final String ACTION_STOP = "com.monster.cybershield.STOP";
    public static final String ACTION_RAISE_THREAT = "com.monster.cybershield.RAISE_THREAT";
    public static final String EXTRA_MODEL_ID = "model_id";
    public static final String EXTRA_TITLE = "title";
    public static final String EXTRA_SOURCE = "source";
    public static final String EXTRA_TARGET = "target";
    public static final String EXTRA_SEVERITY = "severity";
    public static final String EXTRA_PROBABILITY = "probability";
    public static final String EXTRA_RECOMMENDED_ACTION = "recommended_action";

    private static final String CHANNEL_GUARD = "guard";
    private static final String CHANNEL_ALERTS = "alerts";
    private static final int NOTIFICATION_GUARD = 10;
    private HandlerThread workerThread;
    private Handler worker;
    private ModelCatalog catalog;
    private MitmArpMonitor mitmArpMonitor;
    private WifiThreatMonitor wifiThreatMonitor;
    private AlertNoisePolicy alertNoisePolicy;

    @Override
    public void onCreate() {
        super.onCreate();
        createChannels();
        clearOldAlertNotificationsOnce();
        catalog = ModelCatalog.load(this);
        alertNoisePolicy = new AlertNoisePolicy(this);
        mitmArpMonitor = new MitmArpMonitor(this);
        wifiThreatMonitor = new WifiThreatMonitor(this);
        workerThread = new HandlerThread("cyber-defense-worker");
        workerThread.start();
        worker = new Handler(workerThread.getLooper());
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        String action = intent == null ? ACTION_START : intent.getAction();
        if (ACTION_STOP.equals(action)) {
            stopForeground(STOP_FOREGROUND_REMOVE);
            stopSelf();
            return START_NOT_STICKY;
        }
        startForeground(NOTIFICATION_GUARD, buildGuardNotification());
        if (ACTION_RAISE_THREAT.equals(action) && intent != null) {
            raiseThreatFromIntent(intent);
        } else {
            scheduleHeartbeat();
        }
        return START_STICKY;
    }

    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }

    @Override
    public void onDestroy() {
        if (workerThread != null) {
            workerThread.quitSafely();
        }
        super.onDestroy();
    }

    private void scheduleHeartbeat() {
        if (worker == null) {
            return;
        }
        worker.removeCallbacksAndMessages(null);
        worker.postDelayed(new Runnable() {
            @Override
            public void run() {
                if (mitmArpMonitor != null) {
                    mitmArpMonitor.scanAndRaise();
                }
                if (wifiThreatMonitor != null) {
                    wifiThreatMonitor.scanAndRaise();
                }
                updateGuardNotification();
                worker.postDelayed(this, 60 * 1000L);
            }
        }, 10 * 1000L);
    }

    private void raiseThreatFromIntent(Intent intent) {
        String modelId = intent.getStringExtra(EXTRA_MODEL_ID);
        String title = valueOr(intent.getStringExtra(EXTRA_TITLE), "Siber tehdit algilandi");
        String source = valueOr(intent.getStringExtra(EXTRA_SOURCE), "otomatik koruma");
        String target = valueOr(intent.getStringExtra(EXTRA_TARGET), "unknown");
        String severity = valueOr(intent.getStringExtra(EXTRA_SEVERITY), "high");
        String recommendedAction = valueOr(intent.getStringExtra(EXTRA_RECOMMENDED_ACTION), "warn");
        double probability = intent.getDoubleExtra(EXTRA_PROBABILITY, 0.85);

        BlocklistStore blocklist = new BlocklistStore(this);
        if (blocklist.isAllowed(target)) {
            return;
        }
        if (alertNoisePolicy != null && alertNoisePolicy.shouldSuppressModelEvent(modelId, source, target)) {
            return;
        }
        ThreatStore threatStore = new ThreatStore(this);
        if (alertNoisePolicy != null && threatStore.hasRecentTarget(target, alertNoisePolicy.dedupWindowMs())) {
            return;
        }
        ThreatEvent event = threatStore.add(modelId, title, source, target, severity, probability, recommendedAction);
        enforcePhoneProtection(event);
        notifyThreat(event);
    }

    private void enforcePhoneProtection(ThreatEvent event) {
        if ("wifi_threat".equals(event.modelId) || "mitm_arp".equals(event.modelId)) {
            new ProtectionPolicyStore(this).requireStrictVpn(event.modelId + ":" + event.target, 2 * 60 * 60 * 1000L);
        }
        if ("require_vpn".equals(event.recommendedAction)
                || "block_flow".equals(event.recommendedAction)
                || "block_domain".equals(event.recommendedAction)
                || "block_ip".equals(event.recommendedAction)
                || "temporary_block".equals(event.recommendedAction)) {
            startVpnIfAlreadyConsented();
        }
    }

    private void startVpnIfAlreadyConsented() {
        try {
            if (VpnService.prepare(this) == null) {
                startService(new Intent(this, DefenseVpnService.class));
            }
        } catch (Exception ignored) {
        }
    }

    private Notification buildGuardNotification() {
        Intent open = new Intent(this, MainActivity.class);
        PendingIntent openIntent = PendingIntent.getActivity(this, 1, open, PendingIntent.FLAG_IMMUTABLE);

        Intent stop = new Intent(this, CyberDefenseService.class);
        stop.setAction(ACTION_STOP);
        PendingIntent stopIntent = PendingIntent.getService(this, 2, stop, PendingIntent.FLAG_IMMUTABLE);

        return new Notification.Builder(this, CHANNEL_GUARD)
                .setSmallIcon(android.R.drawable.ic_dialog_info)
                .setContentTitle("CyberShield aktif")
                .setContentText("Otomatik koruma dusuk guc modunda izliyor")
                .setContentIntent(openIntent)
                .setOngoing(true)
                .addAction(android.R.drawable.ic_media_pause, "Duraklat", stopIntent)
                .build();
    }

    private void updateGuardNotification() {
        NotificationManager manager = (NotificationManager) getSystemService(Context.NOTIFICATION_SERVICE);
        manager.notify(NOTIFICATION_GUARD, buildGuardNotification());
    }

    private void notifyThreat(ThreatEvent event) {
        if (android.os.Build.VERSION.SDK_INT >= 33 && checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) {
            return;
        }
        PendingIntent openIntent = openInterventionIntent(event, 0);

        Intent block = new Intent(this, InterventionActivity.class);
        block.putExtra(InterventionActivity.EXTRA_EVENT_ID, event.id);
        block.putExtra(InterventionActivity.EXTRA_ACTION, InterventionActivity.ACTION_BLOCK);
        PendingIntent blockIntent = PendingIntent.getActivity(this, event.id.hashCode() + 1, block, PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);

        Intent quarantine = new Intent(this, InterventionActivity.class);
        quarantine.putExtra(InterventionActivity.EXTRA_EVENT_ID, event.id);
        quarantine.putExtra(InterventionActivity.EXTRA_ACTION, InterventionActivity.ACTION_QUARANTINE);
        PendingIntent quarantineIntent = PendingIntent.getActivity(this, event.id.hashCode() + 2, quarantine, PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);

        Intent primary = new Intent(this, InterventionActivity.class);
        primary.putExtra(InterventionActivity.EXTRA_EVENT_ID, event.id);
        primary.putExtra(InterventionActivity.EXTRA_ACTION, primaryAction(event.recommendedAction));
        PendingIntent primaryIntent = PendingIntent.getActivity(this, event.id.hashCode() + 3, primary, PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);

        Notification notification = new Notification.Builder(this, CHANNEL_ALERTS)
                .setSmallIcon(android.R.drawable.stat_sys_warning)
                .setContentTitle(event.title)
                .setContentText(PolicyAssistantText.notificationSummary(event))
                .setStyle(new Notification.BigTextStyle().bigText(PolicyAssistantText.assistantBrief(event)))
                .setContentIntent(openIntent)
                .setGroup(GROUP_THREATS)
                .setAutoCancel(true)
                .addAction(android.R.drawable.ic_menu_send, PolicyAssistantText.actionLabel(event.recommendedAction), primaryIntent)
                .addAction(android.R.drawable.ic_menu_close_clear_cancel, "Engelle", blockIntent)
                .addAction(android.R.drawable.ic_menu_manage, "Karantina", quarantineIntent)
                .build();

        NotificationManager manager = (NotificationManager) getSystemService(Context.NOTIFICATION_SERVICE);
        manager.notify(AlertNoisePolicy.notificationIdFor(event.target), notification);
        manager.notify(NOTIFICATION_THREAT_SUMMARY, threatSummaryNotification(event, openIntent));
    }

    private PendingIntent openInterventionIntent(ThreatEvent event, int offset) {
        Intent open = new Intent(this, InterventionActivity.class);
        open.putExtra(InterventionActivity.EXTRA_EVENT_ID, event.id);
        open.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_CLEAR_TOP | Intent.FLAG_ACTIVITY_SINGLE_TOP);
        return PendingIntent.getActivity(this, event.id.hashCode() + offset, open, PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);
    }

    private Notification threatSummaryNotification(ThreatEvent event, PendingIntent openIntent) {
        return new Notification.Builder(this, CHANNEL_ALERTS)
                .setSmallIcon(android.R.drawable.stat_sys_warning)
                .setContentTitle("CyberShield mudahale bekliyor")
                .setContentText(event.title + " | " + AlertNoisePolicy.normalizedTarget(event.target))
                .setStyle(new Notification.BigTextStyle().bigText("Son olay: " + PolicyAssistantText.assistantBrief(event)))
                .setContentIntent(openIntent)
                .setGroup(GROUP_THREATS)
                .setGroupSummary(true)
                .setAutoCancel(true)
                .build();
    }

    private void clearOldAlertNotificationsOnce() {
        android.content.SharedPreferences prefs = getSharedPreferences("alert_noise_policy", MODE_PRIVATE);
        int policyVersion = 10;
        if (prefs.getInt("cleared_for_policy_version", 0) >= policyVersion) {
            return;
        }
        NotificationManager manager = (NotificationManager) getSystemService(Context.NOTIFICATION_SERVICE);
        manager.cancelAll();
        prefs.edit().putInt("cleared_for_policy_version", policyVersion).apply();
    }

    private void createChannels() {
        NotificationManager manager = (NotificationManager) getSystemService(Context.NOTIFICATION_SERVICE);
        NotificationChannel guard = new NotificationChannel(CHANNEL_GUARD, "Koruma durumu", NotificationManager.IMPORTANCE_LOW);
        NotificationChannel alerts = new NotificationChannel(CHANNEL_ALERTS, "Mudahale uyarilari", NotificationManager.IMPORTANCE_HIGH);
        alerts.setDescription("Engelleme, karantina ve kaldirma onayi isteyen siber guvenlik uyarilari");
        manager.createNotificationChannel(guard);
        manager.createNotificationChannel(alerts);
    }

    private static String valueOr(String value, String fallback) {
        return value == null || value.trim().isEmpty() ? fallback : value;
    }

    private static String primaryAction(String recommendedAction) {
        if ("quarantine".equals(recommendedAction)) {
            return InterventionActivity.ACTION_QUARANTINE;
        }
        if ("temporary_block".equals(recommendedAction)) {
            return InterventionActivity.ACTION_TEMPORARY_BLOCK;
        }
        if ("uninstall_prompt".equals(recommendedAction)) {
            return InterventionActivity.ACTION_REMOVE;
        }
        if ("warn".equals(recommendedAction)
                || "explain_only".equals(recommendedAction)
                || "allow".equals(recommendedAction)
                || "mark_wifi_suspicious".equals(recommendedAction)) {
            return "";
        }
        if ("require_vpn".equals(recommendedAction)) {
            return InterventionActivity.ACTION_REQUIRE_VPN;
        }
        return InterventionActivity.ACTION_BLOCK;
    }

}
