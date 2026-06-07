package com.monster.cybershield.core;

import android.app.AlarmManager;
import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import android.os.Build;

import com.monster.cybershield.SecurityUpdateReceiver;

public final class SecurityUpdateScheduler {
    public static final String ACTION_CHECK = "com.monster.cybershield.SECURITY_UPDATE_CHECK";
    private static final long DAILY_MS = 24L * 60L * 60L * 1000L;

    private SecurityUpdateScheduler() {
    }

    public static void scheduleDaily(Context context) {
        AlarmManager alarmManager = (AlarmManager) context.getSystemService(Context.ALARM_SERVICE);
        if (alarmManager == null) {
            return;
        }
        PendingIntent pendingIntent = pendingIntent(context);
        long first = System.currentTimeMillis() + 60L * 60L * 1000L;
        alarmManager.setInexactRepeating(AlarmManager.RTC_WAKEUP, first, DAILY_MS, pendingIntent);
    }

    public static void checkIfDueAsync(Context context) {
        SecurityUpdateStore store = new SecurityUpdateStore(context);
        if (store.autoUpdatesEnabled() && store.isDue(DAILY_MS)) {
            checkNowAsync(context, false, null);
        }
    }

    public static void checkNowAsync(Context context, boolean userInitiated, Callback callback) {
        Context appContext = context.getApplicationContext();
        new Thread(new Runnable() {
            @Override
            public void run() {
                SecurityUpdateManager.Result result = new SecurityUpdateManager(appContext).checkNow(userInitiated);
                if (callback != null) {
                    callback.onResult(result);
                }
            }
        }, "cybershield-security-update").start();
    }

    private static PendingIntent pendingIntent(Context context) {
        Intent intent = new Intent(context, SecurityUpdateReceiver.class);
        intent.setAction(ACTION_CHECK);
        int flags = PendingIntent.FLAG_UPDATE_CURRENT;
        if (Build.VERSION.SDK_INT >= 23) {
            flags |= PendingIntent.FLAG_IMMUTABLE;
        }
        return PendingIntent.getBroadcast(context, 8801, intent, flags);
    }

    public interface Callback {
        void onResult(SecurityUpdateManager.Result result);
    }
}
