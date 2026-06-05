package com.monster.cybershield;

import android.Manifest;
import android.app.Activity;
import android.content.ComponentName;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.net.VpnService;
import android.os.Bundle;
import android.util.Log;
import android.widget.ScrollView;
import android.widget.TextView;

import com.monster.cybershield.core.FeatureExtractor;
import com.monster.cybershield.core.ThreatEngine;

public class SourceFieldTestActivity extends Activity {
    public static final String TAG = "CYBERSHIELD_FIELDTEST";

    @Override
    protected void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        String report = runChecks();
        Log.i(TAG, report.replace('\n', ' '));

        TextView text = new TextView(this);
        text.setText(report);
        text.setTextSize(14);
        text.setPadding(24, 24, 24, 24);
        ScrollView scroll = new ScrollView(this);
        scroll.addView(text);
        setContentView(scroll);
    }

    private String runChecks() {
        StringBuilder builder = new StringBuilder();
        builder.append("CyberShield kaynak saha testi\n");
        builder.append("SMS RECEIVE: ").append(granted(Manifest.permission.RECEIVE_SMS)).append('\n');
        builder.append("SMS READ: ").append(granted(Manifest.permission.READ_SMS)).append('\n');
        builder.append("Bildirim: ").append(android.os.Build.VERSION.SDK_INT < 33 || granted(Manifest.permission.POST_NOTIFICATIONS)).append('\n');
        builder.append("VPN izin hazir: ").append(VpnService.prepare(this) == null).append('\n');
        builder.append("SMS receiver: ").append(receiverAvailable(SmsThreatReceiver.class)).append('\n');
        builder.append("APK receiver: ").append(receiverAvailable(PackageThreatReceiver.class)).append('\n');
        builder.append("Link scanner: ").append(activityAvailable(LinkScanActivity.class)).append('\n');
        builder.append("APK feature self size: ").append(FeatureExtractor.apk(this, getPackageName()).length).append('\n');
        builder.append("Not: Gercek SMS ve gercek APK kurulumu Android tarafinda sistem olayi ile dogrulanir; ADB korumali broadcast taklidi yapamaz.\n");

        new Thread(() -> new ThreatEngine(this).analyzeApk(getPackageName()), "fieldtest-apk-self").start();
        return builder.toString();
    }

    private boolean granted(String permission) {
        return checkSelfPermission(permission) == PackageManager.PERMISSION_GRANTED;
    }

    private boolean receiverAvailable(Class<?> receiver) {
        try {
            getPackageManager().getReceiverInfo(new ComponentName(this, receiver), 0);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    private boolean activityAvailable(Class<?> activity) {
        try {
            getPackageManager().getActivityInfo(new ComponentName(this, activity), 0);
            return true;
        } catch (Exception e) {
            return false;
        }
    }
}
