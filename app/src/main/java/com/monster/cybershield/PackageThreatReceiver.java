package com.monster.cybershield;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.net.Uri;

import com.monster.cybershield.core.ThreatEngine;

public class PackageThreatReceiver extends BroadcastReceiver {
    @Override
    public void onReceive(Context context, Intent intent) {
        Uri data = intent.getData();
        if (data == null || data.getSchemeSpecificPart() == null) {
            return;
        }
        String packageName = data.getSchemeSpecificPart();
        PendingResult result = goAsync();
        new Thread(() -> {
            try {
                new ThreatEngine(context).analyzeApk(packageName);
            } finally {
                result.finish();
            }
        }, "apk-threat-analysis").start();
    }
}
