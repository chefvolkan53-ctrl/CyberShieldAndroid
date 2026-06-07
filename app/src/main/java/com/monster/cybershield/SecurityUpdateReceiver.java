package com.monster.cybershield;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;

import com.monster.cybershield.core.SecurityUpdateScheduler;

public class SecurityUpdateReceiver extends BroadcastReceiver {
    @Override
    public void onReceive(Context context, Intent intent) {
        SecurityUpdateScheduler.checkNowAsync(context, false, null);
        SecurityUpdateScheduler.scheduleDaily(context);
    }
}
