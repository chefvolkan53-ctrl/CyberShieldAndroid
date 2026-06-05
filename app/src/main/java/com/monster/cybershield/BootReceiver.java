package com.monster.cybershield;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;

public class BootReceiver extends BroadcastReceiver {
    @Override
    public void onReceive(Context context, Intent intent) {
        Intent service = new Intent(context, CyberDefenseService.class);
        service.setAction(CyberDefenseService.ACTION_START);
        context.startForegroundService(service);
    }
}
