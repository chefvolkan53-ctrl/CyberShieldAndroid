package com.monster.cybershield;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.os.Bundle;
import android.telephony.SmsMessage;

import com.monster.cybershield.core.ThreatEngine;

public class SmsThreatReceiver extends BroadcastReceiver {
    @Override
    public void onReceive(Context context, Intent intent) {
        if (!"android.provider.Telephony.SMS_RECEIVED".equals(intent.getAction())) {
            return;
        }
        Bundle bundle = intent.getExtras();
        if (bundle == null) {
            return;
        }
        Object[] pdus = (Object[]) bundle.get("pdus");
        String format = bundle.getString("format");
        if (pdus == null) {
            return;
        }
        StringBuilder body = new StringBuilder();
        String sender = "sms";
        for (Object pdu : pdus) {
            SmsMessage message = SmsMessage.createFromPdu((byte[]) pdu, format);
            if (message != null) {
                sender = message.getOriginatingAddress();
                body.append(message.getMessageBody()).append(' ');
            }
        }
        PendingResult result = goAsync();
        String source = sender == null ? "sms" : "sms:" + sender;
        new Thread(() -> {
            try {
                new ThreatEngine(context).analyzeText(body.toString(), source);
            } finally {
                result.finish();
            }
        }, "sms-threat-analysis").start();
    }
}
