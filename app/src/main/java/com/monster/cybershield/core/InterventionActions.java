package com.monster.cybershield.core;

import android.content.Context;
import android.content.Intent;
import android.net.Uri;
import android.provider.Settings;

public final class InterventionActions {
    public static final String STATUS_WARNED = "warned";
    public static final String STATUS_BLOCKED = "blocked";
    public static final String STATUS_QUARANTINED = "quarantined";
    public static final String STATUS_REMOVE_REQUESTED = "remove_requested";
    public static final String STATUS_ALLOWED = "allowed";
    public static final String STATUS_TEMP_BLOCKED = "temporary_blocked";

    private InterventionActions() {
    }

    public static void block(Context context, ThreatEvent event) {
        new BlocklistStore(context).block(event.target);
        new ThreatStore(context).mark(event.id, STATUS_BLOCKED);
    }

    public static void quarantine(Context context, ThreatEvent event) {
        new BlocklistStore(context).block(event.target);
        new ThreatStore(context).mark(event.id, STATUS_QUARANTINED);
    }

    public static void temporaryBlock(Context context, ThreatEvent event) {
        new BlocklistStore(context).temporaryBlock(event.target, 60 * 60 * 1000L);
        new ThreatStore(context).mark(event.id, STATUS_TEMP_BLOCKED);
    }

    public static void allow(Context context, ThreatEvent event) {
        new BlocklistStore(context).allow(event.target);
        new ThreatStore(context).mark(event.id, STATUS_ALLOWED);
    }

    public static String undoLast(Context context) {
        return new BlocklistStore(context).undoLast();
    }

    public static Intent uninstallIntent(ThreatEvent event) {
        Intent intent = new Intent(Intent.ACTION_DELETE);
        intent.setData(Uri.parse("package:" + event.target));
        return intent;
    }

    public static Intent appSettingsIntent(ThreatEvent event) {
        Intent intent = new Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS);
        intent.setData(Uri.parse("package:" + event.target));
        return intent;
    }
}
