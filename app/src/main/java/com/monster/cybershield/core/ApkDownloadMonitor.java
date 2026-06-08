package com.monster.cybershield.core;

import android.app.DownloadManager;
import android.content.BroadcastReceiver;
import android.content.ContentResolver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.database.ContentObserver;
import android.database.Cursor;
import android.net.Uri;
import android.os.Build;
import android.os.Handler;
import android.provider.MediaStore;

import java.util.HashSet;
import java.util.Locale;
import java.util.Set;

public final class ApkDownloadMonitor {
    private static final String MIME_APK = "application/vnd.android.package-archive";
    private final Context context;
    private final Handler handler;
    private final ThreatEngine threatEngine;
    private final Set<String> seen = new HashSet<>();
    private BroadcastReceiver receiver;
    private ContentObserver observer;

    public ApkDownloadMonitor(Context context, Handler handler) {
        this.context = context.getApplicationContext();
        this.handler = handler;
        this.threatEngine = new ThreatEngine(context);
    }

    public void start() {
        registerDownloadReceiver();
        registerDownloadsObserver();
        scanRecentDownloads();
    }

    public void stop() {
        try {
            if (receiver != null) {
                context.unregisterReceiver(receiver);
            }
        } catch (Exception ignored) {
        }
        try {
            if (observer != null) {
                context.getContentResolver().unregisterContentObserver(observer);
            }
        } catch (Exception ignored) {
        }
        receiver = null;
        observer = null;
    }

    public void scanRecentDownloads() {
        scanDownloadManagerRecent();
        scanMediaStoreRecent();
    }

    private void registerDownloadReceiver() {
        if (receiver != null) {
            return;
        }
        receiver = new BroadcastReceiver() {
            @Override
            public void onReceive(Context context, Intent intent) {
                if (!DownloadManager.ACTION_DOWNLOAD_COMPLETE.equals(intent.getAction())) {
                    return;
                }
                long id = intent.getLongExtra(DownloadManager.EXTRA_DOWNLOAD_ID, -1L);
                if (id >= 0) {
                    scanDownloadManagerId(id);
                } else {
                    scanRecentDownloads();
                }
            }
        };
        IntentFilter filter = new IntentFilter(DownloadManager.ACTION_DOWNLOAD_COMPLETE);
        if (Build.VERSION.SDK_INT >= 33) {
            context.registerReceiver(receiver, filter, Context.RECEIVER_NOT_EXPORTED);
        } else {
            context.registerReceiver(receiver, filter);
        }
    }

    private void registerDownloadsObserver() {
        if (observer != null || Build.VERSION.SDK_INT < 29) {
            return;
        }
        observer = new ContentObserver(handler) {
            @Override
            public void onChange(boolean selfChange, Uri uri) {
                scanRecentDownloads();
            }
        };
        context.getContentResolver().registerContentObserver(
                MediaStore.Downloads.EXTERNAL_CONTENT_URI,
                true,
                observer
        );
    }

    private void scanDownloadManagerId(long id) {
        DownloadManager manager = (DownloadManager) context.getSystemService(Context.DOWNLOAD_SERVICE);
        if (manager == null) {
            return;
        }
        DownloadManager.Query query = new DownloadManager.Query().setFilterById(id);
        try (Cursor cursor = manager.query(query)) {
            if (cursor == null) {
                return;
            }
            while (cursor.moveToNext()) {
                handleDownloadManagerRow(cursor);
            }
        } catch (Exception ignored) {
        }
    }

    private void scanDownloadManagerRecent() {
        DownloadManager manager = (DownloadManager) context.getSystemService(Context.DOWNLOAD_SERVICE);
        if (manager == null) {
            return;
        }
        DownloadManager.Query query = new DownloadManager.Query()
                .setFilterByStatus(DownloadManager.STATUS_SUCCESSFUL);
        try (Cursor cursor = manager.query(query)) {
            if (cursor == null) {
                return;
            }
            while (cursor.moveToNext()) {
                handleDownloadManagerRow(cursor);
            }
        } catch (Exception ignored) {
        }
    }

    private void handleDownloadManagerRow(Cursor cursor) {
        String id = string(cursor, DownloadManager.COLUMN_ID);
        String title = string(cursor, DownloadManager.COLUMN_TITLE);
        String mime = string(cursor, DownloadManager.COLUMN_MEDIA_TYPE);
        String localUri = string(cursor, DownloadManager.COLUMN_LOCAL_URI);
        String sourceUri = string(cursor, DownloadManager.COLUMN_URI);
        long modifiedAt = number(cursor, DownloadManager.COLUMN_LAST_MODIFIED_TIMESTAMP);
        if (modifiedAt > 0 && modifiedAt < System.currentTimeMillis() - 24L * 60L * 60L * 1000L) {
            return;
        }
        if (!looksLikeApk(title, mime, localUri, sourceUri)) {
            return;
        }
        Uri uri = localUri.isEmpty() ? null : Uri.parse(localUri);
        handleApk("dm:" + id + ":" + localUri, uri, title, sourceUri);
    }

    private void scanMediaStoreRecent() {
        if (Build.VERSION.SDK_INT < 29) {
            return;
        }
        ContentResolver resolver = context.getContentResolver();
        String[] projection = new String[]{
                MediaStore.Downloads._ID,
                MediaStore.Downloads.DISPLAY_NAME,
                MediaStore.Downloads.MIME_TYPE,
                MediaStore.Downloads.DATE_ADDED,
                MediaStore.Downloads.SIZE
        };
        String selection = MediaStore.Downloads.DATE_ADDED + ">=?";
        String[] args = new String[]{String.valueOf((System.currentTimeMillis() / 1000L) - 24 * 60 * 60)};
        try (Cursor cursor = resolver.query(
                MediaStore.Downloads.EXTERNAL_CONTENT_URI,
                projection,
                selection,
                args,
                MediaStore.Downloads.DATE_ADDED + " DESC"
        )) {
            if (cursor == null) {
                return;
            }
            while (cursor.moveToNext()) {
                long id = cursor.getLong(cursor.getColumnIndexOrThrow(MediaStore.Downloads._ID));
                String name = cursor.getString(cursor.getColumnIndexOrThrow(MediaStore.Downloads.DISPLAY_NAME));
                String mime = cursor.getString(cursor.getColumnIndexOrThrow(MediaStore.Downloads.MIME_TYPE));
                if (!looksLikeApk(name, mime, "", "")) {
                    continue;
                }
                Uri uri = Uri.withAppendedPath(MediaStore.Downloads.EXTERNAL_CONTENT_URI, String.valueOf(id));
                handleApk("media:" + id, uri, name, "");
            }
        } catch (Exception ignored) {
        }
    }

    private void handleApk(String key, Uri uri, String label, String sourceUrl) {
        if (key == null || !seen.add(key)) {
            return;
        }
        threatEngine.analyzeDownloadedApk(uri, label, sourceUrl);
    }

    private static boolean looksLikeApk(String title, String mime, String localUri, String sourceUri) {
        String value = (safe(title) + " " + safe(mime) + " " + safe(localUri) + " " + safe(sourceUri)).toLowerCase(Locale.US);
        return value.contains(MIME_APK) || value.contains(".apk") || value.contains("android package");
    }

    private static String string(Cursor cursor, String column) {
        try {
            int index = cursor.getColumnIndex(column);
            return index < 0 ? "" : safe(cursor.getString(index));
        } catch (Exception e) {
            return "";
        }
    }

    private static long number(Cursor cursor, String column) {
        try {
            int index = cursor.getColumnIndex(column);
            return index < 0 ? 0L : cursor.getLong(index);
        } catch (Exception e) {
            return 0L;
        }
    }

    private static String safe(String value) {
        return value == null ? "" : value.trim();
    }
}
