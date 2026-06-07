package com.monster.cybershield;

import android.Manifest;
import android.app.Activity;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.PackageManager;
import android.graphics.Color;
import android.net.Uri;
import android.net.VpnService;
import android.os.Bundle;
import android.provider.Settings;
import android.view.View;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

public class OnboardingActivity extends Activity {
    public static final String PREF = "onboarding";
    public static final String KEY_DONE = "done";
    private static final int REQ_VPN = 401;

    @Override
    protected void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        render();
    }

    private void render() {
        ScrollView scroll = new ScrollView(this);
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(dp(18), dp(18), dp(18), dp(18));
        root.setBackgroundColor(Color.rgb(16, 20, 24));
        scroll.addView(root);

        root.addView(text("CyberShield kurulum", 28, Color.WHITE, true));
        root.addView(text("Otomatik koruma icin gerekli izinleri ac. Yikici islemler yine kullanici onayi ile uygulanir.", 14, Color.rgb(169, 182, 194), false));
        root.addView(status("Bildirim", hasNotificationPermission()));
        root.addView(status("SMS korumasi", hasSmsPermission()));
        root.addView(status("Wi-Fi risk izni", hasWifiRiskPermission()));
        root.addView(status("VPN", VpnService.prepare(this) == null));
        root.addView(button(hasNotificationPermission() ? "Bildirim izni acik" : "Bildirim izni ver", v -> requestNotificationPermission()));
        root.addView(button(hasSmsPermission() ? "SMS korumasi acik" : "SMS korumasi izni ver", v -> requestSmsPermission()));
        root.addView(button(hasWifiRiskPermission() ? "Wi-Fi risk izni acik" : "Wi-Fi risk izni ver", v -> requestWifiRiskPermission()));
        root.addView(button("SMS izin ayarini ac", v -> openAppSettings()));
        root.addView(button("VPN korumasini etkinlestir", v -> requestVpnPermission()));
        root.addView(button("Pil optimizasyonundan muaf tut", v -> openBatteryOptimization()));
        root.addView(button("Samsung arka plan ayarlari", v -> openAppSettings()));
        root.addView(button("Kurulumu tamamla", v -> finishOnboarding()));

        setContentView(scroll);
    }

    private void requestNotificationPermission() {
        if (android.os.Build.VERSION.SDK_INT >= 33 && checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) {
            requestPermissions(new String[]{Manifest.permission.POST_NOTIFICATIONS}, 300);
        } else {
            Toast.makeText(this, "Bildirim izni zaten acik", Toast.LENGTH_SHORT).show();
            render();
        }
    }

    private void requestSmsPermission() {
        if (!hasSmsPermission()) {
            requestPermissions(new String[]{Manifest.permission.RECEIVE_SMS, Manifest.permission.READ_SMS}, 301);
        } else {
            Toast.makeText(this, "SMS korumasi zaten acik", Toast.LENGTH_SHORT).show();
            render();
        }
    }

    private void requestWifiRiskPermission() {
        if (!hasWifiRiskPermission()) {
            requestPermissions(new String[]{Manifest.permission.ACCESS_FINE_LOCATION}, 302);
        } else {
            Toast.makeText(this, "Wi-Fi risk izni zaten acik", Toast.LENGTH_SHORT).show();
            render();
        }
    }

    private void requestVpnPermission() {
        Intent intent = VpnService.prepare(this);
        if (intent != null) {
            Toast.makeText(this, "Android VPN onay ekranini aciyorum", Toast.LENGTH_SHORT).show();
            startActivityForResult(intent, REQ_VPN);
        } else {
            startDefenseVpn();
        }
    }

    private void startDefenseVpn() {
        try {
            startService(new Intent(this, DefenseVpnService.class));
            Toast.makeText(this, "VPN korumasi baslatildi", Toast.LENGTH_SHORT).show();
        } catch (Exception e) {
            Toast.makeText(this, "VPN baslatilamadi: " + e.getClass().getSimpleName(), Toast.LENGTH_LONG).show();
        }
        render();
    }

    private void openBatteryOptimization() {
        try {
            Intent intent = new Intent(Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS);
            intent.setData(Uri.parse("package:" + getPackageName()));
            startActivity(intent);
        } catch (Exception e) {
            openAppSettings();
        }
    }

    private void openAppSettings() {
        Intent intent = new Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS);
        intent.setData(Uri.parse("package:" + getPackageName()));
        startActivity(intent);
    }

    private void finishOnboarding() {
        SharedPreferences prefs = getSharedPreferences(PREF, MODE_PRIVATE);
        prefs.edit().putBoolean(KEY_DONE, true).apply();
        startActivity(new Intent(this, MainActivity.class));
        finish();
    }

    @Override
    public void onRequestPermissionsResult(int requestCode, String[] permissions, int[] grantResults) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults);
        render();
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode == REQ_VPN) {
            if (resultCode == RESULT_OK) {
                startDefenseVpn();
            } else {
                Toast.makeText(this, "VPN izni verilmedi", Toast.LENGTH_LONG).show();
                render();
            }
        }
    }

    @Override
    protected void onResume() {
        super.onResume();
        render();
    }

    private boolean hasNotificationPermission() {
        return android.os.Build.VERSION.SDK_INT < 33 || checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) == PackageManager.PERMISSION_GRANTED;
    }

    private boolean hasSmsPermission() {
        return checkSelfPermission(Manifest.permission.RECEIVE_SMS) == PackageManager.PERMISSION_GRANTED
                && checkSelfPermission(Manifest.permission.READ_SMS) == PackageManager.PERMISSION_GRANTED;
    }

    private boolean hasWifiRiskPermission() {
        return checkSelfPermission(Manifest.permission.ACCESS_FINE_LOCATION) == PackageManager.PERMISSION_GRANTED;
    }

    private TextView status(String label, boolean enabled) {
        return text(label + ": " + (enabled ? "ACIK" : "KAPALI"), 16, enabled ? Color.rgb(32, 201, 151) : Color.rgb(245, 165, 36), true);
    }

    private TextView text(String value, int sp, int color, boolean bold) {
        TextView view = new TextView(this);
        view.setText(value);
        view.setTextColor(color);
        view.setTextSize(sp);
        view.setPadding(0, dp(6), 0, dp(6));
        if (bold) {
            view.setTypeface(android.graphics.Typeface.DEFAULT_BOLD);
        }
        return view;
    }

    private Button button(String label, View.OnClickListener listener) {
        Button button = new Button(this);
        button.setText(label);
        button.setAllCaps(false);
        button.setOnClickListener(listener);
        return button;
    }

    private int dp(int value) {
        return Math.round(value * getResources().getDisplayMetrics().density);
    }
}
