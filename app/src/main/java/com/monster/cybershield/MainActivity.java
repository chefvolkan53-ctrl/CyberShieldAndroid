package com.monster.cybershield;

import android.Manifest;
import android.app.Activity;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.PackageManager;
import android.graphics.Color;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.net.VpnService;
import android.os.Bundle;
import android.provider.Settings;
import android.view.View;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import com.monster.cybershield.core.ThreatEvent;
import com.monster.cybershield.core.ThreatStore;
import com.monster.cybershield.core.BlocklistStore;
import com.monster.cybershield.core.PolicyAssistantText;
import com.monster.cybershield.core.ProtectionPolicyStore;
import com.monster.cybershield.model.ModelCatalog;

import java.util.List;
import java.util.Locale;

public class MainActivity extends Activity {
    private static final int REQ_VPN = 501;
    private static final int BG = Color.rgb(11, 18, 24);
    private static final int SURFACE = Color.rgb(22, 31, 39);
    private static final int SURFACE_SOFT = Color.rgb(29, 41, 51);
    private static final int TEXT = Color.rgb(239, 246, 252);
    private static final int MUTED = Color.rgb(158, 174, 187);
    private static final int DANGER = Color.rgb(220, 53, 69);
    private static final int WARNING = Color.rgb(245, 158, 11);
    private static final int OK = Color.rgb(32, 201, 151);
    private static final int ACCENT = Color.rgb(56, 189, 248);
    private ModelCatalog catalog;
    private ThreatStore threatStore;
    private LinearLayout root;

    @Override
    protected void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        SharedPreferences prefs = getSharedPreferences(OnboardingActivity.PREF, MODE_PRIVATE);
        if (!prefs.getBoolean(OnboardingActivity.KEY_DONE, false)) {
            startActivity(new Intent(this, OnboardingActivity.class));
        }
        catalog = ModelCatalog.load(this);
        threatStore = new ThreatStore(this);
        requestNotificationPermission();
        render();
        startService(new Intent(this, CyberDefenseService.class).setAction(CyberDefenseService.ACTION_START));
    }

    @Override
    protected void onResume() {
        super.onResume();
        render();
    }

    private void render() {
        ScrollView scroll = new ScrollView(this);
        root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(dp(18), dp(18), dp(18), dp(24));
        root.setBackgroundColor(BG);
        scroll.addView(root);

        root.addView(text("CyberShield", 13, ACCENT, true));
        root.addView(text("Savunma merkezi", 30, TEXT, true));
        root.addView(text("Telefon, ag, DNS, link, SMS ve APK kaynaklari otomatik izleniyor. Kritik olaylarda bildirim dogrudan mudahale ekranina gider.", 14, MUTED, false));
        addSpace(10);

        List<ThreatEvent> activeEvents = threatStore.activeList();
        List<ThreatEvent> historyEvents = threatStore.historyList();
        int openThreats = activeEvents.size();
        ThreatEvent firstOpen = activeEvents.isEmpty() ? null : activeEvents.get(0);
        ThreatEvent latest = historyEvents.isEmpty() ? null : historyEvents.get(0);
        ProtectionPolicyStore policy = new ProtectionPolicyStore(this);
        SharedPreferences vpnStatus = getSharedPreferences("vpn_status", MODE_PRIVATE);

        root.addView(statusPanel(openThreats, policy, vpnStatus));
        if (firstOpen != null) {
            root.addView(threatPanel(firstOpen, true));
        }

        addSection("Hizli kontroller");
        root.addView(actionButton("Korumayi aktif tut", OK, new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                startService(new Intent(MainActivity.this, CyberDefenseService.class).setAction(CyberDefenseService.ACTION_START));
            }
        }));
        root.addView(actionButton("Siki VPN/DNS korumasini ac", ACCENT, new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                enableStrictDnsVpnProtection();
            }
        }));
        root.addView(secondaryButton("Izinler ve VPN kurulumu", new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                startActivity(new Intent(MainActivity.this, OnboardingActivity.class));
            }
        }));
        root.addView(secondaryButton("Son engellemeyi geri al", new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                String undone = new BlocklistStore(MainActivity.this).undoLast();
                Toast.makeText(MainActivity.this, undone.isEmpty() ? "Geri alinacak karar yok" : "Geri alindi: " + undone, Toast.LENGTH_SHORT).show();
                render();
            }
        }));
        root.addView(secondaryButton("Cozulen olaylari temizle", new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                threatStore.clearResolved();
                Toast.makeText(MainActivity.this, "Cozulen olay gecmisi temizlendi", Toast.LENGTH_SHORT).show();
                render();
            }
        }));
        root.addView(secondaryButton("Tum aktif uyarilari kapat", new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                threatStore.clearAllActive();
                Toast.makeText(MainActivity.this, "Aktif uyarilar kapatildi", Toast.LENGTH_SHORT).show();
                render();
            }
        }));
        root.addView(secondaryButton("Uyumlu internet modu", new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                disableStrictDnsVpnProtection();
            }
        }));
        root.addView(secondaryButton("Korumayi duraklat", new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                startService(new Intent(MainActivity.this, CyberDefenseService.class).setAction(CyberDefenseService.ACTION_STOP));
                stopService(new Intent(MainActivity.this, DefenseVpnService.class));
                Toast.makeText(MainActivity.this, "Koruma duraklatildi", Toast.LENGTH_SHORT).show();
            }
        }));

        addSection("Son tehditler");
        if (activeEvents.isEmpty()) {
            root.addView(card("Aktif olay yok", "Bildirim geldiginde dokununca ilgili mudahale ekranina acilir."));
        } else {
            int count = 0;
            for (ThreatEvent event : activeEvents) {
                if (count++ >= 5) {
                    break;
                }
                root.addView(threatPanel(event, false));
            }
        }

        addSection("Son kararlar");
        if (historyEvents.isEmpty()) {
            root.addView(card("Gecmis karar yok", "Engellenen, karantinaya alinan veya guvenli sayilan olaylar burada kisa sure gorunur."));
        } else {
            int count = 0;
            for (ThreatEvent event : historyEvents) {
                if (count++ >= 3) {
                    break;
                }
                root.addView(card(event.title, readableStatus(event.status) + " | " + event.target));
            }
        }

        addSection("Karantina / blok liste");
        BlocklistStore blocklist = new BlocklistStore(this);
        if (blocklist.all().isEmpty() && blocklist.allowList().isEmpty()) {
            root.addView(card("Politika listesi bos", "Engelleme veya guvenli sayma karari burada gorunur."));
        } else {
            int shown = 0;
            for (String value : blocklist.all()) {
                if (shown++ >= 6) break;
                root.addView(card("Engelli hedef", value));
            }
            for (String value : blocklist.allowList()) {
                if (shown++ >= 8) break;
                root.addView(card("Guvenli sayildi", value));
            }
        }
        setContentView(scroll);
    }

    private View statusPanel(int openThreats, ProtectionPolicyStore policy, SharedPreferences vpnStatus) {
        LinearLayout panel = panel();
        panel.addView(text(openThreats == 0 ? "Koruma stabil" : "Mudahale bekleyen olay var", 21, openThreats == 0 ? OK : WARNING, true));
        panel.addView(text("Acik olay: " + openThreats + " | Model seti: " + catalog.all().size() + " | Pil modu: dengeli", 14, TEXT, false));
        panel.addView(text("DNS/VPN: " + policy.dnsLeakProtectionSummary(), 13, MUTED, false));
        panel.addView(text("Motor: " + vpnStatus.getString("mode", "not_started")
                + " | Proxy " + vpnStatus.getLong("proxy_connections", 0L)
                + " | Flow " + vpnStatus.getLong("proxy_analyzed_flows", 0L), 13, MUTED, false));
        return panel;
    }

    private View threatPanel(ThreatEvent event, boolean prominent) {
        LinearLayout panel = panel();
        int riskColor = event.probability >= 0.85 ? DANGER : event.probability >= 0.65 ? WARNING : ACCENT;
        panel.addView(text((prominent ? "Acil olay: " : "") + event.title, prominent ? 19 : 16, TEXT, true));
        panel.addView(text(String.format(Locale.US, "%.1f%% risk", event.probability * 100.0) + " | " + readableStatus(event.status), 14, riskColor, true));
        panel.addView(text(event.target, 13, MUTED, false));
        panel.addView(text(PolicyAssistantText.notificationSummary(event), 13, Color.rgb(219, 234, 246), false));
        panel.addView(actionButton("Mudahale et", riskColor, v -> openEvent(event)));
        panel.setOnClickListener(v -> openEvent(event));
        return panel;
    }

    private void openEvent(ThreatEvent event) {
        Intent open = new Intent(MainActivity.this, InterventionActivity.class);
        open.putExtra(InterventionActivity.EXTRA_EVENT_ID, event.id);
        startActivity(open);
    }

    private void requestNotificationPermission() {
        if (android.os.Build.VERSION.SDK_INT >= 33 && checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) {
            requestPermissions(new String[]{Manifest.permission.POST_NOTIFICATIONS}, 200);
        }
        if (checkSelfPermission(Manifest.permission.RECEIVE_SMS) != PackageManager.PERMISSION_GRANTED) {
            requestPermissions(new String[]{Manifest.permission.RECEIVE_SMS, Manifest.permission.READ_SMS}, 201);
        }
    }

    private void enableStrictDnsVpnProtection() {
        ProtectionPolicyStore store = new ProtectionPolicyStore(this);
        store.setDnsLeakProtection(true);
        store.setFullVpnForwardingEnabled(true);
        store.setDnsProvider(ProtectionPolicyStore.DNS_CLOUDFLARE);
        stopService(new Intent(this, DefenseVpnService.class));
        if (isPrivateDnsActive()) {
            Toast.makeText(this, "Android Private DNS'i kapatip geri don", Toast.LENGTH_LONG).show();
            try {
                startActivity(new Intent("android.settings.PRIVATE_DNS_SETTINGS"));
            } catch (Exception e) {
                startActivity(new Intent(Settings.ACTION_WIRELESS_SETTINGS));
            }
            render();
            return;
        }
        requestVpnPermission();
    }

    private void disableStrictDnsVpnProtection() {
        ProtectionPolicyStore store = new ProtectionPolicyStore(this);
        store.setFullVpnForwardingEnabled(false);
        store.setDnsLeakProtection(false);
        stopService(new Intent(this, DefenseVpnService.class));
        Toast.makeText(this, "Uyumlu moda donuldu", Toast.LENGTH_SHORT).show();
        render();
    }

    private void requestVpnPermission() {
        Intent intent = VpnService.prepare(this);
        if (intent != null) {
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

    private boolean isPrivateDnsActive() {
        try {
            String mode = Settings.Global.getString(getContentResolver(), "private_dns_mode");
            return mode != null && !"off".equalsIgnoreCase(mode) && !"opportunistic".equalsIgnoreCase(mode);
        } catch (Exception e) {
            return false;
        }
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

    private void addSection(String title) {
        addSpace(18);
        root.addView(text(title, 18, Color.WHITE, true));
    }

    private TextView card(String title, String subtitle) {
        TextView view = text(title + "\n" + subtitle, 15, TEXT, false);
        view.setBackground(rounded(SURFACE));
        view.setPadding(dp(14), dp(12), dp(14), dp(12));
        LinearLayout.LayoutParams params = new LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT);
        params.setMargins(0, dp(6), 0, dp(6));
        view.setLayoutParams(params);
        return view;
    }

    private TextView text(String value, int sp, int color, boolean bold) {
        TextView text = new TextView(this);
        text.setText(value);
        text.setTextColor(color);
        text.setTextSize(sp);
        text.setPadding(0, dp(5), 0, dp(5));
        if (bold) {
            text.setTypeface(Typeface.DEFAULT_BOLD);
        }
        return text;
    }

    private Button actionButton(String label, int color, View.OnClickListener listener) {
        Button button = new Button(this);
        button.setText(label);
        button.setAllCaps(false);
        button.setTextColor(Color.WHITE);
        button.setTextSize(15);
        button.setTypeface(Typeface.DEFAULT_BOLD);
        button.setOnClickListener(listener);
        button.setBackground(rounded(color));
        button.setPadding(0, dp(10), 0, dp(10));
        LinearLayout.LayoutParams params = new LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT);
        params.setMargins(0, dp(6), 0, dp(6));
        button.setLayoutParams(params);
        return button;
    }

    private Button secondaryButton(String label, View.OnClickListener listener) {
        return actionButton(label, SURFACE_SOFT, listener);
    }

    private LinearLayout panel() {
        LinearLayout layout = new LinearLayout(this);
        layout.setOrientation(LinearLayout.VERTICAL);
        layout.setPadding(dp(14), dp(12), dp(14), dp(12));
        layout.setBackground(rounded(SURFACE));
        LinearLayout.LayoutParams params = new LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT);
        params.setMargins(0, dp(6), 0, dp(6));
        layout.setLayoutParams(params);
        return layout;
    }

    private GradientDrawable rounded(int color) {
        GradientDrawable drawable = new GradientDrawable();
        drawable.setColor(color);
        drawable.setCornerRadius(dp(8));
        return drawable;
    }

    private String readableStatus(String status) {
        if ("blocked".equals(status)) return "engellendi";
        if ("quarantined".equals(status)) return "karantinada";
        if ("temporary_blocked".equals(status)) return "gecici engelli";
        if ("allowed".equals(status)) return "guvenli";
        if ("remove_requested".equals(status)) return "kaldirma istendi";
        if ("filtered".equals(status)) return "sistem olayi filtrelendi";
        if ("superseded".equals(status)) return "tekrar eden olay kapatildi";
        if ("archived".equals(status)) return "arsivlendi";
        if ("dismissed".equals(status)) return "kapatildi";
        return "mudahale bekliyor";
    }

    private void addSpace(int heightDp) {
        View spacer = new View(this);
        root.addView(spacer, new LinearLayout.LayoutParams(1, dp(heightDp)));
    }

    private int dp(int value) {
        return Math.round(value * getResources().getDisplayMetrics().density);
    }
}
