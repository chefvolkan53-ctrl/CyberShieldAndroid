package com.monster.cybershield;

import android.Manifest;
import android.app.Activity;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.PackageManager;
import android.graphics.Color;
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
import com.monster.cybershield.model.ModelSpec;

import java.util.List;
import java.util.Locale;

public class MainActivity extends Activity {
    private static final int REQ_VPN = 501;
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
        root.setPadding(dp(18), dp(18), dp(18), dp(18));
        root.setBackgroundColor(Color.rgb(16, 20, 24));
        scroll.addView(root);

        root.addView(text("CyberShield", 28, Color.WHITE, true));
        root.addView(text("Otomatik siber savunma aktif. Olay bazli model yukleme, VPN politikasi, SMS/link/APK kaynaklari ve kullanici onayli mudahale devrede.", 14, Color.rgb(169, 182, 194), false));
        addSpace(10);

        int openThreats = 0;
        for (ThreatEvent event : threatStore.list()) {
            if ("new".equals(event.status)) {
                openThreats++;
            }
        }
        ProtectionPolicyStore policy = new ProtectionPolicyStore(this);
        root.addView(card("Risk paneli", "Acik olay: " + openThreats + " | Algilama modeli: " + catalog.all().size() + " | Policy modeli: aktif | Pil profili: dengeli"));
        root.addView(card("DNS korumasi", policy.dnsLeakProtectionSummary() + " | Strict VPN: " + (policy.isStrictVpnRequired() ? "ACIK" : "KAPALI")));
        SharedPreferences vpnStatus = getSharedPreferences("vpn_status", MODE_PRIVATE);
        root.addView(card("VPN analiz motoru",
                "Mod: " + vpnStatus.getString("mode", "not_started")
                        + " | Proxy: " + vpnStatus.getLong("proxy_connections", 0L)
                        + " | Mirror KB: " + (vpnStatus.getLong("proxy_mirrored_bytes", 0L) / 1024L)
                        + " | Flow: " + vpnStatus.getLong("proxy_analyzed_flows", 0L)));

        Button start = button("Korumayi baslat", new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                startService(new Intent(MainActivity.this, CyberDefenseService.class).setAction(CyberDefenseService.ACTION_START));
            }
        });
        root.addView(start);

        Button stop = button("Korumayi duraklat", new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                startService(new Intent(MainActivity.this, CyberDefenseService.class).setAction(CyberDefenseService.ACTION_STOP));
                stopService(new Intent(MainActivity.this, DefenseVpnService.class));
            }
        });
        root.addView(stop);

        root.addView(button("Siki VPN/DNS korumasini ac", new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                enableStrictDnsVpnProtection();
            }
        }));

        root.addView(button("Siki korumayi kapat / uyumlu moda don", new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                disableStrictDnsVpnProtection();
            }
        }));

        root.addView(button("Uyumlu internet modu", new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                new ProtectionPolicyStore(MainActivity.this).setFullVpnForwardingEnabled(false);
                stopService(new Intent(MainActivity.this, DefenseVpnService.class));
                render();
            }
        }));

        root.addView(button("Tam VPN / DNS leak kilidi", new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                new ProtectionPolicyStore(MainActivity.this).setFullVpnForwardingEnabled(true);
                stopService(new Intent(MainActivity.this, DefenseVpnService.class));
                render();
            }
        }));

        root.addView(button("Izin ve VPN kurulumu", new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                startActivity(new Intent(MainActivity.this, OnboardingActivity.class));
            }
        }));

        root.addView(button("Son engellemeyi geri al", new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                new BlocklistStore(MainActivity.this).undoLast();
                render();
            }
        }));

        addSection("Koruma modulleri");
        for (ModelSpec spec : catalog.all()) {
            root.addView(card(
                    spec.title,
                    "Girdi " + spec.inputSize + " | Esik " + String.format(Locale.US, "%.3f", spec.threshold)
                            + " | Dogruluk " + String.format(Locale.US, "%.1f%%", spec.accuracy * 100.0)
            ));
        }

        addSection("Son olaylar");
        List<ThreatEvent> events = threatStore.list();
        if (events.isEmpty()) {
            root.addView(card("Henuz aktif olay yok", "Bir saldiri yakalandiginda bildirim dogrudan mudahale ekranina gider."));
        } else {
            int count = 0;
            for (ThreatEvent event : events) {
                if (count++ >= 8) {
                    break;
                }
                View card = card(event.title, event.target + " | " + event.status + " | " + PolicyAssistantText.notificationSummary(event));
                card.setOnClickListener(v -> {
                    Intent open = new Intent(MainActivity.this, InterventionActivity.class);
                    open.putExtra(InterventionActivity.EXTRA_EVENT_ID, event.id);
                    startActivity(open);
                });
                root.addView(card);
            }
        }

        addSection("Karantina / blok liste");
        BlocklistStore blocklist = new BlocklistStore(this);
        if (blocklist.all().isEmpty() && blocklist.allowList().isEmpty()) {
            root.addView(card("Politika listesi bos", "Engelleme veya guvenli sayma karari burada gorunur."));
        } else {
            for (String value : blocklist.all()) {
                root.addView(card("Engelli", value));
            }
            for (String value : blocklist.allowList()) {
                root.addView(card("Guvenli sayildi", value));
            }
        }
        setContentView(scroll);
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
        TextView view = text(title + "\n" + subtitle, 15, Color.rgb(245, 247, 250), false);
        view.setBackgroundColor(Color.rgb(23, 32, 40));
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
            text.setTypeface(android.graphics.Typeface.DEFAULT_BOLD);
        }
        return text;
    }

    private Button button(String label, View.OnClickListener listener) {
        Button button = new Button(this);
        button.setText(label);
        button.setAllCaps(false);
        button.setOnClickListener(listener);
        return button;
    }

    private void addSpace(int heightDp) {
        View spacer = new View(this);
        root.addView(spacer, new LinearLayout.LayoutParams(1, dp(heightDp)));
    }

    private int dp(int value) {
        return Math.round(value * getResources().getDisplayMetrics().density);
    }
}
