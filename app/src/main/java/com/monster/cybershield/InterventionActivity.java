package com.monster.cybershield;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.Intent;
import android.graphics.Color;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.net.VpnService;
import android.os.Bundle;
import android.view.Gravity;
import android.view.View;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import com.monster.cybershield.core.InterventionActions;
import com.monster.cybershield.core.PolicyAssistantText;
import com.monster.cybershield.core.ThreatEvent;
import com.monster.cybershield.core.ThreatStore;

import java.text.DateFormat;
import java.util.Date;
import java.util.Locale;

public class InterventionActivity extends Activity {
    public static final String EXTRA_EVENT_ID = "event_id";
    public static final String EXTRA_ACTION = "action";
    public static final String ACTION_BLOCK = "block";
    public static final String ACTION_QUARANTINE = "quarantine";
    public static final String ACTION_TEMPORARY_BLOCK = "temporary_block";
    public static final String ACTION_REMOVE = "remove";
    public static final String ACTION_REQUIRE_VPN = "require_vpn";
    private static final int REQ_VPN = 501;

    private ThreatEvent event;
    private ThreatStore store;
    private static final int BG = Color.rgb(11, 18, 24);
    private static final int SURFACE = Color.rgb(22, 31, 39);
    private static final int SURFACE_SOFT = Color.rgb(29, 41, 51);
    private static final int TEXT = Color.rgb(239, 246, 252);
    private static final int MUTED = Color.rgb(158, 174, 187);
    private static final int DANGER = Color.rgb(220, 53, 69);
    private static final int WARNING = Color.rgb(245, 158, 11);
    private static final int OK = Color.rgb(32, 201, 151);
    private static final int ACCENT = Color.rgb(56, 189, 248);

    @Override
    protected void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        store = new ThreatStore(this);
        event = store.find(getIntent().getStringExtra(EXTRA_EVENT_ID));
        if (event == null) {
            finish();
            return;
        }
        String action = getIntent().getStringExtra(EXTRA_ACTION);
        if (ACTION_BLOCK.equals(action)) {
            confirmBlock();
        } else if (ACTION_QUARANTINE.equals(action)) {
            confirmQuarantine();
        } else if (ACTION_TEMPORARY_BLOCK.equals(action)) {
            confirmTemporaryBlock();
        } else if (ACTION_REMOVE.equals(action)) {
            confirmRemove();
        } else if (ACTION_REQUIRE_VPN.equals(action)) {
            requestVpnPermission();
        }
        render();
    }

    private void render() {
        ScrollView scroll = new ScrollView(this);
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(dp(18), dp(18), dp(18), dp(24));
        root.setBackgroundColor(BG);
        scroll.addView(root);

        root.addView(text("CyberShield", 13, ACCENT, true));
        root.addView(text("Mudahale merkezi", 28, TEXT, true));
        root.addView(text("Bu olay icin uygulanabilir kararlar asagida. Tehlikeli veya yikici islemler Android onayi olmadan otomatik yapilmaz.", 14, MUTED, false));
        addSpace(root, 14);

        LinearLayout risk = panel();
        risk.addView(text(event.title, 22, TEXT, true));
        risk.addView(text(riskLabel() + " | " + String.format(Locale.US, "%.1f%%", event.probability * 100.0), 18, riskColor(), true));
        risk.addView(text("Hedef", 12, MUTED, true));
        risk.addView(text(event.target, 15, TEXT, false));
        risk.addView(text("Kaynak: " + event.source + " | Model: " + event.modelId, 13, MUTED, false));
        risk.addView(text("Durum: " + readableStatus(event.status) + " | " + DateFormat.getDateTimeInstance().format(new Date(event.createdAt)), 13, MUTED, false));
        root.addView(risk);

        addSpace(root, 10);
        LinearLayout actions = panel();
        actions.addView(text("Mudahale secenekleri", 17, TEXT, true));
        actions.addView(actionButton(PolicyAssistantText.actionLabel(event.recommendedAction), colorForAction(event.recommendedAction), new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                runRecommendedAction();
            }
        }));
        actions.addView(actionButton("Engelle", DANGER, new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                confirmBlock();
            }
        }));
        actions.addView(actionButton("1 saat gecici engelle", WARNING, new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                confirmTemporaryBlock();
            }
        }));
        actions.addView(actionButton("Karantinaya al", Color.rgb(147, 51, 234), new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                confirmQuarantine();
            }
        }));
        actions.addView(actionButton("Kaldirma ekranini ac", Color.rgb(239, 68, 68), new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                confirmRemove();
            }
        }));
        actions.addView(actionButton("VPN korumasini zorunlu kil", ACCENT, new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                requestVpnPermission();
            }
        }));
        actions.addView(actionButton("Guvenli say", OK, new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                InterventionActions.allow(InterventionActivity.this, event);
                Toast.makeText(InterventionActivity.this, "Olay guvenli olarak isaretlendi", Toast.LENGTH_SHORT).show();
                event = store.find(event.id);
                render();
            }
        }));
        root.addView(actions);

        addSpace(root, 10);
        LinearLayout primary = panel();
        primary.addView(text("Onerilen mudahale gerekcesi", 17, TEXT, true));
        primary.addView(text(PolicyAssistantText.assistantDetail(event), 14, Color.rgb(219, 234, 246), false));
        root.addView(primary);

        addSpace(root, 10);
        LinearLayout tools = panel();
        tools.addView(text("Ek araclar", 17, TEXT, true));
        tools.addView(secondaryButton("Uygulama ayarlarina git", new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                startActivity(InterventionActions.appSettingsIntent(event));
            }
        }));
        tools.addView(secondaryButton("Kapat", v -> finish()));
        root.addView(tools);

        setContentView(scroll);
    }

    private void runRecommendedAction() {
        String action = event.recommendedAction == null ? "" : event.recommendedAction;
        if (ACTION_QUARANTINE.equals(action) || "quarantine".equals(action)) {
            confirmQuarantine();
        } else if (ACTION_TEMPORARY_BLOCK.equals(action) || "temporary_block".equals(action)) {
            confirmTemporaryBlock();
        } else if (ACTION_REMOVE.equals(action) || "uninstall_prompt".equals(action)) {
            confirmRemove();
        } else if (ACTION_REQUIRE_VPN.equals(action) || "require_vpn".equals(action)) {
            requestVpnPermission();
        } else if ("warn".equals(action) || "explain_only".equals(action) || "allow".equals(action) || "mark_wifi_suspicious".equals(action)) {
            Toast.makeText(this, "Olay izlendi, otomatik engel uygulanmadi", Toast.LENGTH_SHORT).show();
        } else {
            confirmBlock();
        }
    }

    private void confirmBlock() {
        new AlertDialog.Builder(this)
                .setTitle("Engelleme uygulanacak")
                .setMessage(event.target + " hedefi blok listesine eklenecek. VPN korumasi aciksa trafik engellenir.")
                .setPositiveButton("Engelle", (dialog, which) -> {
                    InterventionActions.block(this, event);
                    Toast.makeText(this, "Engelleme kaydedildi", Toast.LENGTH_SHORT).show();
                    event = store.find(event.id);
                    render();
                })
                .setNegativeButton("Vazgec", null)
                .show();
    }

    private void confirmQuarantine() {
        new AlertDialog.Builder(this)
                .setTitle("Karantina uygulanacak")
                .setMessage("Hedefin ag erisimi karantinaya alinacak. Uygulama kaldirma islemi icin ayrica sistem onayi gerekir.")
                .setPositiveButton("Karantina", (dialog, which) -> {
                    InterventionActions.quarantine(this, event);
                    Toast.makeText(this, "Karantina kaydedildi", Toast.LENGTH_SHORT).show();
                    event = store.find(event.id);
                    render();
                })
                .setNegativeButton("Vazgec", null)
                .show();
    }

    private void confirmTemporaryBlock() {
        new AlertDialog.Builder(this)
                .setTitle("Gecici engelleme uygulanacak")
                .setMessage(event.target + " hedefi 1 saat gecici blok listesine eklenecek. Olay gecmisinden geri alinabilir.")
                .setPositiveButton("1 saat engelle", (dialog, which) -> {
                    InterventionActions.temporaryBlock(this, event);
                    Toast.makeText(this, "Gecici engel kaydedildi", Toast.LENGTH_SHORT).show();
                    event = store.find(event.id);
                    render();
                })
                .setNegativeButton("Vazgec", null)
                .show();
    }

    private void confirmRemove() {
        new AlertDialog.Builder(this)
                .setTitle("Kaldirma onayi")
                .setMessage("Android guvenligi geregi uygulama kaldirma islemi sistem onayi ile yapilir.")
                .setPositiveButton("Sistem kaldirma ekranini ac", (dialog, which) -> {
                    store.mark(event.id, InterventionActions.STATUS_REMOVE_REQUESTED);
                    startActivity(InterventionActions.uninstallIntent(event));
                })
                .setNegativeButton("Vazgec", null)
                .show();
    }

    private void requestVpnPermission() {
        Intent vpnIntent = VpnService.prepare(this);
        if (vpnIntent != null) {
            Toast.makeText(this, "Android VPN onay ekranini aciyorum", Toast.LENGTH_SHORT).show();
            startActivityForResult(vpnIntent, REQ_VPN);
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
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode == REQ_VPN) {
            if (resultCode == RESULT_OK) {
                startDefenseVpn();
            } else {
                Toast.makeText(this, "VPN izni verilmedi", Toast.LENGTH_LONG).show();
            }
        }
    }

    private TextView text(String value, int sp, int color, boolean bold) {
        TextView text = new TextView(this);
        text.setText(value);
        text.setTextColor(color);
        text.setTextSize(sp);
        text.setGravity(Gravity.START);
        text.setPadding(0, dp(6), 0, dp(6));
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
        button.setPadding(0, dp(10), 0, dp(10));
        button.setBackground(rounded(color));
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
        params.setMargins(0, dp(5), 0, dp(5));
        layout.setLayoutParams(params);
        return layout;
    }

    private GradientDrawable rounded(int color) {
        GradientDrawable drawable = new GradientDrawable();
        drawable.setColor(color);
        drawable.setCornerRadius(dp(8));
        return drawable;
    }

    private int riskColor() {
        if (event.probability >= 0.85) {
            return DANGER;
        }
        if (event.probability >= 0.65) {
            return WARNING;
        }
        return OK;
    }

    private String riskLabel() {
        if (event.probability >= 0.85) {
            return "Kritik risk";
        }
        if (event.probability >= 0.65) {
            return "Yuksek risk";
        }
        return "Izleme sinyali";
    }

    private int colorForAction(String action) {
        if ("quarantine".equals(action)) {
            return Color.rgb(147, 51, 234);
        }
        if ("temporary_block".equals(action)) {
            return WARNING;
        }
        if ("warn".equals(action) || "explain_only".equals(action) || "allow".equals(action)) {
            return SURFACE_SOFT;
        }
        return DANGER;
    }

    private String readableStatus(String status) {
        if (InterventionActions.STATUS_BLOCKED.equals(status)) return "engellendi";
        if (InterventionActions.STATUS_QUARANTINED.equals(status)) return "karantinada";
        if (InterventionActions.STATUS_TEMP_BLOCKED.equals(status)) return "gecici engelli";
        if (InterventionActions.STATUS_ALLOWED.equals(status)) return "guvenli sayildi";
        if (InterventionActions.STATUS_REMOVE_REQUESTED.equals(status)) return "kaldirma istendi";
        return "mudahale bekliyor";
    }

    private void addSpace(LinearLayout root, int dp) {
        View spacer = new View(this);
        root.addView(spacer, new LinearLayout.LayoutParams(1, dp(dp)));
    }

    private int dp(int value) {
        return Math.round(value * getResources().getDisplayMetrics().density);
    }

}
