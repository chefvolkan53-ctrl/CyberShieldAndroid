package com.monster.cybershield;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.Intent;
import android.graphics.Color;
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

    private ThreatEvent event;
    private ThreatStore store;

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
        }
        render();
    }

    private void render() {
        ScrollView scroll = new ScrollView(this);
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(dp(20), dp(20), dp(20), dp(20));
        root.setBackgroundColor(Color.rgb(16, 20, 24));
        scroll.addView(root);

        TextView title = text(event.title, 24, Color.WHITE, true);
        root.addView(title);
        root.addView(text("Kaynak: " + event.source, 14, Color.rgb(169, 182, 194), false));
        root.addView(text("Hedef: " + event.target, 14, Color.rgb(169, 182, 194), false));
        root.addView(text("Model: " + event.modelId, 14, Color.rgb(169, 182, 194), false));
        root.addView(text("Risk: " + String.format(Locale.US, "%.1f%%", event.probability * 100.0), 18, Color.rgb(245, 165, 36), true));
        root.addView(text("Zaman: " + DateFormat.getDateTimeInstance().format(new Date(event.createdAt)), 14, Color.rgb(169, 182, 194), false));
        root.addView(text("Durum: " + event.status, 14, Color.rgb(32, 201, 151), true));

        addSpace(root, 18);
        root.addView(button("Engelle", new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                confirmBlock();
            }
        }));
        root.addView(button("1 saat gecici engelle", new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                InterventionActions.temporaryBlock(InterventionActivity.this, event);
                Toast.makeText(InterventionActivity.this, "Gecici engel kaydedildi", Toast.LENGTH_SHORT).show();
                event = store.find(event.id);
                render();
            }
        }));
        root.addView(button("Karantinaya al", new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                confirmQuarantine();
            }
        }));
        root.addView(button("Kaldir", new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                confirmRemove();
            }
        }));
        root.addView(button("Uygulama ayarlarina git", new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                startActivity(InterventionActions.appSettingsIntent(event));
            }
        }));
        root.addView(button("Guvenli say", new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                InterventionActions.allow(InterventionActivity.this, event);
                Toast.makeText(InterventionActivity.this, "Olay guvenli olarak isaretlendi", Toast.LENGTH_SHORT).show();
                finish();
            }
        }));
        root.addView(button("VPN engelleme iznini ac", new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                Intent vpnIntent = VpnService.prepare(InterventionActivity.this);
                if (vpnIntent != null) {
                    startActivity(vpnIntent);
                } else {
                    startService(new Intent(InterventionActivity.this, DefenseVpnService.class));
                }
            }
        }));

        setContentView(scroll);
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

    private TextView text(String value, int sp, int color, boolean bold) {
        TextView text = new TextView(this);
        text.setText(value);
        text.setTextColor(color);
        text.setTextSize(sp);
        text.setGravity(Gravity.START);
        text.setPadding(0, dp(6), 0, dp(6));
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
        button.setPadding(0, dp(8), 0, dp(8));
        return button;
    }

    private void addSpace(LinearLayout root, int dp) {
        View spacer = new View(this);
        root.addView(spacer, new LinearLayout.LayoutParams(1, dp(dp)));
    }

    private int dp(int value) {
        return Math.round(value * getResources().getDisplayMetrics().density);
    }
}
