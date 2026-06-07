package com.monster.cybershield;

import android.app.Activity;
import android.graphics.Color;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.os.Bundle;
import android.view.View;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import com.monster.cybershield.core.SecurityUpdateManager;
import com.monster.cybershield.core.SecurityUpdateScheduler;
import com.monster.cybershield.core.SecurityUpdateStore;

public class SecurityUpdateActivity extends Activity {
    private static final int BG = Color.rgb(11, 18, 24);
    private static final int SURFACE = Color.rgb(22, 31, 39);
    private static final int SURFACE_SOFT = Color.rgb(29, 41, 51);
    private static final int TEXT = Color.rgb(239, 246, 252);
    private static final int MUTED = Color.rgb(158, 174, 187);
    private static final int OK = Color.rgb(32, 201, 151);
    private static final int ACCENT = Color.rgb(56, 189, 248);
    private LinearLayout root;

    @Override
    protected void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        render();
    }

    private void render() {
        SecurityUpdateStore store = new SecurityUpdateStore(this);
        ScrollView scroll = new ScrollView(this);
        root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(dp(18), dp(18), dp(18), dp(24));
        root.setBackgroundColor(BG);
        scroll.addView(root);

        root.addView(text("CyberShield", 13, ACCENT, true));
        root.addView(text("Guvenlik guncellemeleri", 28, TEXT, true));
        root.addView(text("Imzali tehdit veritabani, model ve metadata paketleri burada izlenir.", 14, MUTED, false));
        addSpace(12);

        LinearLayout status = panel();
        status.addView(text("Durum", 18, TEXT, true));
        status.addView(text(store.summary(), 14, OK, false));
        status.addView(text(store.updateDetails(), 14, TEXT, false));
        root.addView(status);

        root.addView(actionButton("Simdi kontrol et", OK, new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                Toast.makeText(SecurityUpdateActivity.this, "Guncelleme kontrol ediliyor", Toast.LENGTH_SHORT).show();
                SecurityUpdateScheduler.checkNowAsync(SecurityUpdateActivity.this, true, new SecurityUpdateScheduler.Callback() {
                    @Override
                    public void onResult(SecurityUpdateManager.Result result) {
                        runOnUiThread(new Runnable() {
                            @Override
                            public void run() {
                                Toast.makeText(SecurityUpdateActivity.this, result.success ? result.status : result.status + ": " + result.error, Toast.LENGTH_LONG).show();
                                render();
                            }
                        });
                    }
                });
            }
        }));
        root.addView(actionButton("Savunma merkezine don", SURFACE_SOFT, new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                finish();
            }
        }));

        setContentView(scroll);
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

    private void addSpace(int heightDp) {
        View spacer = new View(this);
        root.addView(spacer, new LinearLayout.LayoutParams(1, dp(heightDp)));
    }

    private int dp(int value) {
        return Math.round(value * getResources().getDisplayMetrics().density);
    }
}
