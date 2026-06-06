package com.monster.cybershield.core;

import java.util.Locale;

public final class PolicyAssistantText {
    private PolicyAssistantText() {
    }

    public static String actionLabel(String action) {
        if ("temporary_block".equals(action)) return "1 saatlik gecici engel";
        if ("block_domain".equals(action)) return "Domain erisimini kes";
        if ("block_ip".equals(action)) return "IP erisimini kes";
        if ("block_flow".equals(action)) return "Riskli ag akisini kes";
        if ("quarantine".equals(action)) return "Karantinaya al";
        if ("uninstall_prompt".equals(action)) return "Kaldirma onayi iste";
        if ("allow".equals(action)) return "Guvenli olarak isaretle";
        if ("explain_only".equals(action)) return "Incele ve kayda al";
        return "Izle ve bilgilendir";
    }

    public static String notificationSummary(ThreatEvent event) {
        String percent = String.format(Locale.US, "%.0f%%", event.probability * 100.0);
        return percent + " risk | " + actionLabel(event.recommendedAction);
    }

    public static String assistantBrief(ThreatEvent event) {
        return "CyberShield Asistani: " + recommendationSentence(event)
                + " " + reasonSentence(event)
                + " " + rollbackSentence(event.recommendedAction);
    }

    public static String assistantDetail(ThreatEvent event) {
        return recommendationSentence(event)
                + "\n\nGerekce: " + reasonSentence(event)
                + "\n\nEtkisi: " + impactSentence(event.recommendedAction)
                + "\n\nGeri alma: " + rollbackSentence(event.recommendedAction);
    }

    private static String recommendationSentence(ThreatEvent event) {
        String target = event.target == null || event.target.trim().isEmpty() ? "hedef" : event.target;
        String action = event.recommendedAction;
        if ("mitm_arp".equals(event.modelId)) {
            if ("temporary_block".equals(action) || "block_flow".equals(action)) {
                return "Bu Wi-Fi aginda olasi MITM/ARP spoofing belirtisi var; " + target + " icin gecici koruma ve VPN uzerinden devam etmeyi oneriyorum.";
            }
            return "Bu Wi-Fi agi icin gateway kimligi izlenmeli; hassas islemlerden once VPN korumasini acmani oneriyorum.";
        }
        if ("temporary_block".equals(action)) {
            return target + " icin kalici karar vermeden once 1 saatlik gecici engel oneriyorum.";
        }
        if ("block_domain".equals(action)) {
            return target + " domain erisimi kesilmeli; risk DNS/link davranisi uzerinden yukselmis gorunuyor.";
        }
        if ("block_ip".equals(action)) {
            return target + " IP erisimi kesilmeli; ayni hedefe tekrar eden riskli baglanti engellenir.";
        }
        if ("block_flow".equals(action)) {
            return target + " ag akisi kesilmeli; bu karar yalnizca ilgili baglantiya uygulanir.";
        }
        if ("quarantine".equals(action)) {
            return target + " karantinaya alinmali; ag erisimi sinirlanarak yayilma riski dusurulur.";
        }
        if ("uninstall_prompt".equals(action)) {
            return target + " icin kaldirma onayi istenmeli; Android son karari kullaniciya birakir.";
        }
        if ("allow".equals(action)) {
            return target + " simdilik guvenli sayilabilir; yine de olay gecmiste kayitli tutulur.";
        }
        if ("explain_only".equals(action)) {
            return target + " icin otomatik engelleme yerine inceleme ve kayit oneriyorum.";
        }
        return target + " icin kullaniciyi bilgilendirip izlemeyi oneriyorum; su an otomatik engelleme icin yeterli kesinlik yok.";
    }

    private static String reasonSentence(ThreatEvent event) {
        String model = event.modelId == null ? "ilgili model" : event.modelId;
        String source = event.source == null ? "otomatik koruma" : event.source;
        String percent = String.format(Locale.US, "%.1f%%", event.probability * 100.0);
        if ("mitm_arp".equals(event.modelId)) {
            return "Gateway/ARP kural motoru ve MITM risk modeli " + source + " kaynaginda " + percent + " risk hesapladı; bu sinyal gateway MAC degisimi, ARP tablo oynakligi veya ayni kimligin birden fazla hedefle gorunmesi gibi belirtilerden uretilir.";
        }
        if (event.probability >= 0.85) {
            return model + " modeli " + source + " kaynaginda cok yuksek risk (" + percent + ") verdi.";
        }
        if (event.probability >= 0.65) {
            return model + " modeli " + source + " kaynaginda yuksek risk (" + percent + ") verdi.";
        }
        if (event.probability >= 0.40) {
            return model + " modeli orta seviye risk (" + percent + ") verdi; yanlis alarm ihtimali korunarak sinirli mudahale secildi.";
        }
        return model + " modeli dusuk/erken sinyal (" + percent + ") verdi; bu nedenle kayit ve izleme daha uygun.";
    }

    private static String impactSentence(String action) {
        if ("temporary_block".equals(action)) return "Hedef gecici blok listesine eklenir ve sure dolunca karar geri alinabilir.";
        if ("block_domain".equals(action)) return "VPN/DNS politikasi uygunsa domain erisimi engellenir.";
        if ("block_ip".equals(action)) return "VPN/firewall politikasi uygunsa IP erisimi engellenir.";
        if ("block_flow".equals(action)) return "Yalnizca riskli ag akisi engellenir; tum internet trafigi kapatilmaz.";
        if ("quarantine".equals(action)) return "Hedef blok listesine alinir ve tekrar baglanti kurmasi sinirlanir.";
        if ("uninstall_prompt".equals(action)) return "Sistem kaldirma ekrani acilir; uygulama kullanici onayi olmadan silinmez.";
        if ("allow".equals(action)) return "Hedef guvenli listeye alinir ve ayni hedef icin yeni uyarilar azalir.";
        if ("explain_only".equals(action)) return "Engelleme uygulanmaz; olay gecmisinde denetlenebilir kayit tutulur.";
        return "Engelleme uygulanmaz; tekrar eden sinyal olursa daha guclu mudahale onerilir.";
    }

    private static String rollbackSentence(String action) {
        if ("allow".equals(action)) return "Guvenli listeden kaldirarak eski koruma davranisina donebilirsin.";
        if ("warn".equals(action) || "explain_only".equals(action)) return "Bu karar bir engel uygulamaz, geri alma gerektirmez.";
        return "Olay gecmisinden veya blok listesinden hedefi kaldirarak karar geri alinabilir.";
    }
}
