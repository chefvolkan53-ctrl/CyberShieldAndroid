# CyberShield Android

Bu dosya onceki ayrintili teknik notlarin public-safe ozetidir. Ayrintili model esikleri, feature sayilari, yerel veri seti yollari, test activity isimleri ve operasyonel zayiflik notlari public repoda tutulmaz.

## Hazir Olan Ana Bilesenler

- Cihaz uzerinde calisan TFLite tabanli tehdit tespit katmani.
- Arka plan koruma servisi ve olay bazli model calistirma.
- SMS/metin, URL, APK, VPN/DNS ve Wi-Fi kaynaklarindan sinyal toplama.
- Kullanici onayli mudahale ekrani ve aksiyonlu bildirimler.
- Blok liste, gecici blok, guvenli sayma ve geri alma politikasi.
- DNS leak protection ve yerel VPN koruma modu.
- Imzali online guvenlik guncellemesi altyapisi.
- Release build hardening ve public/private secret ayrimi.

## Kapsanan Tehdit Alanlari

- Android malware ve supheli APK davranisi
- Phishing URL/HTML
- Sosyal muhendislik mesajlari
- DNS/DoH riski
- Network anomaly
- IoT/Mirai davranisi
- Wi-Fi MITM/ARP ve supheli ag sinyalleri
- TLS/session ve post-kuantum anomali sinyalleri
- Threat-intelligence destek sinyalleri

## Mudahale Yaklasimi

CyberShield yikici islemleri kullanici onayi olmadan uygulamaz. Android platform sinirlari geregi uygulama kaldirma sistem onayi ile yapilir; ag korumasi Android VPN iznine baglidir. Router veya baska fiziksel cihazlara zorlayici mudahale root/MDM/router entegrasyonu olmadan yapilmaz.

## Guvenlik Notu

Public repo sadece guvenli mimari ozetini icermelidir. Operasyonel esikler, model kolon sirasi, false-positive istisnalari, saha kalibrasyon verileri ve private key/keystore bilgileri public dokumana eklenmemelidir.
