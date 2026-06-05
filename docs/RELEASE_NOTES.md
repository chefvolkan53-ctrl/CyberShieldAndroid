# Release Notes

## v0.1.0

### Eklenenler

- 14 TFLite model Android asset olarak paketlendi.
- Model katalog sistemi eklendi: input boyutu, esik, accuracy, recall ve mudahale politikasi merkezi JSON dosyasinda tutulur.
- Foreground `CyberDefenseService` ile otomatik savunma servisi eklendi.
- SMS, link/metin, APK kurulumu ve VPN paket kaynaklari modele baglandi.
- DNS/DoH parser ve flow tabanli Network/IoT feature uretimi eklendi.
- Android malware modeli icin 9503 boyutlu cihaz-ustu feature uretimi guclendirildi.
- Kullanici onayli mudahale ekrani eklendi: engelle, gecici engelle, karantinaya al, guvenli say, kaldirma sistem ekranina git.
- Blok liste, gecici blok, whitelist ve geri alma mekanizmasi eklendi.
- Onboarding ekrani: bildirim, SMS, VPN, pil optimizasyonu ve Samsung arka plan ayarlari.
- Self-test ve saha test aktiviteleri eklendi.
- Profesyonel launcher/adaptive icon eklendi.

### Dogrulama

- Samsung Galaxy A56 uzerinde release APK kuruldu.
- TFLite self-test sonucu: 14/14 model OK.
- SMS ve bildirim izinleri granted.
- Link scanner uyarisi bildirim ve mudahale aksiyonlariyla dogrulandi.

### Bilinen uretim notu

Tam internet forwarding icin native `tun2socks`/NAT katmani gerekir. Mevcut surum TUN okuma, parser, flow feature, model ve politika motorunu hazirlar; native forwarding eklendiginde tam VPN bloklama uretim seviyesine tasinir.
