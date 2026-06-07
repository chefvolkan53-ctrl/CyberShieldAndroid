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
- arm64-v8a `libcybershield_forwarder.so` native tun2socks motoru paketlendi.
- `DirectSocksProxy` ile yerel SOCKS cikisi, `VpnService.protect()` ve domain/IP/port bloklama hattı eklendi.
- Native motor basariliysa `0.0.0.0/0` tam cihaz rotasi, basarisizsa guvenli telemetri fallback modu uygulanir.

### Dogrulama

- Samsung Galaxy A56 uzerinde release APK kuruldu.
- TFLite self-test sonucu: 17/17 model OK.
- SMS ve bildirim izinleri granted.
- Link scanner uyarisi bildirim ve mudahale aksiyonlariyla dogrulandi.
- Galaxy A56 saha testinde `Native VPN forwarding kutuphanesi: true` ve `VPN modu: full_device_forwarding` dogrulandi.
- `tun0` aktif goruldu ve TCP 443 baglanti testi basarili oldu. ICMP/ping tun2socks tarafindan tasinmadigi icin beklenen sekilde basarisizdir.

### Bilinen uretim notu

Tam internet forwarding arm64-v8a icin paketlendi. Diger ABI'ler icin native `.so` eklenmedikce uygulama guvenli telemetri moduna geri duser.
