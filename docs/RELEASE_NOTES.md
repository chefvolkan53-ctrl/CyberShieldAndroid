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
- `wifi_threat_detector.tflite` eklendi; ARP Poison/flood, WPA3 SAE/downgrade, Evil Twin, deauth/disassoc, beacon flood, DNS spoofing, SSL stripping ve CIC/CAP ag CSV'lerinden 916.777 ornekle egitildi.
- `WifiThreatMonitor` eklendi; SSID/BSSID/RSSI, gateway MAC, ARP tablo oynakligi ve Wi-Fi izinli Android sinyallerinden 48 feature uretir.
- Telefon-ustu mudahale guclendirildi: supheli Wi-Fi strict VPN modu, otomatik VPN baslatma, DNS sorgu adi bloklama, URL-domain normalizasyonu ve HTTP downgrade engelleme eklendi.
- `android_malware_flow_detector.tflite` eklendi; CIC-AndMal2017_raw altindaki 2.131 CSV okundu, flow uyumlu 2.127 CSV'den 900.000 dengeli ornekle Android malware ag davranisi destek modeli egitildi.

### Dogrulama

- Samsung Galaxy A56 uzerinde release APK kuruldu.
- Beklenen TFLite self-test sonucu: 19/19 model OK.
- SMS ve bildirim izinleri granted.
- Link scanner uyarisi bildirim ve mudahale aksiyonlariyla dogrulandi.
- Galaxy A56 saha testinde `Native VPN forwarding kutuphanesi: true` ve `VPN modu: full_device_forwarding` dogrulandi.
- `tun0` aktif goruldu ve TCP 443 baglanti testi basarili oldu. ICMP/ping tun2socks tarafindan tasinmadigi icin beklenen sekilde basarisizdir.

### Bilinen uretim notu

Tam internet forwarding arm64-v8a icin paketlendi. Diger ABI'ler icin native `.so` eklenmedikce uygulama guvenli telemetri moduna geri duser.

Wi-Fi Threat Detector veri seti icinde cok yuksek skor verir; Android normal uygulamalari ham 802.11 monitor-mode frame okuyamadigi icin sahada deauth/beacon/Evil Twin sinyalleri dolayli SSID/BSSID/RSSI/gateway/ARP belirtileriyle izlenir.
