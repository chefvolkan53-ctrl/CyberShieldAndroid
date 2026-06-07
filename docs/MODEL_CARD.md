# CyberShield Model Card

## Amac

Bu model seti, Android cihaz uzerinde offline ve dusuk gecikmeli siber savunma yapmak icin tasarlanmistir. Tek bir model yerine domain bazli coklu model mimarisi kullanilir. Bu tercih, her veri kaynaginin farkli feature uzayi ve farkli mudahale politikasina sahip olmasindan kaynaklanir.

## Veri kaynaklari ve egitim yaklasimi

| Domain | Kaynak tipi | Egitim yaklasimi | Android tarafindaki sinyal |
| --- | --- | --- | --- |
| Android malware | CSV/statik APK feature | 9503 feature ile binary/family tahmini | Manifest izinleri, component sayilari, app flag'leri, paket meta verisi |
| Mirai | Mirai/Iot malware CSV | Manifest/behavior odakli siniflandirma | IoT/Mirai risk sinyali |
| DNS | DNS stateful CSV | Binary attack/benign ayrimi | DNS query, port, uzunluk, entropy, domain seviyesi |
| DoH L1 | DoH/non-DoH CSV | Ilk seviye DoH algilama | TCP/443 ve DoH benzeri flow sinyali |
| DoH L2 | Malicious DoH CSV | Zararli DoH binary modeli | Malicious probability, esik 0.2879624069 |
| Social engineering | SMS/metin/URL CSV | Metin davranisi ve URL feature modelleri | Urgency, fear, reward, bank/login/OTP sinyalleri |
| Phishing | HTML/URL CSV | 40 feature phishing modeli | Form, parola, iframe, script, mixed-content |
| Network | Network attack CSV | 79 flow feature | Paket/byte, sure, pps/bps, TCP flag, endpoint |
| Wi-Fi Threat | ARP Poison/flood, WPA3 attacks, CIC/CAP Wi-Fi/network CSV | 48 Android-uyumlu Wi-Fi risk feature | SSID/BSSID/RSSI, gateway MAC, ARP tablo oynakligi, DNS/HTTP downgrade ipuclari |
| IoT/IIoT | IoT/IIoT attack CSV | 71 flow/endpoint feature | Flow ve endpoint izolasyon karari |
| TLS/PQC | Attack/Post-Quantum CSV | Session/anomaly/taxonomy modelleri | TLS/DoH/PQC session risk aciklamasi |

## Model performans ozeti

| ID | Accuracy | Recall | Esik | Karar rolu |
| --- | ---: | ---: | ---: | --- |
| android_malware | 0.9485 | 0.9707 | 0.5000 | Yararli/zararli APK karari |
| mirai | 0.9963 | 1.0000 | 0.7050 | Mirai/botnet uyarisi |
| network_attack | 0.9585 | 0.9801 | 0.7231 | Flow bazli ag saldirisi |
| dns_stateful | 0.8126 | 0.9936 | 0.5000 | DNS attack yakalama |
| doh_l1 | 0.9923 | 0.9891 | 0.5248 | DoH algilama |
| doh_l2 | 0.9990 | 0.9991 | 0.2880 | Zararli DoH karari |
| social_text | 0.9778 | 0.9622 | 0.1315 | SMS/metin sosyal muhendislik |
| social_url | 0.9767 | 0.9787 | 0.2611 | URL phishing/sosyal muhendislik |
| phishing_html | 0.9062 | 0.9220 | 0.4000 | HTML/link phishing |
| iot_attack | 0.9242 | 0.9882 | 0.5314 | IoT/IIoT saldiri |
| attack_anomaly | 0.9734 | 0.8273 | 0.5000 | TLS/session anomali |
| post_quantum | 0.8488 | 0.9800 | 0.3959 | PQC anomali |
| post_quantum_taxonomy | 0.8330 | N/A | 0.0000 | Aciklama/siniflandirma |
| post_quantum_subtype | 0.8198 | N/A | 0.0000 | Alt tur aciklama |
| wifi_threat | 1.0000* | 1.0000* | 0.6500 | Wi-Fi Evil Twin, ARP/DNS spoofing, deauth/disassoc, beacon flood, SSL stripping riski |

## Siber savunmadaki etkisi

- Yuksek recall modelleri, ozellikle DNS, DoH, IoT ve Android malware alanlarinda saldiriyi kacirmamaya odaklanir.
- Dusuk esik kullanan modellerde false-positive riski saha loglariyla izlenmelidir.
- Taxonomy/subtype modelleri dogrudan engelleme yapmaz; olay aciklamasi ve karar kalitesi icin kullanilir.
- Mudahale mekanizmasi model skorunu tek basina yikici aksiyona cevirmeyip kullanici onayi ile uygular.

## Cihaz uzerinde calisma stratejisi

- Modeller olay bazli yuklenir ve inference sonrasi kapatilir.
- `max_hot_models` politikasi pil/RAM yukunu sinirlamak icin dusuk tutulur.
- TFLite modeller asset olarak paketlenir; internet baglantisi olmadan calisir.
- Feature uretimi Java tarafinda hafif islemlerle yapilir.

## Sinirlar ve kalibrasyon

- Egitim skorlarinin tamamı veri seti icindeki test bolumlerinden gelir; gercek saha trafiginde dagilim farki olabilir.
- Android malware 9503 feature seti Android cihazda manifest/meta veri ile yaklastirilir; tam statik APK disassembler baglanirsa kalite artar.
- Network/IoT feature uretimi flow istatistikleriyle guclendirildi; tam PCAP seviyesinde tum kolonlar icin daha fazla protokol ozelligi eklenebilir.
- Wi-Fi Threat Detector egitim/test ayriminda cok yuksek skor verir; veri seti lab ortaminda etiketleri belirgin oldugu icin saha skorunu abartmamak gerekir.
- Android normal uygulamalari ham 802.11 monitor-mode frame okuyamaz; Wi-Fi saldiri modeli sahada Android'in erisebildigi SSID/BSSID/RSSI/gateway/ARP/VPN-DNS belirtileriyle calisir.
- Tam VPN forwarding icin native forwarding katmani gerekir; arm64-v8a native motor paketlenmistir.
