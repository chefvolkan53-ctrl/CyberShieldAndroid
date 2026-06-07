# CyberShield Android

CyberShield otomatik calisan, kullanici onayli mudahale yapan moduler bir Android siber savunma uygulamasidir.

## Bu ilk surumde hazir olanlar

- 18 TFLite model `assets/models` altinda paketlenir.
- `model_catalog.json` model esiklerini, giris boyutlarini ve mudahale politikasini tutar.
- `CyberDefenseService` foreground servis olarak arka planda dusuk guc profilinde calisir.
- Tehdit bildirimi, ilgili `InterventionActivity` ekranina dogrudan gider.
- Mudahale secenekleri: engelle, karantinaya al, kaldirma sistem ekranina git, uygulama ayarlarina git, guvenli say.
- Engelleme/karantina kararlari kalici blok listeye yazilir.
- Telefon yeniden basladiginda servis tekrar acilir.
- `OnboardingActivity`: bildirim, SMS, VPN, pil optimizasyonu ve Samsung arka plan ayarlari icin kurulum akisi.
- `ThreatEngine`: SMS/metin, link, APK/paket ve VPN paket kaynaklarini ilgili modellere baglar.
- `FeatureSchema`: DNS/DoH/network/IoT/Post-Quantum metadata dosyalarindan kolon sirasi ve scaler bilgisi okur.
- `FlowTracker`: VPN paketlerinden 5-tuple flow olusturur; sure, paket/byte sayisi, pps/bps, TCP flag, DNS/DoH yogunlugu gibi degerleri biriktirir.
- Politika motoru: kalici blok, 1 saat gecici blok, whitelist/guvenli say, son karari geri alma.
- `LinkScanActivity`: paylasilan metin veya acilan URL icin sosyal muhendislik/phishing modellerini calistirir.
- `SmsThreatReceiver`: gelen SMS metnini sosyal muhendislik modellerine yollar.
- `PackageThreatReceiver`: gercek APK kurulum/degisim broadcast'i geldiginde Android malware modelini tetikler.
- Android malware 9503 feature uretimi paket adi hash'i ile sinirli degil; manifest izinleri, activity/service/receiver/provider sayilari, debuggable/system flag'leri, cleartext flag'i ve supheli izin gruplari modele verilir.
- `DefenseVpnService`: VPN TUN paketlerini okur, IPv4/UDP/TCP/DNS parser ile DNS/DoH modellerine ve flow tabanli Network/IoT/TLS/PQC analizine baglar, blok/whitelist politikasini uygular.
- `libcybershield_forwarder.so`: arm64-v8a native tun2socks motoru olarak paketlenir; VPN izni verildiginde tam cihaz rotasini TCP/UDP forwarding ile internete tasir.
- `DirectSocksProxy`: native motorun yerel SOCKS cikisini karsilar, `VpnService.protect()` ile donguye girmeyen outbound soket acar ve blok listedeki domain/IP/port akislarini dusurur.
- `SourceFieldTestActivity`: ADB ile cagrilabilen gizli saha testi; SMS izni, APK receiver, link scanner, VPN izin durumu ve 9503 APK feature uretimini raporlar.
- `PolicyInterventionModel`: CyberShield policy TFLite modelini yukler; olay tipi, kaynak, risk ve hedef sinyallerinden profesyonel mudahale onerisi uretir.
- `PolicyAssistantText`: ham aksiyon adlarini kullaniciya anlamli guvenlik diline cevirir; bildirim ve mudahale ekraninda gerekce, etki ve geri alma bilgisini gosterir.
- `MitmArpMonitor`: Wi-Fi gateway MAC degisimi, ayni IP icin birden fazla MAC, ARP tablo dalgalanmasi, local-admin MAC ve broadcast/zero MAC gibi sinyalleri 32 feature olarak MITM/ARP TFLite modeline verir.
- Wi-Fi MITM / ARP spoofing modulunde kural tabanli skor ile model riski birlestirilir; supheli Wi-Fi agini isaretleme, VPN korumasini zorunlu onerme ve gecici blok aksiyonlari desteklenir.
- `WifiThreatMonitor`: SSID/BSSID, RSSI, guvenlik tipi, gateway MAC, `/proc/net/arp`, BSSID degisimi ve baglanti oynakligindan 48 feature uretir; ARP poison/flood, WPA3 SAE/downgrade, Evil Twin, deauth/disassoc, beacon flood, DNS spoofing ve SSL stripping veri setleriyle egitilen `wifi_threat_detector.tflite` modelini calistirir.
- `StealthPhisher2025`: 59 sayisal URL/HTML/sezgisel ozellikle modern phishing altyapilarini, IPFS/kisa link/Google Sites benzeri barindirma izlerini, form/parola sinyallerini ve entropy/obfuscation degerlerini analiz eder.
- `FlowStats` ve `FeatureSchema`: network/IoT modelleri icin TCP flag, TTL, window, IAT, active/idle, forward/backward packet/byte ve payload/header istatistiklerini veri seti kolon adlarina daha birebir map eder.
- APK feature cikarimi, PackageInfo sinyallerine ek olarak APK zip entry, dex, native lib, asset, sertifika ve sinirli statik string sinyallerini kullanir.
- `ModelCalibrationStore` ve `CalibrationActivity`: lab/saha testinden sonra model esiklerini kalici olarak ayarlamak ve TP/FP/FN/TN sayaclarini tutmak icin eklendi.
- Son beklenen cihaz self-test sonucu: 18/18 model OK.

## Android gercegi

Android, kullanici onayi olmadan baska uygulamalari silemez veya tum agi sessizce ele geciremez. Bu yuzden:

- Kaldirma islemi sistem uninstall onayi ile yapilir.
- Ag engelleme icin VPN izni gerekir.
- Destructive aksiyonlar kullanici onayi ile uygulanir.

## Uretim siniri

Android'de tum TCP/UDP trafigini interneti bozmadan 0.0.0.0/0 VPN uzerinden gecirmek icin kullanici-uzayi TCP/IP forwarding veya native `tun2socks` katmani gerekir. Bu surumde arm64-v8a icin `libcybershield_forwarder.so` paketlendi ve Galaxy A56 uzerinde `full_device_forwarding` modu dogrulandi.

Native motor yuklenemez veya baslatilamazsa uygulama telefonu internetsiz birakmamak icin guvenli telemetri rotalarina geri duser. ICMP/ping forwarding desteklenmez; gercek dogrulama TCP/UDP trafikle yapilir.

## Son guncelleme

- CyberShield Policy Assistant TFLite modeli uygulamaya eklendi.
- Wi-Fi MITM / ARP Spoofing icin hibrit kural + TFLite savunma modulu eklendi.
- Wi-Fi Threat Detector modeli eklendi; `C:\Users\Monster\Desktop\wifi` altindaki ARP Poison/flood, MachineLearningCVE, TrafficLabelling, Cap_1_10VM_1Apache ve WPA3 saldiri CSV'lerinden 916.777 ornekle egitildi.
- StealthPhisher2025 URL/HTML heuristic TFLite modeli uygulamaya eklendi.
- Network/IoT feature cikarimi CICFlowMeter tarzina daha yakin hale getirildi.
- Android APK feature cikarimi zip/dex/native lib/string sinyalleriyle guclendirildi.
- Kalibrasyon aktivitesi ve kalici threshold store eklendi.
- Native VPN forwarding arm64-v8a icin paketlendi; tam cihaz rotasi, yerel SOCKS koprusu, `VpnService.protect()` ve guvenli fallback akisi eklendi.
- TensorFlow Lite runtime `2.17.0` surumune cikarildi.
- Bildirimlerde ham "uyar" gibi ifadeler yerine profesyonel mudahale aciklamasi, risk gerekcesi ve geri alma bilgisi kullanilir.
- Android normal uygulamalari monitor-mode 802.11 frame okuyamadigi icin Wi-Fi Threat Detector sahada ham deauth/beacon frame yerine Android'in erisebildigi SSID/BSSID/RSSI/gateway/ARP/VPN-DNS belirtileriyle calisir; gercek Galaxy A56 saha kalibrasyonu onerilir.
- StealthPhisher2025 modelinde ham `URL`, `Domain`, `TLD` stringleri ve dis skor gibi duran `WAPLegitimate/WAPPhishing` alanlari modele alinmadi; uretilebilir 59 numeric feature kullanildi.
