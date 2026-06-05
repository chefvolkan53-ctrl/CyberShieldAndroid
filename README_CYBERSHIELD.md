# CyberShield Android

CyberShield otomatik calisan, kullanici onayli mudahale yapan moduler bir Android siber savunma uygulamasidir.

## Bu ilk surumde hazir olanlar

- 14 TFLite model `assets/models` altinda paketlenir.
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
- `SourceFieldTestActivity`: ADB ile cagrilabilen gizli saha testi; SMS izni, APK receiver, link scanner, VPN izin durumu ve 9503 APK feature uretimini raporlar.

## Android gercegi

Android, kullanici onayi olmadan baska uygulamalari silemez veya tum agi sessizce ele geciremez. Bu yuzden:

- Kaldirma islemi sistem uninstall onayi ile yapilir.
- Ag engelleme icin VPN izni gerekir.
- Destructive aksiyonlar kullanici onayi ile uygulanir.

## Uretim siniri

Android'de tum TCP/UDP trafigini interneti bozmadan 0.0.0.0/0 VPN uzerinden gecirmek icin kullanici-uzayi TCP/IP forwarding veya native `tun2socks` katmani gerekir. Bu makinedeki Android SDK'da NDK klasoru yok; bu yuzden native forwarding kutuphanesi derlenemedi. Bu projede guvenli TUN okuma, DNS/DoH/parser, flow tabanli feature uretimi, model baglantisi ve politika uygulamasi hazirdir; tam NAT/forwarding icin NDK veya guvenilir prebuilt native forwarding katmani eklenmelidir.

Mevcut VPN rotalari test/guvenli modda tutulur. Tum internet rotasi acilmadan once forwarding katmani tamamlanmalidir.
