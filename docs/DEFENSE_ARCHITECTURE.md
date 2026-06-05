# CyberShield Defense Architecture

## Tasarim hedefleri

CyberShield, manuel laboratuvar araci olarak degil, arka planda otomatik calisan ve kritik aksiyonlarda kullanici onayi isteyen profesyonel bir savunma uygulamasi olarak tasarlanmistir.

Oncelikler:

- Dusuk pil, RAM ve CPU kullanimi.
- Offline TFLite inference.
- Kaynak bazli model calistirma.
- Bildirimden dogrudan mudahale ekranina gecis.
- Engelleme/karantina/guvenli sayma kararlarinin geri alinabilir olmasi.

## Kaynak baglayicilari

| Kaynak | Android bileseni | Model hattı |
| --- | --- | --- |
| SMS | `SmsThreatReceiver` | Social text, URL, phishing |
| Paylasilan link/metin | `LinkScanActivity` | Social URL, social text, phishing |
| APK kurulumu/degisimi | `PackageThreatReceiver` | Android malware |
| VPN paketleri | `DefenseVpnService` | DNS, DoH L1/L2, Network, IoT, TLS/PQC |
| Flow istatistikleri | `FlowTracker` | Network 79, IoT 71, anomaly/PQC |

## Karar akisi

1. Kaynak bileseni sinyali yakalar.
2. `FeatureExtractor` ve `FeatureSchema` modelin bekledigi boyutta feature uretir.
3. `ThreatEngine` ilgili TFLite modelini olay bazli yukler.
4. Model skoru `model_catalog.json` icindeki esik ve politika ile karsilastirilir.
5. Aksiyon gerekiyorsa `CyberDefenseService` mudahale bildirimi uretir.
6. Bildirime tiklaninca `InterventionActivity` olay detayina acilir.
7. Kullanici onayina gore blok, gecici blok, karantina, guvenli sayma veya kaldirma intent'i uygulanir.

## Politika ve guvenlik

- Destructive islem kullanici onaysiz uygulanmaz.
- Kaldirma islemi Android sistem uninstall ekranina devredilir.
- Blok/karantina hedefleri app storage icinde saklanir.
- Whitelist karari model uyarilarini bastirabilir.
- Son karar geri alinabilir.

## VPN durumu

Mevcut VPN servisinde:

- TUN arayuzu acilir.
- IPv4, TCP, UDP ve DNS paketleri parse edilir.
- DNS/DoH tespitleri modele verilir.
- Flow bazli paket/byte/sure/flag istatistikleri tutulur.
- Blok listeye dusen hedefler analiz/mudahale tarafinda engelleme politikasina alinir.

Tam uretim seviyesi internet yonlendirme icin eksik native parca:

- `0.0.0.0/0` route.
- TUN'dan internete TCP/UDP forwarding.
- NAT/session mapping.
- Native `tun2socks` veya esdeger kullanici-uzayi TCP/IP stack.

Bu katman eklendiginde mevcut model/politika motoru domain/IP/port bazli gercek bloklamayi uretim seviyesinde uygulayabilir.
