# CyberShield Public Model Card

## Amac

CyberShield model seti, Android cihaz uzerinde dusuk gecikmeli ve offline calisabilen siber savunma sinyalleri uretmek icin tasarlanmistir. Sistem tek bir model yerine domain bazli coklu model yaklasimi kullanir.

## Kapsam

Public model kapsami:

- Android malware ve APK riski
- Android uygulama ag davranisi
- Mirai/IoT davranislari
- DNS ve DoH riskleri
- Network anomaly
- Phishing URL/HTML
- Sosyal muhendislik metinleri
- Wi-Fi MITM/ARP ve supheli ag sinyalleri
- TLS/session ve post-kuantum anomali sinyalleri
- Threat-intelligence destek sinyalleri
- Olay aciklama ve kullanici onayli mudahale onerisi

## Public Performans Politikasi

Model esikleri, kesin feature sayilari, kolon sirasi, veri seti ic ayrintilari ve zayiflik/kalibrasyon notlari public model card icinde yayinlanmaz. Bu bilgiler saldirgana bypass denemeleri icin gereksiz ipucu verebilir.

Paylasilabilecek guvenli ozet:

- Modeller veri seti testlerinde dogrulanmistir.
- Gercek cihaz trafiginde false-positive takibi ve saha kalibrasyonu gereklidir.
- Yuksek riskli mudahaleler tek model skoruna degil, politika motoru ve kullanici onayina baglanir.
- Bazi modeller dogrudan engelleme yerine destek/aciklama sinyali olarak kullanilir.

## Cihaz Uzerinde Calisma Stratejisi

- Modeller olay bazli calistirilir.
- Inference cihaz uzerinde yapilir.
- Guncel threat intelligence ve model paketleri yalnizca imzali ve hash-dogrulanmis sekilde aktif edilir.
- Guvenilir olmayan veya bozuk paketlerde yerlesik guvenli varliklara geri donulur.

## Sinirlar

- Android platformu root/MDM olmadan sessiz uygulama silme veya router seviyesinde mudahale izni vermez.
- Ag korumasi Android VPN iznine baglidir.
- Wi-Fi saldiri tespiti Android'in uygulamalara sundugu sinyallerle sinirlidir.
- Public skorlar urun guvencesi yerine genel model kapsamini anlatir; operasyonel kalibrasyon private olarak tutulur.
