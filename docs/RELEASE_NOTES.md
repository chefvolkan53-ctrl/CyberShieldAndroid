# Release Notes

## v0.1.0

### Eklenenler

- Cihaz uzerinde calisan TFLite tabanli moduler tehdit tespit katmani.
- Arka plan savunma servisi ve olay bazli model calistirma.
- SMS/metin, link, APK, VPN/DNS ve Wi-Fi kaynaklarindan sinyal toplama.
- Kullanici onayli mudahale ekrani.
- Kalici ve gecici engelleme, karantina, guvenli sayma ve geri alma akisları.
- DNS leak protection ve yerel VPN koruma modu.
- Wi-Fi risk izleme ve supheli ag uyarilari.
- Imzali online guvenlik guncellemesi altyapisi.
- Release build hardening ve public/private secret ayrimi.

### Dogrulama

- Release APK hedef Android cihazda kurulum ve temel calisma testinden gecirildi.
- Cihaz uzerinde model yukleme ve inference self-testleri dogrulandi.
- Bildirimden ilgili mudahale ekranina gecis dogrulandi.
- DNS/VPN koruma akisi temel baglanti testleriyle kontrol edildi.

### Bilinen Platform Sinirlari

- Android, root/MDM olmadan sessiz uygulama silme izni vermez.
- Ag korumasi kullanici tarafindan verilen VPN iznine baglidir.
- Wi-Fi saldiri tespiti Android'in uygulamalara sundugu sinyallerle sinirlidir.
- Public release notes model esikleri, veri seti satir sayilari, feature boyutlari ve ic sinif adlari icermez.
