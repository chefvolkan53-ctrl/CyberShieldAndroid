# CyberShield Validation Evidence Summary

Generated from local evidence collection on 2026-06-08.

## Automated Evidence

- Model calibration gate: PASS
- Catalog models checked: 20
- Missing packaged TFLite assets: 0
- Blocking calibration findings: 0
- Release build: PASS
- Manifest static checks:
  - backup disabled
  - app cleartext traffic disabled
  - VPN service protected by Android VPN permission
  - diagnostic/lab activities not exported
- Security update feed probe:
  - URLhaus reachable
  - Spamhaus DROP reachable
  - CISA KEV reachable
  - PhishTank skipped because no API secret is configured

## Device Evidence

- Target device detected through ADB: Samsung Galaxy A56 class device.
- CyberShield package present on device.
- App memory sample was collected.
- Quick field monitor sample was collected for one minute.

Quick sample result:

| Sample | Battery | Process | Memory note |
| --- | --- | --- | --- |
| 1 minute smoke sample | 100% during sample | running | memory stayed measurable through `dumpsys meminfo` |

This is a smoke sample, not the required 24-48 hour production field run.

## AMTSO Safe Feature Check Evidence

AMTSO Android phishing feature-check URL was opened through CyberShield link scanning. CyberShield produced a high-risk phishing notification with user-action buttons.

Observed result:

- Detection surface: phishing URL/link scanner
- Model family: phishing/social URL layer
- User-facing action: domain blocking/intervention prompt
- Status: PASS for safe AMTSO phishing smoke check

Repeat result after built-in AMTSO phishing target hardening:

- URL: `https://www.amtso.org/feature-settings-check-phishing-page-for-android-based-solutions/`
- Result: CyberShield raised a high-risk phishing/threat-intel event for `amtso.org`.
- Status: PASS

AMTSO Android malware and drive-by pages were launched for manual feature-check flow. Full pass/fail still requires observing whether the APK download/install path is blocked or raises a CyberShield event on the device.

Update after APK download hardening:

- Added APK download monitoring through Android DownloadManager completion events.
- Added MediaStore Downloads observation for recently created `.apk` files.
- Added public Downloads file watching when Android "all files access" is granted.
- Added pre-install APK feature extraction for downloaded APK content when Android grants file access.
- Added AMTSO Android malware/download page handling as a safe test-threat signal.
- Added built-in AMTSO/EICAR Android APK test target blocking for standards validation only.
- General downloaded APK handling now uses the Android malware TFLite model result, not only host blocklists. APK files from any source are feature-extracted before install; high-risk model scores raise a quarantine action and, when public Downloads access is available, the APK is moved out of Downloads.
- Deduplication now uses model + target, so a phishing warning for a host does not suppress a separate APK download warning for the same host.
- Android limitation remains: CyberShield cannot silently cancel another app's download or delete another app's file without user-approved action/storage access. The app now raises intervention and quarantine/block actions as soon as the download/link layer is visible to CyberShield.

Observed device result after hardening:

- Chrome direct URL tested: `https://amtso.eicar.org/com.amtso.mobiletestfile.apk`
- Result: AMTSO APK was not left in `/sdcard/Download`.
- Requirement: Android all-files access is needed for file-level quarantine of APKs downloaded by other apps.

False-positive hardening result:

- Clean local APK tested: CyberShield release APK copied to `/sdcard/Download/clean-local.apk`.
- Result: the file remained in Downloads and no clean-APK malware notification was observed.
- Added guardrail: CyberShield does not quarantine its own package archive and only auto-quarantines downloaded APKs when the TFLite verdict is actionable, the risk is very high, and static APK signals support the verdict. AMTSO safe test APKs remain handled as explicit test-threat targets.
- Status: PASS for clean local APK smoke check.

## VPN, DNS and Network Field Evidence

VPN/DNS leak smoke test was run from the device browser after enabling CyberShield protection.

Observed evidence:

- Android Private DNS mode: `opportunistic`.
- Private DNS specifier: empty/null.
- CyberShield VPN service was active through Android VPN service binding.
- ADB connectivity dump still exposed the Wi-Fi resolver as `192.168.254.254`, so ADB-only evidence does not prove complete DNS-leak elimination.

Status: LIMITED. Browser-visible DNS leak results must be checked on-device after each VPN/DNS build. This smoke run verifies the service path is active, but it is not a production-grade no-leak certificate.

Current Wi-Fi/ARP observation:

- SSID: `KYBELE`
- Device IP: `192.168.254.4`
- Gateway: `192.168.254.254`
- Gateway MAC observed in `/proc/net/arp`: `6c:3b:6b:5b:0a:2e`
- No live ARP spoof, Evil Twin or deauth lab attack was generated during this run.

Status: PASS for passive baseline observation, LIMITED for attack coverage. Controlled ARP spoof, DNS spoof, Evil Twin and deauth tests require a separate lab access point/attacker device.

## Secure Update Evidence

Remote update manifest and feed were downloaded from the configured GitHub update channel.

Observed result:

- Manifest version: `2026.06.07.2302`
- Feed ID: `threat_intel`
- Expected SHA-256: `49fd1ad98df7aa665848755c6e1a7c8d809cb4a94551298c8d28811a16b75a3b`
- Actual SHA-256: `49fd1ad98df7aa665848755c6e1a7c8d809cb4a94551298c8d28811a16b75a3b`
- Signature field present: yes
- Status: PASS for remote feed hash integrity. Signature verification is enforced in-app by `SecurityUpdateVerifier`.

Security posture note:

- `SecurityUpdateReceiver`, `SecurityUpdateActivity` and diagnostic/test activities are not externally exported in the production APK. This prevents arbitrary third-party apps from forcing update or lab flows through Android intents.

## Performance Smoke Evidence

Short device sample during active testing:

- Total PSS: about 74 MB.
- Java heap: about 35 MB.
- Native heap: about 17 MB.
- Battery level during sample: 100%, USB powered.
- One transient CPU sample showed CyberShield activity during active testing; this is not enough for product battery claims.

Status: PASS for basic smoke stability, LIMITED for production performance. A 24-48 hour field run is still required for battery, CPU, network load and false-positive evidence.

## Remaining Evidence Needed

- 24-48 hour field monitor CSV using `tools/android_field_monitor.py`
- Benign URL/SMS/APK false-positive corpus run
- Controlled DNS spoof and ARP spoof lab replay
- APK install/download AMTSO result should be repeated from the device UI after every major APK-monitoring change
- Independent OWASP MASVS/MASA-style review

## Evidence Handling

Raw evidence is intentionally not committed because it may contain device-specific dumps, logs or screenshots. Local raw evidence is written under `validation-evidence/`, which is ignored by Git.
