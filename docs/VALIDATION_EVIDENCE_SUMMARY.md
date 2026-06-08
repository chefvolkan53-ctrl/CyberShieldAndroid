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

AMTSO Android malware and drive-by pages were launched for manual feature-check flow. Full pass/fail still requires observing whether the APK download/install path is blocked or raises a CyberShield event on the device.

Update after APK download hardening:

- Added APK download monitoring through Android DownloadManager completion events.
- Added MediaStore Downloads observation for recently created `.apk` files.
- Added pre-install APK feature extraction for downloaded APK content when Android grants file access.
- Added AMTSO Android malware/download page handling as a safe test-threat signal.
- Deduplication now uses model + target, so a phishing warning for a host does not suppress a separate APK download warning for the same host.
- Android limitation remains: CyberShield cannot silently cancel another app's download or delete another app's file without user-approved action/storage access. The app now raises intervention and quarantine/block actions as soon as the download/link layer is visible to CyberShield.

## Remaining Evidence Needed

- 24-48 hour field monitor CSV using `tools/android_field_monitor.py`
- Benign URL/SMS/APK false-positive corpus run
- Controlled DNS spoof and ARP spoof lab replay
- APK install/download AMTSO result confirmed from device UI after the download hardening build
- Independent OWASP MASVS/MASA-style review

## Evidence Handling

Raw evidence is intentionally not committed because it may contain device-specific dumps, logs or screenshots. Local raw evidence is written under `validation-evidence/`, which is ignored by Git.
