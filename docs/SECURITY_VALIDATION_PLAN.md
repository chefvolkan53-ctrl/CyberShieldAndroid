# CyberShield Security Validation Plan

This document defines the safe validation path for CyberShield before any production claim.

## Safe External Feature Checks

Use AMTSO Security Features Check tools because they are designed to verify security product behavior without introducing real malware.

Required Android checks:

- AMTSO Android manually downloaded malware test.
- AMTSO Android phishing page test.
- AMTSO Android potentially unwanted application test, if available for the current platform flow.
- AMTSO Android drive-by download test, if available for the current browser/device flow.

Expected CyberShield behavior:

- Link/phishing tests should trigger `social_url`, `phishing_html`, or `stealth_phisher_2025`.
- APK download/install tests should trigger `android_malware` after package install or shared APK analysis.
- If a target is blocked, `InterventionActivity` must show user-approved actions.
- If full VPN/DNS protection is enabled, `VPN analiz motoru` should show non-zero proxy/mirror/flow counters after network activity.

## AV-TEST Style Local Measurement

AV-TEST evaluates Android security products using real-time malware detection, common malware detection, usability, battery impact, device slowdown, network load, and false alarms. CyberShield must not claim comparable certification without an independent lab, but the same categories should be measured locally.

Local test matrix:

- Malware detection: benign APK set and known-safe test APKs only unless using an isolated lab.
- Phishing detection: AMTSO phishing plus internal benign URL corpus.
- False alarms: at least 500 benign URLs, 100 benign SMS texts, 50 known-safe APKs.
- Performance: foreground launch latency, VPN throughput, DNS latency, browser page-load time.
- Battery: 30-minute idle, 30-minute browsing, 30-minute full VPN mode.
- Network load: proxy mirrored bytes, native rx/tx, DNS query count, blocked count.

Pass criteria for pre-production:

- No app crash during 24-hour background monitoring.
- Self-test reports `modelsFailed=0`.
- Full VPN mode shows proxy connections and mirrored flow counters after browsing.
- DNS leak test shows only the selected resolver family, not ISP DNS.
- False positive rate is documented and reviewed before lowering thresholds.

## OWASP MASVS / MASA Preparation

CyberShield should be reviewed against the following MASVS groups:

- MASVS-STORAGE: sensitive data is not stored in world-readable locations.
- MASVS-CRYPTO: signing keys and secrets are not committed to the repository.
- MASVS-NETWORK: app-owned connections avoid cleartext; VPN sockets use `VpnService.protect()`.
- MASVS-PLATFORM: exported components are minimized; user consent is required for destructive actions.
- MASVS-CODE: release build uses minification and production signing.
- MASVS-RESILIENCE: debug surfaces are disabled in production; future work should add root/tamper signals.
- MASVS-PRIVACY: notifications and logs should avoid sensitive message contents.

MASA/independent review status:

- Not certified.
- Ready for preparatory review after production signing, exported activity hardening, and validation evidence collection.

## Android Platform Boundaries

CyberShield cannot honestly claim these capabilities without root, device owner, MDM, or router integration:

- Silent uninstall of another app.
- Removing an attacker from a router.
- Writing router firewall rules.
- Quarantining another physical device on the LAN.
- Blocking traffic outside Android's VPN/user-consent model.

CyberShield can do:

- User-approved uninstall prompt.
- VPN/DNS/proxy-based block and quarantine for traffic routed through CyberShield.
- Suspicious Wi-Fi marking.
- User notification with explainable intervention choices.
- APK, SMS, link, DNS, DoH, Wi-Fi and proxy-flow risk scoring.

## Official References Checked

- AMTSO Security Features Check: https://www.amtso.org/security-features-check/
- AMTSO Android manually downloaded malware check: https://www.amtso.org/feature-settings-check-download-of-malware-for-android-based-solutions/
- OWASP MASVS: https://mas.owasp.org/MASVS/
- App Defense Alliance MASA: https://appdefensealliance.dev/masa
- MASA requirements: https://appdefensealliance.dev/masa/masa-requirements
