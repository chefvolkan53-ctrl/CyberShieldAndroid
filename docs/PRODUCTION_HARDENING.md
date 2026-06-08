# CyberShield Production Hardening Notes

## Applied

- Release signing no longer uses the Android debug keystore.
- Release signing is supplied from owner-controlled local or CI secrets.
- Release builds enable code and resource shrinking.
- Diagnostic and laboratory screens are not exported in production.
- App-owned cleartext traffic is disabled through network security configuration.
- VPN traffic handling avoids local routing loops.
- Full protection mode mirrors relevant flow metadata into the threat engine.
- Unknown network feature handling avoids synthetic noise that could distort model input.

## Release Signing Configuration

Preferred CI environment variables:

```text
CYBERSHIELD_KEYSTORE
CYBERSHIELD_KEYSTORE_PASSWORD
CYBERSHIELD_KEY_ALIAS
CYBERSHIELD_KEY_PASSWORD
```

Local signing files and keystores must never be committed.

## Production Build

```powershell
$env:JAVA_HOME='C:\Program Files\Android\Android Studio\jbr'
$env:Path="$env:JAVA_HOME\bin;$env:Path"
.\gradlew.bat assembleRelease --no-daemon
```

## Remaining Hardening Before Public Distribution

- Run AMTSO Android feature checks and attach screenshots/results privately.
- Run long-duration stability and battery impact tests on target devices.
- Run false-positive tests for benign URLs, SMS texts, APKs and routine network traffic.
- Review notification text and stored event contents for privacy.
- Consider Play Integrity and app integrity checks for public distribution.
- Consider root/tamper detection as advisory signals only, not hard blockers.

## Public Documentation Rule

Production hardening docs should not expose exact test activity names, local file paths, model thresholds, feature maps or bypass-oriented exception lists.
