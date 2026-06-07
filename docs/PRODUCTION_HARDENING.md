# CyberShield Production Hardening Notes

## Applied

- Release signing no longer uses Android debug keystore.
- Release signing is read from environment variables or `~/.android/cybershield-release.properties`.
- Release build enables R8 minification and resource shrinking.
- Test/diagnostic activities are no longer exported:
  - `SelfTestActivity`
  - `AttackSimulationActivity`
  - `SourceFieldTestActivity`
  - `CalibrationActivity`
- App-owned cleartext traffic is disabled through `network_security_config`.
- VPN sockets are protected from VPN loops in `DirectSocksProxy`.
- Full VPN forwarding traffic is mirrored into `ThreatEngine` through `ProxyTrafficMirror`.
- `FeatureSchema` no longer injects synthetic hash noise into unknown network feature columns.

## Release Signing Configuration

Preferred CI environment variables:

```text
CYBERSHIELD_KEYSTORE
CYBERSHIELD_KEYSTORE_PASSWORD
CYBERSHIELD_KEY_ALIAS
CYBERSHIELD_KEY_PASSWORD
```

Local fallback:

```text
%USERPROFILE%\.android\cybershield-release.properties
```

The local fallback file must not be committed.

## Production Build

```powershell
$env:JAVA_HOME='C:\Program Files\Android\Android Studio\jbr'
$env:Path="$env:JAVA_HOME\bin;$env:Path"
.\gradlew.bat assembleRelease --no-daemon
```

## Remaining Hardening Before Public Distribution

- Run AMTSO Android feature checks and attach screenshots/results.
- Run at least one 24-hour stability pass on the target Samsung device.
- Run local false-positive tests for benign URLs, SMS texts, and APKs.
- Add privacy review for notification text and stored event contents.
- Consider Play Integrity / app integrity checks if distributing publicly.
- Consider root/tamper detection as advisory signals only, not as hard blockers.
