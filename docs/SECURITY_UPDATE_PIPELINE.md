# CyberShield Security Update Pipeline

CyberShield does not train models on the phone. The app downloads only tested and signed security packages:

- threat intelligence feeds: malicious domains, IPs, phishing patterns, DoH endpoints, risky ports
- TFLite model files
- feature metadata JSON files
- model catalog and threshold updates

## Device Rules

- Updates are checked automatically once per day.
- Default mode is Wi-Fi only.
- Model downloads over mobile data are blocked unless explicitly allowed by the package.
- Low battery postpones background checks.
- Every downloaded package must use HTTPS.
- Every downloaded package must pass SHA-256 and ECDSA signature verification.
- Threshold changes in the manifest are applied only when the manifest uses a signed payload.
- Broken packages are rejected before activation.
- Active files are replaced atomically and old built-in assets remain the fallback path.

## Manifest Location

The app checks:

`https://raw.githubusercontent.com/chefvolkan53-ctrl/CyberShieldAndroid/main/security-updates/model_update_manifest.json`

The initial manifest intentionally contains no packages. Publish signed packages through GitHub Releases or another HTTPS endpoint, then add their URL, SHA-256 and signature to the manifest.

## Automatic Feed Updates

GitHub Actions runs `.github/workflows/security-threat-feed.yml` once per day and can also be started manually from the GitHub Actions tab.

The workflow:

1. Fetches external threat sources.
2. Builds an unsigned `security-updates/threat_intel.json` artifact in a read-only job.
3. Enters the `security-update-signing` environment.
4. Signs the feed with the private update key stored in a protected GitHub secret.
5. Rebuilds `security-updates/model_update_manifest.json`.
6. Pushes the signed feed and manifest to a short-lived update branch.
7. Opens a pull request into `main`, so branch protection and Code Owner review still apply before Android devices can see the new manifest.

Required GitHub secret or protected environment secret:

- `CYBERSHIELD_UPDATE_PRIVATE_KEY`: contents of `C:\Users\Monster\Desktop\CyberShield_Update_Signing_PrivateKey_PKCS8.pem`

Recommended location:

- `Settings -> Environments -> security-update-signing -> Environment secrets`
- Do not keep a duplicate repository-level copy of this secret.

Recommended environment protection:

- required reviewer: `chefvolkan53-ctrl`
- deployment branches: `main` only

Recommended `main` branch protection:

- require pull requests before merge
- require at least 1 approval
- require Code Owner review
- require the `build-feed` status check
- require branches to be up to date before merge
- keep force pushes and branch deletion disabled

Optional GitHub secrets:

- `URLHAUS_AUTH_KEY`: enables authenticated URLhaus recent CSV export.
- `PHISHTANK_APP_KEY`: enables PhishTank online-valid feed.

Without optional secrets, the workflow still uses sources that are reachable without credentials and records skipped sources in `source_status`.

## Threat Feed Schema

```json
{
  "version": "2026.06.08",
  "malicious_domains": ["example-bad.test"],
  "malicious_ips": ["203.0.113.66"],
  "malicious_cidrs": ["203.0.113.0/24"],
  "phishing_patterns": ["login-verify", "wallet-confirm"],
  "doh_endpoints": ["dns.example.test"],
  "risky_ports": [22, 23, 445, 1433, 5900]
}
```

## Manifest Package Entry

Generate package hash and signature:

```powershell
java tools/SignSecurityUpdatePackage.java .\security-updates\threat_intel.json C:\Users\Monster\Desktop\CyberShield_Update_Signing_PrivateKey_PKCS8.pem
```

```json
{
  "id": "threat_intel",
  "version": "2026.06.08",
  "url": "https://github.com/chefvolkan53-ctrl/CyberShieldAndroid/releases/download/security-2026.06.08/threat_intel.json",
  "sha256": "hex_sha256_here",
  "signature": "base64_ecdsa_signature_here"
}
```

For models, use the model id from `model_catalog.json`:

```json
{
  "id": "stealth_phisher_2025",
  "version": "2026.06.08",
  "url": "https://github.com/chefvolkan53-ctrl/CyberShieldAndroid/releases/download/models-2026.06.08/stealth_phisher_2025.tflite",
  "sha256": "hex_sha256_here",
  "signature": "base64_ecdsa_signature_here",
  "metadata": {
    "name": "social_url_metadata.json",
    "url": "https://github.com/chefvolkan53-ctrl/CyberShieldAndroid/releases/download/models-2026.06.08/social_url_metadata.json",
    "sha256": "hex_sha256_here",
    "signature": "base64_ecdsa_signature_here"
  }
}
```

## Signing Key

The app contains only the public verification key. The private signing key was created locally and must not be committed.

Local private key path:

`C:\Users\Monster\Desktop\CyberShield_Update_Signing_PrivateKey_PKCS8.pem`

Keep this file offline or in a secure secret store. If it leaks, rotate the public key in the app and publish a new release.

GitHub hardening checklist:

`docs/GITHUB_HARDENING.md`
