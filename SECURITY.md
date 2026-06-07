# Security Policy

CyberShield accepts only signed update packages on the device.

## Sensitive Material

Never commit these values:

- `CYBERSHIELD_UPDATE_PRIVATE_KEY`
- URLhaus or PhishTank API keys
- Android release keystore files
- local signing properties

The update private key must exist only in GitHub Actions secrets or in the offline signing location controlled by the owner.

## Update Pipeline Controls

- Threat feed generation runs without write access.
- Signing and publishing runs in the `security-update-signing` environment.
- The signing job has the only workflow-level write permission.
- TFLite/feed/metadata packages must pass SHA-256 and ECDSA verification before the Android app activates them.
- Built-in app assets remain the fallback if an update fails.

## Reporting

Report suspected exposed secrets, malicious update packages, or bypass issues privately to the repository owner.

Do not open public issues containing exploit steps, private keys, access tokens, malware samples, or live malicious links.
