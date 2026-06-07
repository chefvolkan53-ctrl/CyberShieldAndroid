# GitHub Hardening Checklist

This repository contains security tooling and an update pipeline. Keep GitHub itself hardened.

## Already Added In Repository

- Critical file ownership through `.github/CODEOWNERS`.
- Split threat feed workflow:
  - unsigned feed generation has read-only permissions
  - signing/publishing is isolated in `security-update-signing`
  - write permission exists only in the signing job
- Signed package verification on Android.
- Public key in app, private key only in secret/offline storage.
- Security policy in `SECURITY.md`.

## Required GitHub Settings

Enable these manually in GitHub because they are repository/account settings, not normal source files.

### Account Security

1. Enable 2FA on the GitHub account.
2. Review active sessions and remove unknown devices.
3. Use a strong password and password manager.

### Branch Protection For `main`

Go to:

`Settings -> Branches -> Add branch protection rule`

Use:

- Branch name pattern: `main`
- Require a pull request before merging
- Require approvals: at least `1`
- Require review from Code Owners
- Require status checks to pass before merging
- Require branches to be up to date before merging
- Restrict force pushes
- Restrict deletions
- Do not allow bypassing the above settings unless you intentionally need emergency owner access

### Protected Environment

Go to:

`Settings -> Environments -> New environment`

Create:

`security-update-signing`

Recommended rules:

- Required reviewers: `chefvolkan53-ctrl`
- Deployment branches: selected branches only -> `main`
- Optional wait timer: 5 minutes

Then keep this secret in that environment or repository Actions secrets:

`CYBERSHIELD_UPDATE_PRIVATE_KEY`

The safest option is the protected environment secret, because the signing job cannot access it until the environment approval passes.

## If A Secret Leaks

1. Delete the leaked secret from GitHub.
2. Generate a new ECDSA signing key.
3. Replace the public key in `SecurityUpdateVerifier`.
4. Publish a new APK.
5. Re-sign future update packages with the new private key.
6. Treat old update packages as untrusted.

## Public Repository Note

Open source visibility helps auditing, but attackers can read the architecture. The security boundary must therefore be:

- private signing key stays private
- branch protection prevents silent pipeline changes
- update packages are signed
- app rejects unsigned or hash-mismatched packages
