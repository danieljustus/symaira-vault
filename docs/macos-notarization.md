# macOS Notarization Setup Guide

## Status: In Progress — Apple Developer Account Active (Team ID: M4744F3TAA)

This document outlines the steps needed to enable macOS notarization for Symaira Vault releases.

## Prerequisites

1. **Apple Developer Program Membership**
   - Active Apple Developer account (Team ID: `M4744F3TAA`).
   - Required for: Developer ID Application certificate + notarization access.

2. **Developer ID Application Certificate**
   - Create in Apple Developer Portal → Certificates, Identifiers & Profiles.
   - Download and install in Keychain.
   - Export as `.p12` file for CI use.

3. **App Store Connect API Key**
   - Create at: https://appstoreconnect.apple.com/access/api
   - Role: "Developer"
   - Download `.p8` private key file.
   - Note the Key ID and Issuer ID.

## GitHub Secrets Required

Configure the following secrets in the Symaira Vault repository settings (`Settings` → `Secrets and variables` → `Actions`):

| Secret Name | Description / Format | CI Usage |
|-------------|----------------------|----------|
| `APPLE_DEVELOPER_ID_CERTIFICATE` | Base64-encoded `.p12` certificate | Code signing (`Developer ID Application`) |
| `APPLE_DEVELOPER_ID_CERTIFICATE_PASSWORD` | Password for the `.p12` file | Unlocking imported CI keychain |
| `APPLE_API_KEY_ID` | App Store Connect API Key ID (10 alphanumeric characters) | Notarization service authentication |
| `APPLE_API_ISSUER_ID` | App Store Connect API Issuer ID (UUID format) | Notarization service authentication |
| `APPLE_API_KEY_BASE64` | Base64-encoded `.p8` private key | Notarization service authentication |

> **Credential Status:** While the paid Apple Developer account (Team ID: `M4744F3TAA`) is active, repository secrets must be configured in GitHub Secrets before automated notarization in GoReleaser can run. Until these secrets are provisioned, the GoReleaser notarization block remains commented out.

## GoReleaser Configuration

Add the following to `.goreleaser.yml` after the `builds:` section:

```yaml
# macOS code signing and notarization
# Requires Apple Developer ID (see docs/macos-notarization.md)
# Uncomment and configure the following after obtaining credentials:

# macos:
#   signing:
#     enabled: true
#     identity: "Developer ID Application: Your Name (M4744F3TAA)"
#   notarize:
#     enabled: true
#     issuer_id: "{{ .Env.APPLE_API_ISSUER_ID }}"
#     key_id: "{{ .Env.APPLE_API_KEY_ID }}"
#     key: "{{ .Env.APPLE_API_KEY_BASE64 }}"
#     wait: true
#     timeout: 20m
```

## Release Workflow Changes

Add these steps to `.github/workflows/release.yml` before the GoReleaser step:

```yaml
      - name: Import Apple Developer ID certificate
        if: runner.os == 'macOS'
        run: |
          echo "${{ secrets.APPLE_DEVELOPER_ID_CERTIFICATE }}" | base64 -d > developer_id.p12
          security create-keychain -p "" build.keychain
          security import developer_id.p12 -t agg -k build.keychain -P "${{ secrets.APPLE_DEVELOPER_ID_CERTIFICATE_PASSWORD }}" -A
          security list-keychains -s build.keychain
          security default-keychain -s build.keychain
          security unlock-keychain -p "" build.keychain
          security set-keychain-settings -t 3600 -u build.keychain
```

## Verification

After setting up, verify notarization with:

```bash
# Check notarization status
spctl -a -t exec -vv /path/to/symvault

# Expected output:
# /path/to/symvault: accepted
# source=Notarized Developer ID
```

## References

- [GoReleaser macOS documentation](https://goreleaser.com/customization/macos/)
- [Apple Notarization Guide](https://developer.apple.com/documentation/security/notarizing-macos-software-before-distribution)
- Code-Audit §10.1

## Current Status

**As of 2026-08**: Apple Developer account is available (Team ID: `M4744F3TAA`). Automated notarization is prepared and pending repository secrets configuration (`APPLE_DEVELOPER_ID_CERTIFICATE`, `APPLE_DEVELOPER_ID_CERTIFICATE_PASSWORD`, `APPLE_API_KEY_ID`, `APPLE_API_ISSUER_ID`, `APPLE_API_KEY_BASE64`).
