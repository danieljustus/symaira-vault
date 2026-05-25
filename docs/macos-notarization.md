# macOS Notarization Setup Guide

## Status: BLOCKED — Apple Developer ID Required

This document outlines the steps needed to enable macOS notarization for Symaira Vault releases.

## Prerequisites

1. **Apple Developer Program Membership** ($99/year)
   - Enroll at: https://developer.apple.com/programs/
   - Required for: Developer ID Application certificate + notarization access

2. **Developer ID Application Certificate**
   - Create in Apple Developer Portal → Certificates, Identifiers & Profiles
   - Download and install in Keychain
   - Export as .p12 file for CI use

3. **App Store Connect API Key**
   - Create at: https://appstoreconnect.apple.com/access/api
   - Needs "Developer" role
   - Download .p8 private key file
   - Note the Key ID and Issuer ID

## GitHub Secrets Required

Add these secrets to the Symaira Vault repository:

| Secret Name | Value |
|-------------|-------|
| `APPLE_DEVELOPER_ID_CERTIFICATE` | Base64-encoded .p12 certificate |
| `APPLE_DEVELOPER_ID_CERTIFICATE_PASSWORD` | Password for the .p12 file |
| `APPLE_API_KEY_ID` | App Store Connect API Key ID |
| `APPLE_API_ISSUER_ID` | App Store Connect API Issuer ID |
| `APPLE_API_KEY_BASE64` | Base64-encoded .p8 private key |

## GoReleaser Configuration

Add the following to `.goreleaser.yml` after the `builds:` section:

```yaml
# macOS code signing and notarization
# Requires Apple Developer ID (see docs/macos-notarization.md)
# Uncomment and configure the following after obtaining credentials:

# macos:
#   signing:
#     enabled: true
#     identity: "Developer ID Application: Your Name (TEAM_ID)"
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
spctl -a -t exec -vv /path/to/openpass

# Expected output:
# /path/to/openpass: accepted
# source=Notarized Developer ID
```

## References

- [GoReleaser macOS documentation](https://goreleaser.com/customization/macos/)
- [Apple Notarization Guide](https://developer.apple.com/documentation/security/notarizing-macos-software-before-distribution)
- Code-Audit §10.1

## Current Blocker

**As of 2026-05-07**: Apple Developer ID not available. This item is prepared but cannot be activated until credentials are obtained.
