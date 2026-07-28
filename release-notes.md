## What's Changed

### Features
- #661 feat: add native macOS vault client — native SwiftUI app for unlock, search, TOTP, create, edit, and delete workflows
- #665 feat(mcp): surface vault directory in whoami responses
- #670 feat: make secret consumption discoverable for agents that only see a reference
- #673 feat: ephemeral file injection for run_command (files map) — store PKCS#12 certificates and other seekable files as vault entries, materialized ephemerally on command execution
- #674 feat: symvault file add/get/use CLI commands for certificate/key attachments — store, retrieve, and consume binary attachments (ELSTER .pfx, etc.) without manual decoding
- #693 feat(doctor): add diagnostics for unsafe environment passphrase unlocking
- #702 feat: Add proactive local secret-leak detection at process and output boundaries — exact-value, pattern, and entropy-heuristic scanning with strict mode and metadata-only audit events
- #706 feat(audit): per-entry HMAC key generation ID (kid) for rotation-safe verification — distinguishes Unverifiable (missing key generation) from Tampered (content mismatch)

### Fixes
- #669 fix: stop inferring certificate type from path for non-self-identifying values — a path containing "certificate" no longer promotes a passphrase to SecretTypeCertificate
- #681 fix(deps): update google.golang.org/grpc to v1.82.1 — fixes GHSA-hrxh-6v49-42gf (CVSS 8.8, authorization bypass + DoS)
- #692 fix(cli): make environment passphrase unlocking explicit opt-in via SYMVAULT_ALLOW_ENV_PASSPHRASE
- #699 fix(secrets): reject sensitive-named env vars even when explicitly requested — fail-closed over trusting caller intent
- #703 fix: macOS: parallel agents and tests no longer trigger native Keychain dialog for "wrap-key"
- #705 fix(admin): make symvault init use argon2id for new vaults (was silently using legacy scrypt)
- #707 fix(audit): fix test-isolation bug in ReloadConfig cleanup ordering — fixes test flakiness under -shuffle=on
- #710 fix(deps): bump js-yaml 4.2.0 → 4.3.0, brace-expansion → 1.1.16 — closes Dependabot alerts #6 and #5 (DoS via YAML merge-key chains and brace expansion)

### Refactors
- #709 refactor(update): delegate cosign/extract/installmethod to symaira-corekit — reduces maintenance surface by reusing corekit's generalized updatecheck packages

### Maintenance
- #687 chore(ci): bump actions/setup-go from 6.5.0 to 7.0.0
- #688 chore(ci): bump actions/checkout from 7.0.0 to 7.0.1
- #686/#689/#690 chore(ci): bump github/codeql-action/* from 4.37.0 to 4.37.3
- #691 chore(deps): bump go-dependencies group (aws-sdk-go-v2, prometheus client_golang/common)
- #712 test(cmd/file): add unit tests for add/get/use CLI commands (coverage 0% → 86.8%)

### Closed Issues
- #662 Deferred dependency audit: golang/protobuf v1.5.4 still present
- #664 Surface vault directory in whoami responses
- #666 Certificate type inference from path
- #667 Secret consumption discoverability for agents
- #671 Ephemeral file injection for run_command
- #672 CLI commands for file attachments
- #675 Make environment passphrase unlocking explicit opt-in
- #676 Zeroize cached passphrase on cleanup
- #677 Doctor diagnostics for unsafe env passphrase
- #678 Hermetic passphrase-source tests
- #679 Remove unsafe env-passphrase from CLI guidance
- #680 Proactive local secret-leak detection
- #682 macOS keychain dialog for "wrap-key"
- #683 Default scrypt work factor below dynamic recommendation
- #684 KDF migration inconsistency
- #685 Audit: missing HMAC key generation reported as tampered
- #694 Harden child-process environment passphrase whitelist
- #695 Output-scanning redaction core
- #696 Strict blocking mode and metadata-only audit
- #697 Entropy heuristic pattern layer
- #698 Document leak detection limits
- #700 Opt-in env-passphrase in export/import tests
- #704 symvault init uses argon2id for new vaults
- #708 Delegate update mechanism to corekit
- #711 Test coverage for cmd/file commands
- GHSA-hrxh-6v49-42gf (grpc authorization bypass)
- 2 Dependabot alerts (js-yaml, brace-expansion)

**Full Changelog**: https://github.com/danieljustus/symaira-vault/compare/v0.10.1...v0.11.0
