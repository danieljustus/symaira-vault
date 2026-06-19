## What's changed

### Features
- #494 Add redacted self-hosted audit evidence export (+7 more) — closes #484, #487, #488, #489, #490, #491, #492, #493
- #502 Concurrent file I/O and authorization middleware extraction — closes #498, #499

### Security
- #476 Fix argon2id passphrase handling, KDF migration safety, and related cleanup — closes #472, #473, #474, #475
- #483 v0.6.1 security hardening — 6 vulnerabilities — closes #477, #478, #479, #480, #481, #482
- #501 Strengthen session cache, add MCP rate-limiting, improve error messages — closes #495, #496, #497

### Fixes
- #471 Fix smoke test init + corekit v0.1.1 upgrade

### Documentation
- #486 Add post-quantum transition plan — closes #485

### Dependencies
- #470 Bump the go-dependencies group with 3 updates

### CI
- #469 Use SYMVAULT_PASSPHRASE env var in smoke tests

**Full Changelog**: https://github.com/danieljustus/symaira-vault/compare/v0.6.0...v0.7.0
