## What's changed

### Security
- #516 Argon2id zero-key self-heal and KDF state from identity.age
- #524 Harden policy storage, MCP policy loading, search isolation, and the gosec gate
- #527 Escape backslashes first in cursor path sanitizer
- #518 Annotate G304 false positive in KDF doctor check
- #543 Fix weak-sensitive-data-hashing in search index — closes #540, #541, #542

### Fixes
- #537 Recipients remove no longer revokes access to existing entries
- #526 Measure password strength by rune count, not byte length

### Added
- #532 Search-index persistence, MCP coverage gate, and server-bootstrap cleanup
- #516 Manifest rebuild capability
- #517 Projects v2 board with Status/Priority/Iteration fields

### Dependencies
- #543 Clean build artifacts and harden Argon2id KDF path

### CI
- #511 Pin docker/* actions and fix invalid github-script pin

**Full Changelog**: https://github.com/danieljustus/symaira-vault/compare/v0.7.0...v0.7.1
