## What's Changed

### Features
- #390 Add experimental TUI, interactive config fix, and security/release docs — closes #385 #386 #387 #388
- #381 Introduce KeyringBackend interface, extract migrate command — closes #343 #344
- #380 Eliminate global OperationService, introduce VaultService for DI — closes #342

### Fixes
- #404 Fix clipboard auto-clear after `symvault get` never fires, replace pseudonym cache denylist with allowlist, fix Postgres CREATE USER DDL, add cosign verification to install.ps1, fix TCC permission denials on macOS, skip full worktree status walk on affected-paths path — closes #396 #397 #398 #399 #400 #401 #402 #403 #405 #406 #407 #408 #409 #410 #411
- #382 Harden search index fallback against wrong-key rebuild — closes #351
- #316 Fix TouchID timeouts and allow locked MCP stdio startup — closes #313 #314 #315
- #328 Add RejectDenied env-var protection to run_command tool — closes #317 #318 #319 #320 #321 #325 #326 #327

### Security
- #377 Store audit log HMAC key in OS keyring instead of vault directory, harden session passphrase handling, add actionable error remediation hints — closes #368 #369 #370 #372 #373 #375 #376
- #360 Use HKDF-SHA256 for search index key derivation — closes #330 #332 #349 #350

### Refactors
- #329 Eliminate 49 global mutable variables in internal/cli/cli.go — closes #322 #323 #324
- #361 Eliminate global mutable state for search identity — closes #334

### Documentation
- #312 Stabilize audit event schema and retention controls — closes #308
- #311 Document commercial boundary
- #389 Clarify v0.x release line vs. historical v4.0.0 (OpenPass) — closes #384

### CI & Dependencies
- #304 Fix mcpb output path in build-mcpb.sh
- #362-#367, #391-#395 Bump Docker actions, GitHub Actions, and Go dependencies

### Closed Issues
- #308 Stabilize self-hosted audit event schema and local retention controls
- #313 TouchID unlock times out immediately on some macOS versions
- #314 MCP stdio server requires vault to be unlocked first
- #315 TouchID prompts appear behind terminal window
- #317 run_command tool allows arbitrary command execution
- #318 run_command lacks environment variable filtering
- #319 run_command output leaks to MCP client without redaction
- #320 run_command has no timeout enforcement
- #321 run_command allows path traversal via relative paths
- #322 Global mutable state in CLI package
- #323 Config validation errors not corrected interactively
- #324 CLI error messages lack actionable remediation hints
- #325 run_command allows execution of sensitive binaries
- #326 run_command lacks audit logging
- #327 run_command allows network access without approval
- #330 Search index key derivation uses weak KDF
- #332 Search index not encrypted at rest
- #342 OperationService is a global singleton
- #343 Session cache has no pluggable backend interface
- #344 migrate command is not discoverable
- #349 Search index key not derived from vault identity
- #350 Search index key stored in plaintext
- #351 Search index fallback rebuilds with wrong key
- #368 Audit log HMAC key stored on disk
- #369 Audit log HMAC key not rotated
- #370 Audit log HMAC key accessible to other processes
- #372 Audit log writes are synchronous
- #373 Audit log lacks retention controls
- #375 Audit log entries not redacted
- #376 Audit log accessible without authentication
- #371 AgentProfile has excessive nil-check boilerplate
- #374 AgentProfile fields not validated
- #384 Changelog confusing v0.x vs v4.0.0 releases
- #385 Experimental TUI for interactive vault management
- #386 Interactive config correction
- #387 Security documentation improvements
- #388 Release process documentation
- #396 Clipboard auto-clear timer not triggered
- #397 Clipboard cleared on wrong event
- #398 Pseudonym cache retains sensitive fields
- #399 Postgres CREATE USER fails with bind parameters
- #400 install.ps1 lacks cosign verification
- #401 macOS secure-input dialog misclassifies TCC denials
- #402 Auto-commit triggers full worktree status scan
- #403 Keyring startup note pollutes stderr
- #405 Cosign certificate identity regexp corrupted after rename
- #406 install.ps1 skips cosign verification
- #407 Pseudonym cache uses substring denylist
- #408 Unconditional keyring startup note
- #409 macOS TCC permission denials misclassified
- #410 Postgres engine DDL fails with bind parameters
- #411 Auto-commit worktree walk not optimized

**Full Changelog**: https://github.com/danieljustus/symaira-vault/compare/v0.4.0...v0.4.1
