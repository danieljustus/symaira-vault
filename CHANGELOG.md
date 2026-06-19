# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

> **Note — release series:** The releases `v1.0.0` through `v4.0.0` were
> published under the legacy **OpenPass** name. The current **Symaira Vault**
> series begins at `v0.1.0` and follows the `v0.x` line. Historical OpenPass
> releases remain in this changelog for reference only and are not part of the
> current Symaira Vault release target. See
> [docs/MIGRATION-RENAME.md](docs/MIGRATION-RENAME.md) for the rename context
> and [docs/commercial-boundary.md](docs/commercial-boundary.md) for the
> current release-line policy. (Added 2026-06-10, see #384.)

## [v0.7.1] - unreleased

### Added — repository operations

- **Projects v2 board** — a new GitHub Projects v2 board named `Symaira
  Vault` (number 11) is linked to this repository. The board includes a
  `Status` single-select (Todo / In Progress / Done), a `Priority`
  single-select (Urgent / High / Medium / Low), and an `Iteration` field
  with two-week iterations starting `2026-06-16` (v0.7.x, v0.8.x, v0.9.x,
  v0.10.x). The previous Projects v2 board (`symaira-vault`, number 1)
  remains read-only historical context. Tracked issues can now be
  assigned to an iteration alongside the milestone. See #508.

## [v4.0.0] - 2026-05-21

v4.0 reshapes Symaira Vault around AI-agent integration. The CLI becomes a
first-class surface for agents (dual to MCP), agent profiles gain an explicit
tier system, skill packages ship inside the binary, and the MCP server defaults
to a lean 7-tool surface to reduce context-window pollution.

See [docs/migration-v3-to-v4.md](docs/migration-v3-to-v4.md) for the upgrade
guide and [docs/skills/symaira-agent/UPGRADE-TO-V4.md](docs/skills/symaira-agent/UPGRADE-TO-V4.md)
for an AI-agent-ready upgrade prompt. Run `symvault migrate v4 --dry-run` to
preview, then `symvault migrate v4` to apply.

### Breaking changes

- **CLI consolidation.** All AI-integration commands moved under
  `symvault agent`. Replaced: `symvault mcp install`, `symvault mcp-config`,
  `symvault mcp token …`, `symvault mcp-token-rotate`, `symvault agent setup`.
  Deprecation stubs remain in v4.0 (print replacement, exit 2) and will be
  removed in v4.1.
- **MCP tool `openpass_delete` removed** (was an alias for `delete_entry` since
  v2.x). Callers receive `ERR_TOOL_NOT_FOUND`. Use `delete_entry`.
- **Default tier for `symvault agent install` is `safe`** (metadata-only).
  Upgrade explicitly with `symvault agent upgrade <name> --tier standard`.
- **Token `tools: ["*"]` now means "inherit from profile"** instead of "all
  tools the server knows." Profile changes take effect on the next call.
- **MCP `tools/list` lean mode by default** — returns 7 essential tools at
  connect time. Pass `include_all_tools: true` in init or call `openpass_search`
  for the full surface.

### Added — agent integration

- **`symvault agent install <name>`** — single command for agent setup:
  generates scoped token + writes MCP config + drops embedded skill package +
  runs smoke test. Flags: `--auto-detect`, `--tier`, `--http`, `--dry-run`,
  `--skill-only`, `--config-only`, `--force`, `--output json|yaml|text`.
- **`symvault agent upgrade <name> --tier <tier>`** — explicit, audited tier
  change with interactive diff. Non-interactive `--yes --reason "…"` requires a
  reason for the audit trail. Optional `--rotate-token`.
- **`symvault agent uninstall <name>`** — removes profile, token, skill, and
  MCP config entry; skill files without the Symaira Vault sentinel are preserved.
- **`symvault agent doctor <name>` / `--all`** — end-to-end diagnostic for one
  or all agent integrations; detects skill drift via hash comparison.
- **`symvault agent list`** — installed agents with tier, token status, last-seen.
- **`symvault agent token <name> new|list|revoke|rotate`** — token management
  per agent.
- **`symvault agent audit <name>` / `audit self`** — per-agent audit log with
  `--since` and `--format table|json`.
- **`symvault agent profile show|edit|export <name>`** — agent profile
  inspection and editing in `$EDITOR` with schema validation + confirmation.
- **`symvault agent skill export|refresh <agent>`** — pack skill for org
  distribution or re-render in place.
- **`symvault agent whoami --output json`** — CLI form of the `openpass_whoami`
  MCP tool.
- **`symvault agent prompt <path>.<field>`** — CLI form of `secure_input`.
- **`symvault agent request <path>.<field> --reason "…"`** — CLI form of
  `request_credential`.

### Added — MCP tools

- **`openpass_whoami`** — agent self-introspection: tier, allowed paths,
  quotas, available tools, vault status, CLI-alternative hint. Available in
  every tier; agents should call once per session.
- **`openpass_audit_self`** — agents read their own recent audit events
  (success, denied, redacted). Other agents' trails are not exposed.
- **`openpass_search`** — discover and on-demand-load tools by intent string.
  Returns matching tool spec inline plus `cli_alternative` for each match.
- **Lean-mode `tools/list`** — 7-tool default surface (`openpass_whoami`,
  `openpass_search`, `health`, `find_entries`, `get_entry_metadata`,
  `request_credential`, `openpass_audit_self`); ~83% less initial context.
- **Structured error responses** — every MCP error now returns
  `{ code, message, hint, details, doc }` with codes from
  `internal/mcp/errors/codes.go` (`ERR_PATH_FORBIDDEN`, `ERR_TOOL_NOT_ALLOWED`,
  `ERR_APPROVAL_DENIED`, `ERR_QUOTA_EXCEEDED`, …).
- **Tool descriptions for LLMs** — every tool documented in
  `internal/mcp/tooldocs/<tool>.md` with `USE WHEN`, `DON'T USE WHEN`, `INPUT`,
  `OUTPUT`, `COMBINES WELL WITH`, `EXAMPLE` sections.
- **`find_entries` returns mini-metadata inline** — `path`, `name`, `updated`,
  `version`, `score` per hit; saves repeat `get_entry_metadata` round-trips.

### Added — tier system

- **Three tier presets** in `internal/config/presets.go`: `safe` (alias for
  `read-only`), `standard`, `admin`. Each is snapshot-tested to prevent silent
  drift.
- **`safe` (default)** — metadata-only tools, no writes, no clipboard/autotype,
  no commands, deny-mode approvals, strict redaction.
- **`standard`** — adds value-read, write, clipboard, autotype, prompts; uses
  `prompt`-mode approvals for destructive ops.
- **`admin`** — adds command execution, profile management, exposes
  value-returning tools; prompts only on destructive ops.
- **Audit events** for tier lifecycle: `AGENT_INSTALLED`, `AGENT_TIER_CHANGED`,
  `AGENT_TIER_CHANGE_DENIED`, `AGENT_TOKEN_ROTATED`, `AGENT_UNINSTALLED`,
  `AGENT_QUOTA_HIT`.

### Added — skill packages

- **Per-agent skills embedded in the binary** via `internal/agentskill/assets/`
  with templates for `hermes`, `claude-code`, `codex`, `opencode`, `openclaw`,
  plus a `common/` base.
- **Sentinel-based lifecycle** — frontmatter `managed_by: symvault` +
  SHA-256 hash. Install/refresh/uninstall only touch files with the sentinel;
  user-edited skills are preserved unless `--force` is passed.
- **Deterministic rendering** — golden-file tests in
  `internal/agentskill/testdata/` enforce byte-identical re-renders.
- **Per-agent paths** resolved automatically (`~/.claude/`, `~/.codex/`,
  `~/.config/opencode/`, `~/.hermes/`, `~/.openclaw/`).

### Added — CLI as agent surface

- **`OPENPASS_AGENT=<name>` environment variable** applies the agent profile
  (allowed paths, redaction, quotas, audit) to every CLI call. Same enforcement
  logic as MCP.
- **`internal/agentctx/`** — shared profile-context loader used by both CLI
  and MCP dispatch paths; eliminates duplicate enforcement code.
- **`internal/quotas/`** — file-lock-based shared quota counter between CLI
  and MCP; both paths increment the same `~/.openpass/state/quotas/<agent>.json`.
- **Standardized exit codes** on every command:
  0/1/2/10/11/12/13/14/15.
- **`--output text|json|yaml`** on every command; JSON output is the contract
  for agent-driven CLI calls.

### Added — migration

- **`symvault migrate v4 [--dry-run] [--yes]`** — classifies existing v3
  profiles into tiers, computes skill drift, backs up `config.yaml` to
  `config.yaml.bak.v3-<timestamp>`, renders skill packages, re-validates token
  registry, prints summary. Idempotent.
- **Profile classification:** `canRunCommands=true → admin`; `canWrite=true`
  and `canUseClipboard=true → standard`; metadata-only → `safe`; profiles
  with redact-field overrides that don't match a preset → `custom`.
- **`docs/migration-v3-to-v4.md`** — full user-facing upgrade guide.
- **`docs/skills/symaira-agent/UPGRADE-TO-V4.md`** — AI-agent-ready prompt
  to drive the upgrade end-to-end.

### Security

- Memory hygiene: TOTP secret, OPENPASS_PASSPHRASE, OPENPASS_MCP_TOKEN string
  backing arrays wiped after read; passphrase wiping via `[]byte` instead of
  `unsafe.StringData`; legacy passphrase wiped after migration (#154, #155,
  #158, #159, #177).
- Generated passwords protected with `SecureString` (mlock'd mmap) (#156).
- `SafeMkdirAll` hardened against symlink-traversal attacks (#157).
- `unsafe.StringData`/`unsafe.Slice` removed from TOTP input handling.
- Prompt-injection hardening: 4 fixes + threat model + e2e tests; per-tool
  `redactFields`, registry hash, tool-chain anomaly detection, import
  quarantine (#91-95, #97).
- API response sanitization for `execute_api_request` (#57, #62).
- `generate_totp` hardened: default clipboard, return-value gated on approval
  (#59).
- 32 + 27 + 15 + 6 + 5 gosec/code-scanning alerts resolved across
  the v3→v4 cycle (#121, #122, #123, #137 et al).

### Fixed

- `--dry-run` no longer creates real tokens in `mcp install` (#68).
- Token registry reloads when the file changes on disk (#67).
- Opencode install uses the correct root key and adds required fields (#66).
- `symvault auth status --output json` uses `PrintResult` instead of the
  deprecated `PrintJSON` (#180).
- `migrateLegacyEntries` walks skip `IsNotExist` errors instead of bailing
  out.
- 2 `goconst` lint findings in `internal/config/config_load.go` and
  `config_merge.go` resolved by reusing existing constants.

### Performance

- `EnforceRetention` uses `os.ReadDir` instead of `filepath.Glob`
  (orders-of-magnitude faster on large vaults) (#161).

### Refactored

- `init()` functions replaced with explicit package-level initialization
  (#162).
- `copyAgentProfiles` replaced with JSON deep-copy (#178).
- Session passphrase wiping uses `[]byte` instead of `unsafe.StringData`
  (#177).

### Documentation

- Expanded error-wrapping conventions in `CONTRIBUTING.md` (#163).
- Added CVE monitoring guidance for the deferred ProtonMail/go-crypto
  transitive dependency (#179).
- Added v4 release checklist (`docs/release-checklist-v4.md`).

## [v3.0.0] - 2026-05-15

### Added

- **Security: MCP response hardening** — new `taint.Untrusted` typesystem provides compile-time safety boundary between trusted and untrusted data; all MCP responses pass through `SanitizeForMCP` chokepoint; new `EmbedAsData()` helper wraps untrusted content in safe `<data>` tags; all 12 prompt injection points migrated to `EmbedAsData` (#38, #40)
- **Security: typed vault accessors** — `FieldUntrusted()`, `TagsUntrusted()`, `UsageHintUntrusted()` return `taint.Untrusted` values with provenance tracking; `SecretHandle` type with `ParseSecretHandle()` for `op://` path resolution; `HandleResolver` interface (#39)
- **Security: `CanReadValues` profile option** — gates `get_entry_value` behind explicit agent permission; `requireApproval()` helper with `Intent` struct, `ApprovalMode` (none/auto/deny/prompt), and audit-logged approval/rejection events (#40)
- **Security: custom Go vet analyzer (`passlint`)** — detects `fmt.Print*/Sprintf/Fprint*` with `taint.Untrusted` args; integrated into CI via `make vet` (#42)
- **Terminal output hardening** — all TUI, Doctor, and CLI output sanitized through `render.ForTerminal()` and `ForTerminalLine()` (#41)
- OAuth refresh token grant (RFC 6749 §6) with configurable TTLs (`ScopedToken` gains `RefreshTokenHash`/`RefreshExpiresAt`; `CreateWithRefresh()`/`RotateViaRefreshToken()`; single-use rotation) (#46)
- Persistent OAuth client registry — client registrations survive server restarts via JSON persistence (`oauthClientStore.Load()`/`Save()`); optional TTL with background expired-client cleanup (#45)
- Config options `mcp.oauth.access_token_ttl` (default 24h) and `mcp.oauth.refresh_token_ttl` (default 720h/30d) with file config + merge support (#46)
- Nix flake for NixOS/Nix support — `nix run github:danieljustus/symaira-vault` with `buildGoModule` package, default app, and dev shell (#36)
- New `internal/ui/render` package with `ForTerminal()`, `QuoteForTerminal()`, `ForTerminalLine()` sanitizers
- New `internal/mcp/render.go` with `RenderChokepoint` and `SanitizeForMCP()`

### Changed

- **Breaking: MCP `get_entry` response format** — `fields` now `[]map[string]{name, handle, kind}` instead of `[]string`; each field includes type-inferred `kind` (string, number, boolean, totp, object, null) (#40)
- **Breaking: `include_value` removed** — `handleGet` returns metadata only; `handleSanitizeOutput` delegates to `SanitizeForMCP` chokepoint (#42)
- **Breaking: prompt format migrated** — all user-supplied values in MCP prompts are now wrapped in `<data label=..>` tags with `(data)` annotation, removing `%s`/`%q` injection risk (#40)
- OAuth docs updated to reflect live OAuth implementation (removed "501 Not Implemented" claims) (#47)
- Agent integration docs: added OAuth DCR section with opencode configuration example (#47)
- `get_entry_metadata`: `UsageHint` sanitized through `SanitizeForMCP`
- `list_entries`/`find_entries`: `Path` and `UsageHint` sanitized through `SanitizeForMCP`
- `set_entry_field`/`delete_entry`: use `requireApproval()` instead of `requiresApproval`
- Bumped `github.com/mattn/go-runewidth` from v0.0.19 to v0.0.23 (#44)
- Bumped `actions/upload-artifact` from 4 to 7 (#43)
- `gocyclo` complexity threshold adjusted to 30 for existing codebase

### Fixed

- OAuth error response: `unauthorized_client` → `invalid_client` with `WWW-Authenticate` header (#45)
- Nix `vendorHash` resolved for reproducible builds (#36)
- `err` shadowing in `handlerForAgent` goroutine closure
- `gofmt` formatting across `config.go`, `taint_test.go`, `schema.go`, `token.go`, `oauth.go`, and test files
- `errcheck`: handle `fmt.Fprintf` return values in `taint.go`
- `goconst`: use `SecretTypePassword` constant in `types.go`
- `govet shadow`: rename `err` variables in `tools_delete.go` and `tools_get.go`
- `prealloc`: preallocate slice with capacity in `approval_helper.go`
- `unconvert`: remove unnecessary `string()` conversion
- `unused`: remove dead `buildVaultResolver` function
- Skip file permission assertion on Windows (`chmod` is no-op on Windows)
- `goimports`: formatting on `passlint_test.go`

## [v2.9.0] - 2026-05-13

### Added

- Weak password support: `AssessPasswordStrength` (non-blocking) alongside `ValidatePasswordStrength`, weak passwords accepted with confirmation in TTY mode, `--force` for scripted use, automatic `weak-password` tag on entries, and new doctor checks `password.strength` and `password.reuse` (#35)
- Centralized TUI theme system with visual polish and Esc-to-confirm (#33)
- Doctor enhancements: tag-based check filtering (`--quick`), 9 new checks (auto-type backend, clipboard, daemon, MCP server, dynamic secrets, agents, secure UI, pre-commit hooks, session keyring), `--fix-dry-run` flag, schema_version output (#31)
- Agent auto-install support for Codex and OpenCode alongside existing Claude Code config (#32)
- Theme symbols and styletheme packages for consistent UI styling

### Changed

- Wizard UX improvements: summary highlight, MultiDevice default to No, Enter-to-save on empty textarea, progress spinner with step counter, resume prompt with file age, passphrase autofocus, vault path validation, resume file moved to UserCacheDir with 0600 perms (#30)
- TOML config reader/writer (`FormatTOML` constant) for agent config generation

### Fixed

- Security: OAuth flow now requires client registration, TTY consent, and returns scoped tokens (#21)
- Security: `list_shares` scoped to calling agent instead of showing all grants (#22)
- Security: authorization gates (CanRunCommands, allowlist, approval) on `generate_dynamic_secret` (#23)
- Security: passphrase heap copy eliminated via `unsafe.String` aliasing before Wipe (#26)
- Security: Origin header warning + `approve_share` self-approval check (#27, #29)
- Security: global cooldown replacing per-guess failed-attempts map (#25)
- Removed `generate_dynamic_secret` tool (dead code — engines never registered) (#24)
- Removed duplicate `logAuditWithToken` helper (#28)
- Resolved 13 golangci-lint issues (errcheck, goconst, gocritic, govet, unused)
- Added timeout to `checkSessionKeyring` to prevent hang on headless macOS CI
- Lowered coverage threshold to 68.0% to match current baseline
- Added #nosec annotations for gosec G103/G304 false positives (10 alerts)
- gofmt formatting fixes across test files

## [v2.8.2] - 2026-05-12

### Fixed

- Resolve gosec code scanning alerts (G115, G302, G304):
  - Add overflow bounds check for int32 conversion in `SetTestScryptWorkFactor`
  - Fix nosec annotation format for directory permissions check
  - Fix nosec annotation format for controlled file read

## [v2.8.1] - 2026-05-12

### Fixed

- Accept `application/json; charset=utf-8` Content-Type in OAuth dynamic client registration
- Security hardening, concurrency locking, and audit error handling
- Resolve golangci-lint errors (prealloc, errorlint, errcheck)
- Fix test helper vars and Windows LockFileEx test skipping

## [v2.8.0] - 2026-05-12

### Added

- MCP **Prompts** capability with four slash commands surfaced in Claude Code, OpenCode, Hermes and other MCP clients: `add-credential`, `rotate-credential`, `find-and-use`, `share-credential`. Each prompt renders a guided workflow that the agent follows step-by-step (e.g. `/mcp__openpass__add-credential` walks the agent through collecting a new secret without ever exposing the value)
- `request_credential` MCP tool — the agent calls this when it discovers a credential is missing from the vault during a task; the user gets a native input dialog, types the value, and it lands in the vault without ever transiting the chat
- New `internal/secureui` package providing cross-platform secure input: native macOS dialogs via `osascript`, Linux dialogs via `zenity` or `kdialog`, Windows credential prompts via PowerShell `Get-Credential`, with the existing TTY backend as a fallback. Backend selection honors a new `OPENPASS_SECUREUI=tty|gui|none` environment override
- `auth_rotate` CLI command for credential rotation
- `verify` CLI command for vault integrity checks
- `internal/audit/keystore` with OS-level and fallback backends
- `internal/crypto/diceware` passphrase generator with EFF large wordlist
- Multi-device QR pairing in wizard
- Wizard state persistence
- Vault manifest for metadata tracking
- OAuth well-known endpoints for MCP server discovery

### Changed

- `secure_input` MCP tool is now available in HTTP mode as well, provided the host has a native dialog backend (previously stdio + TTY only)
- Server initialize response now advertises the `prompts` capability so clients enable the slash-command surface
- Doctor checks expanded for crypto KDF modern status and keystore health
- Vault entry, lock, reencrypt, and search improvements

## [v1.0.0] - 2026-04-22

Initial stable Symaira Vault release.

### Added

- Age-based encrypted vault storage with passphrase-protected identity files
- CLI commands for initializing vaults, adding, setting, getting, listing, finding, editing, deleting, and generating entries
- TOTP support for storing seeds and generating one-time codes
- Clipboard copy support with automatic clearing
- Session caching through the operating system keyring
- Git integration for vault history and synchronization
- Multi-recipient vault support for shared access
- MCP server support over stdio and local HTTP transports
- Agent profiles, path restrictions, write controls, metadata-only reads, and TOTP-safe redaction
- HTTP MCP bearer token authentication, request validation, health checks, and Prometheus metrics
- JSON output for automation-friendly CLI use
- Shell completions and generated manual pages
- Linux package, archive, and checksum release automation
- CI coverage checks, race tests, smoke tests, vulnerability scanning, and linting

### Security

- Entry files are encrypted independently with age X25519 and ChaCha20-Poly1305
- Passphrases are read through terminal password prompts and are not stored in plain text
- HTTP MCP binds to `127.0.0.1` by default and requires bearer token authentication
- Release checksums are published for artifact verification

## [v1.1.0] - 2026-04-23

Major update with vault improvements, self-update mechanism, and enhanced MCP transport.

### Added

- Update check command (`symvault update check`) for detecting newer releases
- Self-update mechanism for managing Symaira Vault installations
- MCP server stdio transport support for local agent integration
- Session management commands (`symvault unlock`, `symvault lock`) with configurable TTL
- Release smoke tests for validating published artifacts
- Installer scripts for cross-platform installation (`install.sh`, `install.ps1`)

### Changed

- Vault structure refactored to use `entries/` subdirectory for organized storage
- Entry format updated to structured YAML with individual file encryption
- Removed index cache in favor of direct filesystem operations
- Improved handler concurrency for better performance
- Enhanced context propagation throughout the codebase

### Fixed

- Audit error logging improved for better diagnostics

## [v1.1.1] - 2026-04-24

Documentation updates.

### Changed

- Updated documentation images and README content

## [v1.1.2] - 2026-04-24

Documentation fixes.

### Changed

- Additional documentation images and README updates (same commit as v1.1.1)

## [v1.1.3] - 2026-04-24

CI configuration fix.

### Fixed

- Skipped Homebrew tap publishing workflow until GitHub PAT is properly configured

## [v1.1.4] - 2026-04-24

CI fix for release validation.

### Fixed

- Fixed release smoke tests to properly validate published artifacts

## [v1.2.0] - 2026-04-24

Audit, backup, and security hardening release.

### Added

- Backup and restore commands with automated test coverage
- Audit log support and broader integration test coverage for vault operations

### Changed

- Enabled Homebrew tap publishing through the release workflow
- Raised package test coverage across vault, session, update, git, and audit paths

### Fixed

- Resolved CI lint failures and a serve race condition
- Fixed generated coverage artifact handling in Git ignores

### Security

- Hardened file handling against path traversal, symlink TOCTOU, and unsafe permissions
- Addressed gosec findings for integer conversion and weak crypto hash usage

## [v1.3.0] - 2026-04-26

MCP, vault search, and backup hardening release.

### Added

- Concurrent vault search with scoped `FindWithOptions` support
- Trusted proxy support for MCP HTTP deployments
- TOTP secret validation before storing credentials

### Changed

- Metrics endpoint authentication now respects loopback vs non-loopback bind security

### Fixed

- Password generation stores entries through the vault entry path helper

### Security

- Hardened backup restore against symlink and permission vulnerabilities
- Fixed additional integer overflow findings in backup restore handling

## [v2.0.0] - 2026-04-28

Platform expansion, transport hardening, and developer experience release.

### Added

- FreeBSD support with in-memory encrypted session cache fallback (AES-256-GCM)
- Scoop distribution channel for Windows
- TLS configuration support for update checker and HTTP MCP
- Batch MCP operations for efficient multi-entry workflows
- Quiet mode flag (`-q` / `--quiet`) for script-friendly output
- Sentinel errors and restructured exit codes for reliable automation
- Password normalization and enhanced TOTP metadata support
- Improved in-memory session cache with configurable expiration
- Graceful OS keyring fallback to memory cache when keyring is unavailable

### Changed

- Go version bumped to 1.26.3
- Comprehensive CI documentation with lint gates and FreeBSD guidance

### Fixed

- FreeBSD cross-compilation by isolating go-keyring imports
- golangci-lint findings across bodyclose, errorlint, shadow, and staticcheck
- Session prompt logic now checks active session before requesting passphrase

## [v2.2.0] - 2026-05-05

Autotype, secure secret execution, MCP token management, and session hardening release.

### Added

- Cross-platform autotype package for automatic password entry (macOS, Linux, Windows)
- MCP tools for autotype and clipboard operations
- Secure wrap key and encrypted identity storage in vault sessions
- Vault legacy mode detection for migration optimization
- Extended secure memory wipe to decrypted entries and additional paths
- `symvault run` command for executing commands with vault secrets as environment variables
- MCP tools for command execution with secret injection
- `CanRunCommands` permission for agent profiles
- MCP scoped token management with fine-grained access control
- Token registry with SHA-256 hashed storage
- `symvault mcp token` CLI commands (create, list, revoke)
- Tool registry for introspecting available MCP tools
- Scoped token authentication integrated into HTTP server authorization
- Fuzz test coverage for importer path normalization
- Windows arm64 to distribution platform matrix
- Installation problem issue template

### Changed

- Updated config schema with `PrintByDefault` and `LegacyMode` fields
- Moved OpenTelemetry dependencies to direct in go.mod
- Enhanced MCP tool registration across all tools
- Refactored touchid session handling
- Improved metrics infrastructure

### Fixed

- Resolved golangci-lint v2 compatibility failures across the codebase
- Fixed pre-existing lint issues: shadowed variables, copylocks, errorlint, exhaustive switches
- Fixed gofmt formatting and Windows path test failures in CI
- Added gosec nosec annotation for intentional subprocess execution
- Fixed macOS keychain hang in CI by stubbing session save identity
- Updated ADR-0003 with completed memory wipe phases

## [v2.2.1] - 2026-05-05

Documentation and bug fix release.

### Added

- Extended comparison table with 1Password, Bitwarden, and pass including accurate pricing, features, and legal disclaimers
- AI chat anti-pattern documentation highlighting the risks of pasting secrets into chat interfaces

### Changed

- Updated README comparison section with a comprehensive five-column feature matrix
- Revised MCP documentation to reflect v2.2.0 features

### Fixed

- Improved argument validation for auth set command with custom validation replacing cobra.ExactArgs, showing help on invalid input

## [v2.3.0] - 2026-05-06

Interactive form, secure memory handling, and MCP token migration release.

### Added

- Interactive Bubble Tea form for guided password entry creation
- Auto-migration of legacy MCP tokens to scoped tokens for enhanced security
- cliout package for consistent colored output with --quiet and NO_COLOR support
- Service interface abstraction in vault service layer

### Changed

- Refactored vault service errors into consolidated error types
- Extracted SafeWriteFile utility to break import cycles across packages
- Upgraded charmbracelet/bubbles to v1.0.0, bubbletea to v1.3.10, and lipgloss to v1.1.0
- Bumped prometheus/common dependency to v0.67.5

### Fixed

- Secret keys and passphrases are now wiped from heap after use
- Atomic file writes via SafeWriteFile pattern for crash-safe vault and config operations
- Touch ID now checks keychain item existence before prompting, preventing double authentication
- Resolved Windows test flakiness and data races in crypto Wipe operations
- Fixed gosec linting violations across the codebase

## [v2.4.0] - 2026-05-07

Daemon mode, device pairing, and multi-device synchronization release.

### Added

- Background daemon mode for persistent MCP server operation
- Device pairing workflow for linking multiple devices to the same vault
- New CLI commands: device, remote, sync, migrate, and serve-install
- Device support in vault and config layers with entry re-encryption for device-specific identities
- Enhanced search functionality for improved entry discovery
- Server handler improvements in MCP layer with bootstrap logic and refined service layer
- macOS notarization documentation and service management scripts

### Changed

- Updated README with multi-device workflow documentation
- Improved server bootstrap sequence for reliable daemon startup
- Refactored input handling across CLI commands for consistency

## [v2.5.0] - 2026-05-08

Dynamic secrets, secret sharing, template engine, and audit integrity release.

### Added

- AWS and PostgreSQL dynamic secret support with automatic lease management and rotation
- Agent-to-agent secret sharing with human approval workflow including ShareStore, approve, revoke, and list tools with full audit integration
- Template engine for secret generation with variable substitution support
- HMAC chain for audit log integrity with chained HMAC per entry and VerifyLogIntegrity function
- Output sanitization for MCP tools to redact secrets before LLM chat interactions
- New sanitize_output MCP tool for secret-safe agent communication
- Editor plugin build targets for IDE integration

### Changed

- Upgraded Go to 1.26.3, fixing eight CVEs (CVE-2026-39820, CVE-2026-39823, CVE-2026-33811, CVE-2026-39826, CVE-2026-42499, CVE-2026-39825, CVE-2026-39836, CVE-2026-33814)
- Refactored autotype string escaping into shared utilities for macOS and Windows

### Fixed

- Hardened crypto with explicit scrypt work factor configuration
- Added ZIP bomb protection in the importer for safe data migration
- Enforced secure deletion of temporary files
- Protected mcp-tokens.json as a runtime path in Git operations
- Resolved Windows CI failures and lint warnings across gosec and gofmt

## [v2.7.0] - 2026-05-11

KDF configuration, vault file locking, MCP security hardening, and platform diagnostics release. Supersedes all v2.6.0 changes (tagged but unreleased).

### Added

- Doctor command for vault health diagnostics including init check, config parsing, identity encryption, permissions, auth, session cache, Git, recipients, MCP tokens, audit log, update check, and vault size, with --no-network option and JSON and text output
- Interactive setup wizard with guided TUI for vault initialization covering passphrase, authentication, agents, backup, multi-device, recipients, profile, sync, and passphrase strength meter
- Scrypt KDF configuration parameter for age passphrase encryption
- Vault file locking using Unix flock and Windows LockFileEx with automatic cleanup on process exit
- OAuth well-known endpoints for MCP server discovery and integration
- Build tag infrastructure for platform-specific feature compilation
- Dynamic shell completion for entry names in symvault get, symvault delete, and related commands
- Hermes and OpenClaw safe adoption guidance documentation
- Expanded test coverage across multiple packages to reach the 70% threshold

### Changed

- Consolidated --json flag onto a persistent --output flag, with --json still functional but deprecated with a warning
- Go toolchain pinning for reproducible MCP agent builds
- Improved MCP agent integration test isolation and port allocation

### Fixed

- Suppressed ANSI color codes when stderr is not a TTY for scripted and piped usage
- Editor resolution now uses LookPath with a fallback chain of EDITOR, sensible-editor, vi, nano, and notepad
- Entry display truncation now operates on rune width instead of byte count for correct multi-byte character rendering
- WriteEntry is now atomic via temporary file write, fsync, and rename
- Command output redaction in MCP agent tests
- Resolved golangci-lint findings across copyloopvar, errcheck, gocyclo, goconst, revive, staticcheck, and unparam

### Performance

- Cached parsed vault configuration by modification time to avoid repeated file reads
- Skipped legacy top-level directory walk when LegacyMode is disabled

### Security

- Autotype now passes passwords via stdin instead of command-line arguments to prevent exposure in process listings
- MCP server now requires TLS or explicit opt-in for non-loopback bind addresses
- Capped RateLimiter map size with LRU eviction to prevent memory exhaustion attacks
- Added loud warning on legacy token migration with wildcard scope

## [v2.1.0] - 2026-04-29

Interactive TUI, vault management, and observability release.

### Added

- Interactive TUI using bubbletea for intuitive vault browsing and management
- Import command for migrating from 1Password, Bitwarden, pass, and CSV
- Config command with JSON schema validation for structured settings
- Profile command for multi-vault management and switching
- Auth command for passphrase and biometric (Touch ID) authentication setup
- Vault service layer for cleaner separation of concerns
- OpenTelemetry tracing support for operation observability
- Structured logging package with configurable verbosity
- Diag command for runtime metrics and environment inspection
- Windows path sanitization in importer to strip invalid characters

### Changed

- Refactored MCP server into focused files for maintainability
- Moved clipboard package to `internal/clipboard` for better organization
- Updated project documentation and generated man pages

### Fixed

- Resolved golangci-lint v2 compatibility issues
- Fixed Ubuntu CI session caching test flakiness
- Corrected release workflow environment variable duplication

[v1.0.0]: https://github.com/danieljustus/symaira-vault/releases/tag/v1.0.0
[v1.1.0]: https://github.com/danieljustus/symaira-vault/releases/tag/v1.1.0
[v1.1.1]: https://github.com/danieljustus/symaira-vault/releases/tag/v1.1.1
[v1.1.2]: https://github.com/danieljustus/symaira-vault/releases/tag/v1.1.2
[v1.1.3]: https://github.com/danieljustus/symaira-vault/releases/tag/v1.1.3
[v1.1.4]: https://github.com/danieljustus/symaira-vault/releases/tag/v1.1.4
[v1.2.0]: https://github.com/danieljustus/symaira-vault/releases/tag/v1.2.0
[v1.3.0]: https://github.com/danieljustus/symaira-vault/releases/tag/v1.3.0
[v2.0.0]: https://github.com/danieljustus/symaira-vault/releases/tag/v2.0.0
[v2.1.0]: https://github.com/danieljustus/symaira-vault/releases/tag/v2.1.0
[v2.2.0]: https://github.com/danieljustus/symaira-vault/releases/tag/v2.2.0
[v2.2.1]: https://github.com/danieljustus/symaira-vault/releases/tag/v2.2.1
[v2.3.0]: https://github.com/danieljustus/symaira-vault/releases/tag/v2.3.0
[v2.4.0]: https://github.com/danieljustus/symaira-vault/releases/tag/v2.4.0
[v2.5.0]: https://github.com/danieljustus/symaira-vault/releases/tag/v2.5.0
[v2.7.0]: https://github.com/danieljustus/symaira-vault/releases/tag/v2.7.0
[v3.0.0]: https://github.com/danieljustus/symaira-vault/releases/tag/v3.0.0
[v2.9.0]: https://github.com/danieljustus/symaira-vault/releases/tag/v2.9.0
[v2.8.2]: https://github.com/danieljustus/symaira-vault/releases/tag/v2.8.2
[v2.8.1]: https://github.com/danieljustus/symaira-vault/releases/tag/v2.8.1
[v2.8.0]: https://github.com/danieljustus/symaira-vault/releases/tag/v2.8.0
