# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- MCP **Prompts** capability with four slash commands surfaced in Claude Code, OpenCode, Hermes and other MCP clients: `add-credential`, `rotate-credential`, `find-and-use`, `share-credential`. Each prompt renders a guided workflow that the agent follows step-by-step (e.g. `/mcp__openpass__add-credential` walks the agent through collecting a new secret without ever exposing the value)
- `request_credential` MCP tool — the agent calls this when it discovers a credential is missing from the vault during a task; the user gets a native input dialog, types the value, and it lands in the vault without ever transiting the chat
- New `internal/secureui` package providing cross-platform secure input: native macOS dialogs via `osascript`, Linux dialogs via `zenity` or `kdialog`, Windows credential prompts via PowerShell `Get-Credential`, with the existing TTY backend as a fallback. Backend selection honors a new `OPENPASS_SECUREUI=tty|gui|none` environment override

### Changed

- `secure_input` MCP tool is now available in HTTP mode as well, provided the host has a native dialog backend (previously stdio + TTY only)
- Server initialize response now advertises the `prompts` capability so clients enable the slash-command surface

## [v1.0.0] - 2026-04-22

Initial stable OpenPass release.

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

- Update check command (`openpass update check`) for detecting newer releases
- Self-update mechanism for managing OpenPass installations
- MCP server stdio transport support for local agent integration
- Session management commands (`openpass unlock`, `openpass lock`) with configurable TTL
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
- `openpass run` command for executing commands with vault secrets as environment variables
- MCP tools for command execution with secret injection
- `CanRunCommands` permission for agent profiles
- MCP scoped token management with fine-grained access control
- Token registry with SHA-256 hashed storage
- `openpass mcp token` CLI commands (create, list, revoke)
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
- Dynamic shell completion for entry names in openpass get, openpass delete, and related commands
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

[v1.0.0]: https://github.com/danieljustus/OpenPass/releases/tag/v1.0.0
[v1.1.0]: https://github.com/danieljustus/OpenPass/releases/tag/v1.1.0
[v1.1.1]: https://github.com/danieljustus/OpenPass/releases/tag/v1.1.1
[v1.1.2]: https://github.com/danieljustus/OpenPass/releases/tag/v1.1.2
[v1.1.3]: https://github.com/danieljustus/OpenPass/releases/tag/v1.1.3
[v1.1.4]: https://github.com/danieljustus/OpenPass/releases/tag/v1.1.4
[v1.2.0]: https://github.com/danieljustus/OpenPass/releases/tag/v1.2.0
[v1.3.0]: https://github.com/danieljustus/OpenPass/releases/tag/v1.3.0
[v2.0.0]: https://github.com/danieljustus/OpenPass/releases/tag/v2.0.0
[v2.1.0]: https://github.com/danieljustus/OpenPass/releases/tag/v2.1.0
[v2.2.0]: https://github.com/danieljustus/OpenPass/releases/tag/v2.2.0
[v2.2.1]: https://github.com/danieljustus/OpenPass/releases/tag/v2.2.1
[v2.3.0]: https://github.com/danieljustus/OpenPass/releases/tag/v2.3.0
[v2.4.0]: https://github.com/danieljustus/OpenPass/releases/tag/v2.4.0
[v2.5.0]: https://github.com/danieljustus/OpenPass/releases/tag/v2.5.0
[v2.7.0]: https://github.com/danieljustus/OpenPass/releases/tag/v2.7.0
