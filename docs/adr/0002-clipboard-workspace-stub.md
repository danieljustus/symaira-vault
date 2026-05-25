# ADR 0002: Clipboard Workspace Stub

## Status

Superseded

## Context

Symaira Vault depends on `github.com/atotto/clipboard` for cross-platform clipboard operations. During development, we use a Go workspace (`go.work`) that replaces the upstream clipboard dependency with a local stub module (`clipboardpkg/`).

This creates two clipboard-related packages in the repository:

1. **`clipboardpkg/`** — A separate Go workspace module (not the main module) that provides a minimal buildable stub for `github.com/atotto/clipboard`. It exists only to satisfy the workspace replace directive.
2. **`internal/clipboard/`** — Application-level clipboard logic: auto-clear timers, countdown display, and integration with the upstream clipboard library.

The separation exists because:
- The workspace stub (`clipboardpkg/`) allows local builds without downloading the real dependency during development
- The application logic (`internal/clipboard/`) is where the actual user-facing clipboard behavior lives
- The CI pipeline explicitly guards against accidentally shipping the stub in release builds

## Decision

Keep both packages with clear separation of concerns:

- `clipboardpkg/` remains a workspace-only stub. Never imported by application code.
- `internal/clipboard/` contains all application clipboard logic. Imported by CLI commands.
- `cmd/get.go` imports `internal/clipboard` with alias `clipboardapp` to avoid confusion with the workspace module.

## Consequences

- **Positive**: Clear separation between workspace infrastructure and application logic
- **Positive**: CI guard prevents stub leakage into release binaries
- **Negative**: Two packages with "clipboard" in the name can confuse new contributors (mitigated by this ADR and ARCHITECTURE.md documentation)

## Superseded By

Build-tagged dual implementation (`system_clipboard.go` / `null_clipboard.go`).
See `internal/clipboard/interface.go` for the new approach.

The workspace stub approach (`clipboardpkg/` + `go.work`) has been replaced with
build-tagged implementations that use `//go:build test_headless` to switch
between real clipboard and no-op stub based on build context.

## References

- `go.work` — Workspace replace directive
- `clipboardpkg/go.mod` — Stub module definition
- `internal/clipboard/clipboard.go` — Application clipboard logic
- `.github/workflows/ci.yml` — Release dependency graph validation
