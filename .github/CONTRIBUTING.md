# Contributing to Symaira Vault

Symaira Vault is an open-source, age-encrypted password manager for terminal
users and AI agents. We welcome contributions from the community.

This document describes how to set up a development environment, run tests, and
submit changes. For agent-specific conventions (merge policy, issue handling,
release scope), see [AGENTS.md](AGENTS.md).

## Prerequisites

- **Go:** 1.24.4 or later (see `.go-version`)
- **Git:** for building and version stamping
- **Make:** to use the provided targets
- **On macOS:** Xcode Command Line Tools for CGO (keyring integration)

### Optional (client/macOS GUI build)

- **Xcode-beta:** the SwiftUI client requires `DEVELOPER_DIR=/Applications/Xcode-beta.app/Contents/Developer`
- **xcodegen:** to regenerate `client/Symvault.xcodeproj` from `client/project.yml`

## Building

```bash
# Build the CLI binary
make build

# Build the macOS client (requires Xcode-beta)
DEVELOPER_DIR=/Applications/Xcode-beta.app/Contents/Developer swift build
```

## Testing

```bash
# Run all tests with race detector (CI-like, ~2 min)
make test

# Quick iteration without race detector
make test-fast

# Run tests for a specific package
make test-vault   # internal/vault tests
make test-config  # internal/config tests

# Run tests with coverage
make test-coverage
make test-coverage-html  # opens HTML report in browser

# Run the full CI-like suite (race + coverage + 30m timeout)
make test-ci
```

## Linting and formatting

```bash
make fmt        # format Go source
make fmt-check  # check formatting without modifying files
make lint       # run golangci-lint
make vet        # run go vet (includes passlint analyzer)
```

## Submitting changes

1. Create a feature branch from `main`:
   ```bash
   git checkout -b feat/my-feature main
   ```
2. Make your changes, then run the full test suite and lint:
   ```bash
   make fmt-check test vet lint
   ```
3. Commit with a conventional message:
   ```bash
   git commit -m "feat(scope): what this does"
   ```
4. Push and open a pull request:
   ```bash
   git push origin feat/my-feature
   gh pr create --fill
   ```
5. Ensure all CI checks pass on your PR.

### Merge policy

- **Squash merge** is the only allowed merge method. No merge commits or
  rebase merges.
- **Branch protection** is enforced on `main`: CI (`CI Success`), strict
  context, required conversation resolution, no force pushes, no deletions.
- For a solo-maintained repo, required approving reviews is set to 0 (GitHub
  does not count the PR author's own review). If you are the maintainer, your
  CI gate is the enforcement — not a second reviewer.

## Coding standards

- **Formatting:** All Go code must pass `gofmt` (`make fmt-check`).
- **Linting:** All Go code must pass `golangci-lint` (`make lint`).
- **Tests:** New code must be covered by meaningful tests. Run `make test-coverage`
  to check. Coverage gates are enforced during release.
- **Error handling:** Use `%w` for error wrapping when the wrapped error should
  be inspectable via `errors.Is`/`errors.As`. Do not wrap for decoration only.
- **Agent instructions:** These conventions are also captured in
  [AGENTS.md](AGENTS.md) for automated coding agents (Hermes, Claude Code,
  OpenCode). Both human contributors and agents follow the same rules.

## Issue triage

Issues are labeled with priority (`priority: urgent` through `priority: low`)
and type (`bug`, `feature`, `documentation`). See the [Labels](#labels) section
of the GitHub repository for the full taxonomy. To claim an issue, comment on
it — if you're an automated agent, the `auto-claimed` label is applied
automatically.

## Releases

- Releases are managed via GitHub Releases with GoReleaser.
- Release milestones are milestone-scoped (not iteration/sprint-based).
- The full release flow is documented in `docs/release-process.md` and
  automated via the `gh-coding-complete` pipeline (sync → audit → release).

## Security

See [SECURITY.md](SECURITY.md) for reporting vulnerabilities.
**Do not** open public issues for security vulnerabilities — use the GitHub
Security Advisory "Report a vulnerability" flow instead.

## Code of conduct

Be respectful and constructive. This is a volunteer-driven project;
maintainers may ask you to rework or resubmit contributions that don't meet
the standards above.
