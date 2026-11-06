# Contributing to Symaira Vault

Symaira Vault is an open-source, age-encrypted password manager for terminal
users and AI agents. We welcome contributions from the community.

This document describes how to set up a development environment, run tests, and
submit changes.

## Prerequisites

- **Rust/Cargo:** use the toolchain pinned in `rust-toolchain.toml` (no Go toolchain is needed)
- **Python 3:** required by the contract and CI helper scripts under `scripts/`
- **Git:** for building and version stamping
- **Make:** to use the provided targets
- **On macOS:** Xcode Command Line Tools (linker and keyring integration)

### Optional (client/macOS GUI build)

- **Xcode-beta:** the SwiftUI client requires `DEVELOPER_DIR=/Applications/Xcode-beta.app/Contents/Developer`
- **xcodegen:** to regenerate `client/Symvault.xcodeproj` from `client/project.yml`

## Building

```bash
# Build the CLI binary (target/release/symvault)
make rust-cli

# Build the macOS client (requires full Xcode with the iOS SDK)
bash scripts/build-vaultcore.sh
cp target/release/symvault symvault   # the app embeds ../symvault (client/project.yml)
swift build --package-path client
```

## Testing

```bash
# Whole workspace: nextest + doctests
make rust-test

# One crate
cargo test -p symvault-store

# Coverage
make rust-coverage
```

## Linting and formatting

```bash
cargo fmt --all           # format Rust source
make rust-lint            # rustfmt check + Clippy with -D warnings
make rust-security        # cargo audit + cargo deny
```

## Submitting changes

1. Create a feature branch from `main`:
   ```bash
   git checkout -b feat/my-feature main
   ```
2. Make your changes, then run the full test suite and lint:
   ```bash
   make rust-lint rust-test
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

- **Formatting:** All Rust code must pass `cargo fmt --all --check` (`make rust-lint`).
- **Linting:** All Rust code must pass Clippy with `-D warnings` (`make rust-lint`).
- **Tests:** New code must be covered by meaningful tests. Run `make rust-coverage`
  to check. Coverage gates are enforced during release.
- **Error handling:** Propagate errors with `?` and keep the underlying error as
  `source()` so it stays inspectable. Do not stringify an error just to wrap it.

## Issue triage

Issues are labeled with priority (`priority: urgent` through `priority: low`)
and type (`bug`, `feature`, `documentation`). See the repository's
[Labels page](https://github.com/danieljustus/symaira-vault/labels) for the full taxonomy. To claim an issue, comment on
it — if you're an automated agent, the `auto-claimed` label is applied
automatically.

## Releases

- Releases are managed via GitHub Releases with GoReleaser (the Rust builder; no Go toolchain is involved).
- Release milestones are milestone-scoped (not iteration/sprint-based).
- The full release flow is documented in `docs/release-process.md` and
  automated via the `gh-coding-complete` pipeline (sync → audit → release).

## Security

See [SECURITY.md](../SECURITY.md) for reporting vulnerabilities.
**Do not** open public issues for security vulnerabilities — use the GitHub
Security Advisory "Report a vulnerability" flow instead.

## Code of conduct

Be respectful and constructive. This is a volunteer-driven project;
maintainers may ask you to rework or resubmit contributions that don't meet
the standards above.
