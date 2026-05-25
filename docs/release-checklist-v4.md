# Release Checklist — v4.0.0

The release manager ticks every box below before running `git tag v4.0.0` and
pushing the tag. The checklist is a hard gate: a missing tick blocks the
release.

The checklist matches ADR-0004 §7.12 plus the standard distribution gates we
run on every minor.

---

## Pre-flight (run from a clean checkout of `main`)

- [ ] `git status` is clean.
- [ ] `git pull --ff-only origin main` succeeds (no divergence).
- [ ] Working tree is on `main`, not a feature branch.
- [ ] `make clean` removes all build artifacts (no `*.test`, `*.out`,
      `symvault` binary, `coverage/` dir in repo root). The goreleaser
      pre-hook would otherwise reject the build.
- [ ] `go env GOWORK` is empty (or set via `env GOWORK=off`).

## Build & static analysis

- [ ] `make build` succeeds on the release machine.
- [ ] `make vet` is clean (includes `passlint` analyzer).
- [ ] `make lint` exits 0. `golangci-lint` findings, if any, are documented in
      the PR that introduced them and explicitly approved.
- [ ] `make fmt-check` is clean.

## Tests

- [ ] `make test-fast` is green on macOS.
- [ ] `make test-fast` is green on Linux (or wait for CI to report green on
      the merge commit).
- [ ] CI matrix on the v4 commit is green for all OS targets (macOS, Linux,
      Windows).
- [ ] Security regression suite (`internal/mcp/server/security_*_test.go`,
      `internal/mcp/server/tools_value_exposure_test.go`,
      `cmd/passlint`) green.
- [ ] Tier-preset snapshot tests (`internal/config/tier_presets_test.go`) green.
- [ ] Skill golden-file tests (`internal/agentskill/skill_test.go`) green.

## Documentation

- [ ] `CHANGELOG.md` has a `## [v4.0.0]` entry with the correct date and the
      breaking changes called out at the top.
- [ ] `docs/migration-v3-to-v4.md` is up-to-date with the shipped CLI surface
      and does not reference any non-existent intermediate version.
- [ ] `docs/skills/openpass-agent/UPGRADE-TO-V4.md` is up-to-date.
- [ ] `docs/adr/0004-cli-agent-optimization-v4.md` status is `Accepted` (not
      `Draft`).
- [ ] `README.md` v4 section (if any) reflects the new `symvault agent` CLI.
- [ ] `docs/agent-integration.md` and `docs/mcp-api.md` reflect the v4 tool
      surface (7-tool lean mode, `openpass_whoami`, `openpass_audit_self`,
      `openpass_search`, structured errors).

## Manual smoke (per platform)

The release manager runs these by hand. Skip a row only with a written
justification in the release PR.

### macOS

- [ ] `symvault agent install hermes --tier safe` succeeds end-to-end (config
      written, token issued, skill dropped, smoke test passes).
- [ ] `symvault agent upgrade hermes --tier standard` shows the spec'd diff
      and the upgrade applies after confirmation.
- [ ] Real Hermes session can call `mcp_openpass_openpass_whoami` and
      `mcp_openpass_get_entry` against the upgraded profile.
- [ ] `OPENPASS_AGENT=hermes symvault list --output json` respects the
      profile's `allowedPaths`.
- [ ] `symvault migrate v4` on a real v3 vault is lossless (round-trip:
      restore backup, re-run, no diff).
- [ ] LaunchAgent HTTP setup: `symvault serve --port 8765` reachable; GUI
      approval prompt pops via `secureui`.
- [ ] Skill drift detection: edit `~/.hermes/skills/symvault/SKILL.md`,
      `symvault agent doctor hermes` reports drift.

### Linux

- [ ] `symvault agent install claude-code --tier safe` succeeds.
- [ ] Basic vault ops (`symvault init` on a fresh dir, `symvault set`,
      `symvault get`, `symvault list`) work.
- [ ] systemd unit (if shipped) launches `symvault serve` cleanly.

### Windows

- [ ] `symvault agent install codex --tier safe` succeeds; path handling for
      `~/.codex/config.toml` correct.
- [ ] Basic vault ops work.

## Distribution dry-run

- [ ] `goreleaser release --snapshot --clean` produces all expected artifacts
      under `dist/`.
- [ ] `dist/openpass_*.tar.gz` and `dist/openpass_*_windows_*.zip` extract and
      `./symvault version` prints the expected version string.
- [ ] Checksums file is generated and includes every artifact.
- [ ] SBOM (`*.sbom.json`) is generated.
- [ ] Homebrew tap formula renders without unresolved templates.
- [ ] Scoop manifest renders.
- [ ] Nix flake builds: `nix build .#symvault` succeeds from a clean store.
- [ ] macOS notarization gate (separate workflow) passes on a signed snapshot
      build.

## Security & supply-chain

- [ ] `make vet` includes `passlint`; analyzer is loaded.
- [ ] `govulncheck ./...` reports no actionable vulnerabilities (deferred
      transitive CVEs documented in `docs/dependency-evaluations/`).
- [ ] Code-scanning (gosec/CodeQL) on `main`: 0 open alerts.
- [ ] Dependabot alerts on the repo: 0 open.
- [ ] No secrets in the release tree: goreleaser pre-hook passes
      (`identity.age`, `mcp-token`, `.env`, `coverage`, `*.test`).

## Release artifact

- [ ] Decide tag: `v4.0.0` (final) or `v4.0.0-rc.1` / `v4.0.0-beta.1`. Tag
      message includes the breaking-changes summary.
- [ ] Tag is signed (`git tag -s v4.0.0`) and `git verify-tag v4.0.0` checks
      out.
- [ ] Push tag: `git push origin v4.0.0`.
- [ ] CI release workflow completes successfully; GitHub release is created
      with the rendered changelog.
- [ ] Release notes include a prominent link to
      `docs/migration-v3-to-v4.md` and
      `docs/skills/openpass-agent/UPGRADE-TO-V4.md`.
- [ ] Homebrew tap PR auto-opens (or the bot updates the formula) and is
      reviewable.

## Post-release

- [ ] Install the published binary on a fresh machine (or VM/container) via
      the install script and confirm `symvault version` matches.
- [ ] `brew install symvault && symvault version` works after the tap merges.
- [ ] Update project page on <https://github.com/users/danieljustus/projects/1>
      (issues/PRs moved to Done).
- [ ] Announce in the README badge area and any external channels.
- [ ] File any acceptance-criteria gaps from ADR-0004 §10 that landed as
      follow-ups, so v4.1 planning has a clean starting list.

---

## Sign-off

| Role | Name | Date |
|---|---|---|
| Release manager | | |
| Security review | | |
| Docs review | | |

Once all boxes above are ticked and signed off, the release is GA. If any box
remains unchecked, either complete it or open a release-blocking issue and
stop.
