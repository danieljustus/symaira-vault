<!-- review: timestamp=2026-07-30T10-18-13Z  repo=danieljustus/symaira-vault  head=58d320b093c2f15d04443ef213923ea9991e12ca -->
<!-- adopt: source=qianniuspace/mcp-security-audit  source_ref=f8caea63debad0d9b0d01ce848375e8fcb66f932  source_url=https://github.com/qianniuspace/mcp-security-audit  depth=clone  license=MIT -->

# Adoption Report — symaira-vault ← qianniuspace/mcp-security-audit — 2026-07-30

## Sources

| Field | Value |
|---|---|
| SOURCE | `qianniuspace/mcp-security-audit` (https://github.com/qianniuspace/mcp-security-audit) |
| Ref analyzed | `f8caea63` (main) |
| Language / License | TypeScript / MIT |
| Health | 54 stars, 9 forks, last push 2025-07-18 (~12 months stale), not archived, no GitHub releases, ~16 KB of source across 5 files |
| Scope | all facets, full clone |
| TARGET | `danieljustus/symaira-vault` @ `58d320b0` |

## Verdict

Zero findings, and the widest gap of the four repos analyzed against this
SOURCE. `symvault` already runs every practice the SOURCE demonstrates, in a
stronger form: `govulncheck` **and** `osv-scanner` in CI, Dependabot, cosign
keyless signing, SLSA build-provenance attestation, an MCP server with masking,
auth and transport layers, and a taint analyzer of its own. The SOURCE's single
capability — look up known vulnerabilities for declared dependencies — is
covered here twice over by tooling that is call-graph-aware, which theirs is
not. Nothing survived the gates, and nothing came close.

## What we already do as well or better

- Dependency vulnerability scanning, the SOURCE's entire product (`src/handlers/security.ts:39`) → [`.github/workflows/ci.yml:38-54`](../../.github/workflows/ci.yml) runs `golang/govulncheck-action` SHA-pinned, and line 75 adds `google/osv-scanner-action` with an `osv-scanner.toml` config. Two independent scanners; theirs is one legacy endpoint.
- Dependency update automation → [`.github/dependabot.yml`](../../.github/dependabot.yml), demonstrably working (commit `fb32f75`, grouped go-dependencies bumps), plus a `deferred-deps-check.yml` workflow. The SOURCE has neither.
- Published-artifact provenance (`npm publish --provenance`, `.github/workflows/publish.yml:18-20,44`) → [`.github/workflows/release.yml:11-12,111-112`](../../.github/workflows/release.yml) grants `id-token: write` + `attestations: write` for SLSA build-provenance attestation, and [`.goreleaser.yml:230-233`](../../.goreleaser.yml) adds cosign keyless `sign-blob` over every artifact. We also implement the *verifying* side ([`internal/update/cosign.go`](../../internal/update/cosign.go)); the SOURCE never checks a signature.
- Stderr-only logging so stdout stays a clean JSON-RPC channel (their `Pitfalls.md` §"MCP 规范") → guaranteed structurally by `symaira-corekit`'s `mcpserver/mcpserver.go:125-128` and `logkit/logkit.go:71`.
- MCP server construction (`src/index.ts`, one file, one tool) → [`internal/mcp/`](../../internal/mcp) carries `auth`, `masking`, `transport`, `serverbootstrap`, `tooldocs`, `errors` and `toolhash.go` as separate concerns, with typed tool definitions and tests.
- Static analysis → `.github/workflows/codeql.yml` plus a purpose-built taint analyzer (`cmd/passlint`, `internal/vault/taint/`) that catches secret-leak paths. The SOURCE runs no static analysis at all.
- CI action pinning → third-party actions are pinned to commit SHAs (`ci.yml:54,75`), and `GITHUB_TOKEN` is not persisted on checkout (commit `9393bb8`). The SOURCE's workflow uses mutable tags throughout.
- Documented threat model → [`docs/threat-model.md`](../../docs/threat-model.md), `SECURITY.md`, `ARCHITECTURE.md`. The SOURCE documents its traps in a 30-line `Pitfalls.md`.
- Test suite → tests beside essentially every package, including `binary_e2e_test.go` and `beta_smoke_test.go`. `src/test/test.ts` upstream is one manual script, ~80% commented out, asserting nothing.

## Findings

None. No candidate from `qianniuspace/mcp-security-audit` survived the four
gates against this repo.

## Considered and rejected

- **Their dependency-audit MCP tool** (`src/index.ts:61-81`) — gate 1 (Transferable) / gate 3 (Better): npm-specific, and `symvault`'s MCP surface is a credential broker. An npm audit tool has no place in it, and the capability is already covered in CI where it belongs.
- **Remote advisory-API lookup instead of a local audit subprocess** (`src/handlers/security.ts:39`, rationale in `Pitfalls.md` §"npm audit 优化") — gate 2 (New): already covered twice (`govulncheck` + `osv-scanner`), and both are call-graph/lockfile-aware rather than one-package-at-a-time.
- **Their per-dependency audit loop** (`src/handlers/security.ts:78-87`) — gate 3 (Better): an anti-pattern. Sequential HTTP round-trip per package against a legacy bulk endpoint, with per-package failures swallowed to `console.error` so a partially-failed audit reads as clean.
- **`npm publish --provenance` + `id-token: write`** (`.github/workflows/publish.yml:18-20,44`) — gate 2 (New): already implemented, in the stronger SLSA + cosign form (`release.yml:11-12`, `.goreleaser.yml:230-233`).
- **`Pitfalls.md` as a gotchas document** — gate 2 (New): `AGENTS.md`, `ARCHITECTURE.md`, `CONTRIBUTING.md` and `docs/threat-model.md` already cover this ground far more thoroughly.
- **Smithery listing + `smithery.yaml`** (`smithery.yaml:1-13`) — gate 1 (Transferable): assumes a Node entrypoint and npm distribution; `symvault` ships via goreleaser, Homebrew and a signed macOS client. No recorded discoverability pain point.
- **Their multi-stage Dockerfile with `--ignore-scripts`** (`Dockerfile:12,32`) — gate 1/gate 2: the `--ignore-scripts` half defends against npm lifecycle scripts, which Go's build model does not have; this repo already ships its own `Dockerfile`.
- **Their publish workflow's auto-tag-and-release** (`.github/workflows/publish.yml:34-48`) — gate 3 (Better): fires on every push to `main`, gates release steps on commit-message substring matching, and uses unpinned third-party actions. Strictly worse than the `06-gh-prerelease`/`07-gh-release` gate flow here.
- **Their `bump` script wrapping `standard-version`** (`package.json:40`) — gate 3 (Better): chains `git add . ; git commit ; git push` with `;`, so every step runs regardless of the previous exit status.
- **CVSS/CWE fields on their vulnerability type** (`src/types/index.ts:19-24`) — gate 2/gate 3: dead code upstream — declared optional, never populated by `processVulnerabilities` (`src/handlers/security.ts:126-137`).
- **Structured `McpError` codes on tool failure** (`src/handlers/security.ts:52`) — gate 2 (New): `internal/mcp/errors/` already covers this, with masking rules layered on top so error text cannot leak secret material — a concern the SOURCE does not have and does not address.

## Open questions

None arising from this SOURCE. It is roughly two orders of magnitude smaller
than this repo and shares only the MCP protocol; there is nothing left
unresolved to investigate.

The single best first step: none — file no issues from this report, and treat
`qianniuspace/mcp-security-audit` as closed for `symvault`.
