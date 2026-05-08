# Dependency Evaluation: ProtonMail/go-crypto v1.1.6 → v1.4.1

**Work Item:** OPENPASS-466  
**Date:** 2026-04-27  
**Evaluator:** Sisyphus-Junior (autonomous)  
**Scope:** Transitive dependency via `github.com/go-git/go-git/v5`

---

## Executive Summary

**Recommendation: DEFER — Wait for go-git v5.x to bump the dependency.**

OpenPass has zero direct exposure to `ProtonMail/go-crypto` APIs. The dependency is used exclusively by `go-git/v5` for OpenPGP signature verification during Git operations. The go-git maintainers have deliberately kept the v5.x release branch on `ProtonMail/go-crypto v1.1.x` (up to v1.1.6) despite v1.4.1 being available, indicating a conservative stability posture. Upgrading this transitive dependency independently would create an untested dependency combination with marginal security benefit for OpenPass's specific use case (local vault Git sync).

---

## Compatibility Matrix

| go-git Version | ProtonMail/go-crypto Version | Go Min Version | Notes |
|----------------|------------------------------|----------------|-------|
| v5.13.0 | v1.1.3 | 1.21 | Reverted in v5.13.1 due to host key mismatch regressions |
| v5.14.0–v5.15.x | v1.1.4–v1.1.5 | 1.21 | Incremental bumps within v1.1.x |
| **v5.16.0–v5.18.0** | **v1.1.6** | **1.24** | **Current — stable, no v1.2+ adoption** |
| v6.0.0-alpha / main | v1.4.1 | 1.25 | go-git v6 has adopted v1.4.1 (PR #1933) |

**Key Observation:** go-git v5.18.0 was released on **2026-04-16**, well after go-git main merged `ProtonMail/go-crypto v1.4.1` on **2026-03-28** (PR #1933). The maintainers explicitly chose **not** to backport the v1.4.1 update to the v5.x branch for v5.18.0.

---

## Breaking Changes & Notable Changes (v1.1.6 → v1.4.1)

### v1.2.0 (2025-04-11)
- **Min Go version bumped to 1.22.0** ([#278](https://github.com/ProtonMail/go-crypto/pull/278))
- **Max AEAD chunk size increased** from 64 KiB to 4 MiB ([#280](https://github.com/ProtonMail/go-crypto/pull/280))
- Risk: Low — behavioral change in streaming encryption, unlikely to affect go-git's usage

### v1.3.0 (2025-05-22)
- **API v2: Tolerate invalid key signatures** if at least one verifies ([#284](https://github.com/ProtonMail/go-crypto/pull/284))
- **Enforce acceptable hash functions** in clearsign operations ([#281](https://github.com/ProtonMail/go-crypto/pull/281))
- **Decompressed message size limit** configurable ([#285](https://github.com/ProtonMail/go-crypto/pull/285))
- **API v1: Restrict acceptable hashes** when writing signatures ([#286](https://github.com/ProtonMail/go-crypto/pull/286))
- Risk: Low–Medium — stricter hash validation could reject previously accepted signatures in edge cases

### v1.4.0 (2026-01-07 / 2026-02-27)
- **Min Go version bumped to 1.23** ([#294](https://github.com/ProtonMail/go-crypto/pull/294))
- **Armor whitespace handling** — ignore leading/trailing whitespace in armor body ([#288](https://github.com/ProtonMail/go-crypto/pull/288))
- **New insecure opt-in flags** for non-critical subpackets ([#291](https://github.com/ProtonMail/go-crypto/pull/291), [#292](https://github.com/ProtonMail/go-crypto/pull/292))
- **ECDHv4 security fix:** Error on low-order x25519 public key curve points ([#299](https://github.com/ProtonMail/go-crypto/pull/299))
- **Cleartext security fix:** Only allow valid hashes in header ([#298](https://github.com/ProtonMail/go-crypto/pull/298))
- Risk: Low — security hardening; the stricter cleartext hash check is the main behavioral change

### v1.4.1 (2026-03-18)
- **ECC panic fix:** Invalid curve points now return `errors.KeyInvalidError` instead of **panicking** ([#304](https://github.com/ProtonMail/go-crypto/pull/304))
- Risk: Low — this is a reliability improvement (panic → error), but indicates the v1.1.6 code path could panic on malformed input

---

## Security Fixes Summary

The following CVE-class issues were fixed between v1.1.6 and v1.4.1:

| Fix | Version | Description | Impact on OpenPass |
|-----|---------|-------------|-------------------|
| Low-order x25519 points | v1.4.0 | Rejects malformed ECDHv4 public keys | Very Low — OpenPass vaults use age (X25519 + ChaCha20-Poly1305), not OpenPGP |
| Invalid ECC points panic | v1.4.1 | Panic → controlled error on bad ECC keys | Very Low — only triggered by malformed OpenPGP keys from Git remotes |
| Cleartext hash validation | v1.4.0 | Stricter hash algorithm whitelist | Very Low — OpenPass does not use OpenPGP cleartext signing |

**Important Context:** OpenPass uses `filippo.io/age` for vault encryption. `ProtonMail/go-crypto` is used **only** by `go-git` for OpenPGP commit/tag signature verification during `git pull` / `git push` / `git log` operations. OpenPass does not perform OpenPGP encryption, signing, or key generation.

---

## OpenPass Impact Assessment

### Direct Usage
- **Zero direct imports** of `ProtonMail/go-crypto` in OpenPass source code
- Verified via `grep -r "ProtonMail\|go-crypto\|openpgp" *.go` — no matches

### Indirect Usage (via go-git)
- Git commit automation (`openpass git commit`, auto-commit on edit)
- Git sync operations (`openpass git pull`, `openpass git push`)
- Git log viewing (`openpass git log`)

All Git remotes are **user-configured** (typically the user's own private repository). OpenPass does not clone from untrusted sources.

### Go Version Compatibility
- OpenPass requires **Go 1.26.3**
- `ProtonMail/go-crypto v1.4.0+` requires **Go 1.23.0+**
- **No Go version blocker** — OpenPass's Go version exceeds all minimum requirements

---

## Upstream Status

### go-git v5.x Branch
- Still pinned to `github.com/ProtonMail/go-crypto v1.1.6` as of 2026-04-27
- No open PRs or issues indicating an imminent v1.4.x backport
- Historical pattern: go-git v5.x has been extremely conservative with ProtonMail/go-crypto bumps (stayed within v1.1.x since ~2024)

### go-git v6 / main Branch
- Updated to `github.com/ProtonMail/go-crypto v1.4.1` via [PR #1933](https://github.com/go-git/go-git/pull/1933) (merged 2026-03-28)
- go.mod: `module github.com/go-git/go-git/v6`
- Suggests the go-git project views v1.4.1 as appropriate for v6, but not (yet) for v5

### Relevant Upstream Issues/PRs
- [go-git/go-git #1933](https://github.com/go-git/go-git/pull/1933) — v1.4.1 update merged to main (v6)
- [go-git/go-git #818](https://github.com/go-git/go-git/issues/818) — Historical issue requesting ProtonMail/go-crypto updates (2023)
- [go-git/go-git #1341](https://github.com/go-git/go-git/issues/1341) — v5.13.0 host key mismatch caused by ProtonMail/go-crypto bump, reverted in v5.13.1 (cautionary tale)
- [ProtonMail/go-crypto #304](https://github.com/ProtonMail/go-crypto/pull/304) — v1.4.1 ECC invalid points fix
- [ProtonMail/go-crypto #294](https://github.com/ProtonMail/go-crypto/pull/294) — v1.4.0 Go 1.23 + dependency bumps

---

## Decision

### ❌ Do NOT upgrade independently

**Rationale:**
1. **Untested combination** — go-git v5.18.0 + ProtonMail/go-crypto v1.4.1 has not been validated by the go-git maintainers or the broader ecosystem
2. **Zero direct benefit** — OpenPass does not invoke ProtonMail/go-crypto directly; all exposure is mediated through go-git
3. **Historical precedent** — go-git v5.13.0 previously had to revert a ProtonMail/go-crypto bump due to unexpected SSH/host-key regressions ([go-git/go-git #1341](https://github.com/go-git/go-git/issues/1341))
4. **Low security exposure** — OpenPass's Git usage is limited to user-configured vault remotes; the fixed edge cases (malformed OpenPGP keys, low-order curve points) are extremely unlikely in this context
5. **Maintainer signal** — go-git v5.18.0 was released **after** v1.4.1 was available on main, yet maintainers deliberately kept v5.x on v1.1.6

### ✅ Recommended Action

1. **Monitor go-git releases** — Subscribe to [go-git/go-git releases](https://github.com/go-git/go-git/releases)
2. **Upgrade together** — When go-git v5.19.0+ or v6.0.0 bumps ProtonMail/go-crypto, upgrade `go-git` and let the transitive dependency update naturally
3. **Remove deferral note** — Once go-git adopts v1.4.1+, remove the deferral comment from `go.mod`
4. **No workaround needed** — The current v1.1.6 dependency is stable and functionally sufficient for OpenPass's use case

### Exception (re-evaluate if)
- A **CVE is published** specifically affecting `ProtonMail/go-crypto v1.1.6` with a severity ≥ High that impacts OpenPGP signature verification
- **go-git v5.x explicitly documents** v1.4.1 compatibility
- OpenPass begins **cloning from untrusted Git remotes** (increasing exposure to malformed OpenPGP data)

---

## Quarterly Re-Evaluation Log

| Date | Evaluator | Status | Notes |
|------|-----------|--------|-------|
| 2026-04-27 | Sisyphus-Junior | DEFER | go-git v5.18.0 still on v1.1.6; v6 adopted v1.4.1 |
| 2026-04-28 | Sisyphus | DEFER | Quarterly check: no upstream changes; scheduled workflow active |

---

## Appendix: Dependency Graph

```
OpenPass
└── github.com/go-git/go-git/v5 v5.18.0
    └── github.com/ProtonMail/go-crypto v1.1.6
        ├── github.com/cloudflare/circl v1.3.7
        ├── golang.org/x/crypto v0.17.0
        └── golang.org/x/sys v0.16.0
```

*OpenPass does not import `ProtonMail/go-crypto` directly. The `// indirect` annotation in `go.mod` is correct.*
