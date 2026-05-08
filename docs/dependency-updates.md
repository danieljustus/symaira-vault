# Dependency Update Runbook

A procedural guide for evaluating, testing, and merging dependency updates for
OpenPass. This runbook applies to all direct and transitive Go module
dependencies. Its goal is to keep the dependency tree current and secure while
avoiding unplanned breakage in a password manager where stability is
safety-critical.

> **Scope**: Go module dependencies managed via `go.mod` / `go.sum`.  
> **Work item**: OPENPASS-469  
> **Last reviewed**: 2026-04-27

---

## Table of Contents

1. [Overview](#overview)
2. [Evaluation Criteria](#evaluation-criteria)
3. [Test Protocol](#test-protocol)
4. [Deferral Decision Template](#deferral-decision-template)
5. [Update Process](#update-process)
6. [Emergency Updates](#emergency-updates)
7. [Roles and Responsibilities](#roles-and-responsibilities)
8. [References](#references)

---

## Overview

OpenPass is a command-line password manager that handles sensitive user
secrets. A compromised or broken dependency could result in data loss,
unintended exposure, or build failures. This runbook establishes a repeatable,
documented workflow for dependency updates so that every change is evaluated
for risk, validated against tests, and traceable to a decision record.

### Guiding Principles

| Principle | Application |
|-----------|-------------|
| **Security first** | CVEs and security advisories take precedence over feature updates. |
| **Minimal blast radius** | Prefer patch and minor updates; treat major updates as feature projects. |
| **Evidence-based decisions** | Every deferral must have a written justification with a review date. |
| **Auditability** | All dependency changes are tracked in commit messages and `go.mod` comments. |

### What This Runbook Does NOT Cover

- Automated dependency bots (Dependabot, Renovate) — not enabled for this
  project.
- Vendor directory management — not used; Go modules are source of truth.

---

## Evaluation Criteria

Every dependency update must be classified by **semantic version delta** and
assessed for **risk to OpenPass**.

### Version Classification

| Delta | Example | Risk Level | Evaluation Focus |
|-------|---------|------------|------------------|
| **Patch** | `v1.2.3` → `v1.2.4` | Low | Changelog review for security fixes or bug fixes. Usually safe to merge after green CI. |
| **Minor** | `v1.2.3` → `v1.3.0` | Medium | Review changelog for new features, deprecations, or behavior changes. Run full test suite. |
| **Major** | `v1.2.3` → `v2.0.0` | High | Treat as a breaking-change project. Assess API compatibility, migration guide, and upstream stability. |

### Risk Assessment Matrix

Evaluate across four dimensions. Score each **Low / Medium / High**. An update
scoring **High** in any dimension requires explicit deferral or a dedicated
task.

| Dimension | Questions to Ask |
|-----------|------------------|
| **Crypto / Security** | Does the dependency touch encryption, hashing, randomness, or network TLS? Does the update change any of those code paths? |
| **API Stability** | Are any exported APIs that OpenPass (or its direct deps) uses marked as changed or deprecated? |
| **Transitive Impact** | Is this dependency indirect? Does it feed into a critical direct dependency (e.g., `go-git`, `age`)? |
| **Upstream Trust** | Is the maintainer responsive? Is the release signed or tagged by a known key? Are there open CVEs for the target version? |

### Concrete Example: Current Deferred Updates

The following updates are **intentionally deferred** as of the 2026-04-20 audit.
They illustrate how the criteria above are applied in practice.

#### 1. `github.com/ProtonMail/go-crypto` — v1.1.6 → v1.4.1

| Dimension | Assessment |
|-----------|------------|
| Version delta | **Major** (v1.1 → v1.4) |
| Crypto / Security | **High** — this is a cryptographic library. Breaking changes in crypto APIs could silently alter encryption behavior consumed by `go-git`. |
| API Stability | **High** — three minor versions ahead; upstream may have refactored internal signing or parsing paths. |
| Transitive Impact | **Medium** — indirect only (`go-git` → `ProtonMail/go-crypto`). OpenPass has no direct import. Risk is contained in `go-git`. |
| Upstream Trust | **Low** — ProtonMail is a known maintainer, but the jump is large and not yet adopted by `go-git`. |

**Decision**: Defer until `go-git` upgrades its own dependency or provides a
migration advisory. No action required from OpenPass maintainers.

#### 2. `github.com/golang/protobuf` — v1.5.4 (deprecated)

| Dimension | Assessment |
|-----------|------------|
| Version delta | N/A — library is **deprecated** by Google. |
| Crypto / Security | **Low** — protobuf parsing is not in OpenPass's threat model. |
| API Stability | **Medium** — replacement is `google.golang.org/protobuf`. Migration is upstream's responsibility. |
| Transitive Impact | **Low** — indirect only (`go-git` → `groupcache` → `golang/protobuf`). `google.golang.org/protobuf` v1.36.7 is already present as a transitive dependency. |
| Upstream Trust | **Low** — deprecation is official; migration path documented by Google. |

**Decision**: Defer until `groupcache` (or `go-git`) migrates off the deprecated
module. The deferral may become irrelevant without OpenPass intervention.

---

## Test Protocol

The following checklist must be completed **before any dependency update is
merged** to `main`. For patch updates, some steps may be combined if CI is
trusted; for major updates, every step is mandatory.

### Pre-Merge Checklist

- [ ] **1. Isolate the change**  
  Create a dedicated branch: `deps/<module>-<old>-to-<new>`.

- [ ] **2. Review the delta**  
  Inspect the upstream changelog, release notes, and commit diff:
  ```bash
  # Example for a GitHub-hosted module
  open https://github.com/<org>/<repo>/compare/v1.2.3...v1.2.4
  ```

- [ ] **3. Update and tidy**  
  ```bash
  go get <module>@<version>
  go mod tidy
  go mod verify
  ```
  Ensure `go.sum` changes are limited to the expected module graph.

- [ ] **4. Static analysis**  
  ```bash
  go vet ./...
  golangci-lint run   # if installed locally
  ```

- [ ] **5. Unit and integration tests**  
  ```bash
  go test ./...
  ```
  All tests must pass. If the dependency is used in integration tests (e.g.,
  `go-git` in repository tests), run those explicitly:
  ```bash
  go test -run TestRepository ./...
  ```

- [ ] **6. Build verification**  
  ```bash
  go build ./...
  ```
  Confirm no compilation errors on the target Go version (currently Go 1.26.3).

- [ ] **7. Cross-compilation smoke test**  
  Because OpenPass ships for multiple platforms:
  ```bash
  GOOS=linux   GOARCH=amd64 go build -o /dev/null .
  GOOS=darwin  GOARCH=arm64 go build -o /dev/null .
  GOOS=windows GOARCH=amd64 go build -o /dev/null .
  ```

- [ ] **8. Runtime smoke test**  
  Perform a quick manual end-to-end test:
  ```bash
  go build -o openpass-test .
  ./openpass-test version
  ./openpass-test init /tmp/op-test-vault
  ./openpass-test --vault /tmp/op-test-vault set test.password --value "smoke-test-42"
  ./openpass-test --vault /tmp/op-test-vault get test.password
  rm -rf /tmp/op-test-vault openpass-test
  ```

- [ ] **9. Check for new indirect dependencies**  
  If `go.mod` gained new indirect entries, evaluate each with the [Risk
  Assessment Matrix](#risk-assessment-matrix).

- [ ] **10. Document the decision**  
  Summarize findings in the PR description. Link to the upstream changelog.

### When to Escalate

Escalate to the security lead (see [Roles](#roles-and-responsibilities)) if:

- The dependency is cryptographic (`golang.org/x/crypto`, `filippo.io/age`,
  `ProtonMail/go-crypto`, etc.).
- The update addresses a CVE with CVSS ≥ 7.0.
- The update removes or changes network/TLS behavior.
- The full test suite fails and the failure root cause is unclear.

---

## Deferral Decision Template

Use this template when an update is **intentionally postponed**. Record the
template in `go.mod` as a block comment directly above the relevant `require`
line, or in the PR description if deferral is decided during review.

```markdown
### Deferral Record: <module>

| Field | Value |
|-------|-------|
| **Dependency name** | `<module>` |
| **Current version** | `vX.Y.Z` |
| **Proposed version** | `vX.Y.Z` |
| **Risk level** | Low / Medium / High |
| **Version delta** | Patch / Minor / Major |
| **Breaking changes assessment** | <summary: yes/no/unknown — which APIs are affected> |
| **Test results** | <summary: passed / failed / not run — link to CI run> |
| **Decision** | Merge / Defer / Emergency-merge |
| **Justification** | <why this decision was made> |
| **Review date** | `YYYY-MM-DD` |
| **Owner** | `@github-handle` |

#### Notes

- <any additional context, upstream links, or prerequisites>
```

### Example: ProtonMail/go-crypto Deferral (from go.mod)

```markdown
### Deferral Record: github.com/ProtonMail/go-crypto

| Field | Value |
|-------|-------|
| **Dependency name** | `github.com/ProtonMail/go-crypto` |
| **Current version** | `v1.1.6` |
| **Proposed version** | `v1.4.1` |
| **Risk level** | High |
| **Version delta** | Major (effectively) |
| **Breaking changes assessment** | Unknown — upstream has not published a migration guide for the v1.1 → v1.4 jump. Crypto APIs may have changed. |
| **Test results** | Not run — deferral decided during audit before update attempt. |
| **Decision** | Defer |
| **Justification** | Dependency is transitive-only (via go-git). OpenPass has no direct import. Upgrade risk is contained in the upstream `go-git` project. Defer until `go-git` adopts the new version or provides migration guidance. |
| **Review date** | 2026-07-20 |
| **Owner** | @danieljustus |

#### Notes

- Dependency path: `OpenPass → go-git → ProtonMail/go-crypto`
- `go-git` v5.18.0 still requires `ProtonMail/go-crypto` v1.1.x.
- Re-evaluate after next `go-git` minor release.
```

### Example: golang/protobuf Deferral (from go.mod)

```markdown
### Deferral Record: github.com/golang/protobuf

| Field | Value |
|-------|-------|
| **Dependency name** | `github.com/golang/protobuf` |
| **Current version** | `v1.5.4` |
| **Proposed version** | N/A (deprecated) |
| **Risk level** | Low |
| **Version delta** | N/A |
| **Breaking changes assessment** | No breaking changes expected; module is frozen. Replacement module `google.golang.org/protobuf` is already in the transitive graph. |
| **Test results** | N/A |
| **Decision** | Defer |
| **Justification** | This is a deprecated transitive dependency pulled in by `groupcache`. OpenPass does not import it directly. The correct fix is for `groupcache` (or `go-git`) to migrate to `google.golang.org/protobuf`. No action required from OpenPass until upstream moves. |
| **Review date** | 2026-07-20 |
| **Owner** | @danieljustus |

#### Notes

- Dependency path: `OpenPass → go-git → groupcache → golang/protobuf`
- `google.golang.org/protobuf` v1.36.7 is already present as a transitive dep.
- This deferral may resolve itself without OpenPass intervention.
```

---

## Update Process

### Standard Workflow

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│ 1. IDENTIFY     │────▶│ 2. EVALUATE     │────▶│ 3. TEST         │
│ Update available│     │ Risk & scope    │     │ Run protocol    │
└─────────────────┘     └─────────────────┘     └─────────────────┘
                                                        │
                        ┌─────────────────┐            ▼
                        │ 5. MERGE        │◀─── 4. DOCUMENT
                        │ Tag & close     │     Decision + PR
                        └─────────────────┘
```

#### Step 1: Identify

- Check for available updates:
  ```bash
  go list -u -m all
  ```
- Or review GitHub Security Advisories for the Go ecosystem.
- Create a task in Plane (work item prefix `OPENPASS-`) to track the update.

#### Step 2: Evaluate

- Apply the [Evaluation Criteria](#evaluation-criteria).
- Determine if the update is patch, minor, or major.
- If risk is **Low** → proceed to testing.  
  If risk is **Medium** → proceed with caution; note any deprecations.  
  If risk is **High** → use the [Deferral Decision Template](#deferral-decision-template) and move to deferral tracking.

#### Step 3: Test

- Follow the [Test Protocol](#test-protocol) checklist.
- All steps must pass. Failures are blockers.

#### Step 4: Document

- Open a PR with a clear title: `deps: bump <module> from vX.Y.Z to vX.Y.Z`
- PR description must include:
  - Changelog summary
  - Risk assessment result
  - Test checklist with all items checked
  - Any manual smoke-test commands run
- For deferrals: open a **tracking issue** instead of a PR, and record the
decision in `go.mod` comments.

#### Step 5: Merge

- Require **one approving review** for patch/minor updates.
- Require **two approving reviews** for major updates or any crypto/security
dependency.
- Merge with a clean commit message:
  ```
  deps: bump <module> from vX.Y.Z to vX.Y.Z

  - Reviewed upstream changelog: <link>
  - Risk assessment: Low/Medium/High
  - Full test suite: passing
  - Smoke test: passing
  ```
- After merge, verify CI on `main` passes.
- Close the associated Plane work item.

### Deferral Tracking

When an update is deferred:

1. Record the deferral in `go.mod` using a block comment (see [Examples](#example-protonmailgo-crypto-deferral-from-gomod)).
2. Create a tracking issue labeled `dependencies` and `deferred`.
3. Set a calendar reminder for the **Review date**.
4. Re-evaluate on the review date or when the upstream dependency releases a
   new version.

---

## Emergency Updates

An **emergency update** is any dependency change required to address a
**security-critical CVE** or an **active exploit** in the dependency tree.

### Trigger Conditions

| Severity | Action |
|----------|--------|
| **Critical (CVSS ≥ 9.0)** | Immediate emergency update. Bypass normal scheduling. |
| **High (CVSS 7.0–8.9)** | Emergency update within 48 hours of identification. |
| **Medium (CVSS 4.0–6.9)** | Standard workflow, expedited if the CVE affects crypto/network paths. |
| **Low (CVSS < 4.0)** | Standard workflow, next scheduled maintenance window. |

### Emergency Procedure

1. **Assess exposure**  
   Determine whether OpenPass is actually vulnerable:
   ```bash
   # Check if the vulnerable module is in the module graph
   go list -m all | grep <vulnerable-module>
   # Check if OpenPass imports it directly or indirectly
   go list -deps ./... | grep <vulnerable-package>
   ```

2. **Identify the fix version**  
   Use the upstream security advisory or `go list -u -m` to find the patched
   version.

3. **Apply with minimal change**  
   ```bash
   go get <module>@<patched-version>
   go mod tidy
   ```
   Do **not** bundle unrelated dependency updates in the same commit.

4. **Fast-track testing**  
   Run the full [Test Protocol](#test-protocol), but in parallel where possible:
   - CI pipeline (unit tests, build)
   - Local smoke test (vault init, set, get)
   - Cross-compilation check

5. **Review and merge**  
   - Ping the security lead for expedited review.
   - Merge with the commit message prefix `security:` instead of `deps:`.
   - Example:
     ```
     security: bump golang.org/x/crypto to v0.50.1

     Fixes CVE-2026-XXXXX (CVSS 8.2) in TLS certificate verification.
     - Exposure: indirect via filippo.io/age
     - Full test suite: passing
     - Smoke test: passing
     - Advisory: https://github.com/advisories/GHSA-xxxxx
     ```

6. **Post-merge actions**  
   - Tag a patch release if the vulnerability affects a released version.
   - Update the security advisory log (see [References](#references)).
   - Notify users via GitHub Security Advisory if the CVE affects published
     binaries.

### Rollback Plan

If an emergency update introduces a regression:

```bash
# Revert the module change
go get <module>@<previous-version>
go mod tidy
# Open a revert PR immediately
# Tag a hotfix release if the previous version was already published
```

---

## Roles and Responsibilities

| Role | Responsibility | Current Assignee |
|------|----------------|------------------|
| **Dependency Owner** | Monitors for updates, runs evaluations, opens PRs, maintains `go.mod` comments. | Project maintainers |
| **Security Lead** | Reviews all crypto/security dependency changes; approves or blocks emergency updates. | Project lead (`@danieljustus`) |
| **Reviewer** | Validates test evidence in PRs; approves merge for non-emergency updates. | Any maintainer |
| **Release Manager** | Tags releases after security merges; publishes GitHub Security Advisories when needed. | Project lead (`@danieljustus`) |

### Rotation and Escalation

- If the Security Lead is unavailable, any maintainer may approve a **critical**
  (CVSS ≥ 9.0) emergency update, but must document the decision in the PR and
  notify the lead within 24 hours.
- Deferred updates are re-evaluated quarterly or when the upstream dependency
  releases a new version — whichever comes first.

---

## References

### Current Deferred Dependencies

| Module | Current | Proposed / Target | Status | Review Date |
|--------|---------|-------------------|--------|-------------|
| `github.com/ProtonMail/go-crypto` | `v1.1.6` | `v1.4.1` | Deferred — wait for `go-git` migration | 2026-07-20 |
| `github.com/golang/protobuf` | `v1.5.4` | Migrate to `google.golang.org/protobuf` | Deferred — wait for `groupcache` migration | 2026-07-20 |

See inline comments in [`go.mod`](../go.mod) for full deferral rationale.

### Useful Commands

```bash
# List all modules with available updates
go list -u -m all

# Show why a module is required
go mod why -m <module>

# Show the full module graph
go mod graph

# Verify module checksums
go mod verify

# Audit for known vulnerabilities
go run golang.org/x/vuln/cmd/govulncheck@latest ./...
```

### External Resources

- [Go Modules Reference](https://go.dev/ref/mod)
- [Semantic Versioning](https://semver.org/)
- [GitHub Security Advisories](https://github.com/advisories)
- [Go Vulnerability Database](https://pkg.go.dev/vuln/)

---

*End of runbook. For questions or process improvements, open a PR against this
document or discuss in the project's issue tracker.*
