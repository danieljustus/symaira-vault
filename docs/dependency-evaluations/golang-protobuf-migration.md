# Migration Assessment: github.com/golang/protobuf to google.golang.org/protobuf

**Work Item:** OPENPASS-467  
**Date:** 2026-04-27  
**Status:** Deferred — Accept Status Quo with Monitoring

---

## 1. Current Dependency Chain Analysis

### 1.1 Direct Dependency Graph

```
Symaira Vault
├── github.com/go-git/go-git/v5 v5.19.1 (direct)
│   └── github.com/golang/groupcache v0.0.0-20241129210726-2c02b8208cf8 (indirect)
│       └── github.com/golang/protobuf v1.5.4 (indirect, DEPRECATED)
│           └── google.golang.org/protobuf v1.36.11+ (indirect)
└── google.golang.org/grpc v1.81.1 (indirect)
    └── github.com/golang/protobuf v1.5.4 (indirect, DEPRECATED)
        └── google.golang.org/protobuf v1.36.11+ (indirect)
```

### 1.2 go.mod Evidence

From `go.mod` (lines 7, 12, 37, 104, 144, 145):

```go
// github.com/golang/protobuf: v1.5.4 (deprecated, migration to google.golang.org/protobuf needed)
// Symaira Vault → go-git → groupcache → golang/protobuf (deprecated)

require (
    github.com/golang/groupcache v0.0.0-20241129210726-2c02b8208cf8 // indirect
    google.golang.org/grpc v1.81.1 // indirect
    google.golang.org/protobuf v1.36.11 // indirect
)
```

**Key Observation:** `google.golang.org/protobuf v1.36.11` is already present as a transitive dependency. The deprecated `github.com/golang/protobuf v1.5.4` is itself a thin compatibility wrapper around `google.golang.org/protobuf` (since v1.4.0+). Both modules coexist without runtime conflicts.

### 1.3 Why Symaira Vault Cannot Directly Fix This

- Symaira Vault has **zero direct imports** of either protobuf package
- The deprecated dependency enters through **two independent paths**:
  1. `go-git` → `groupcache` → `golang/protobuf`
  2. `grpc` → `golang/protobuf`
- Any replacement or exclusion would require either:
  - Forking/replacing `groupcache` (breaks `go-git` compatibility)
  - Forking/replacing `grpc` (used by transitive deps, high blast radius)
  - Using `replace` directives in `go.mod` (fragile, shifts maintenance burden)
  - Patching upstream `groupcache` and `grpc` (requires community coordination)

---

## 2. Upstream Assessment: groupcache

### 2.1 Official Repository Status

| Attribute | Value |
|-----------|-------|
| Repository | `github.com/golang/groupcache` |
| Last Commit | 2024-11-29 (`2c02b8208cf8`) |
| Releases | **None published** |
| Open Issues | 25 |
| Open PRs | 18 |
| Maintenance | Effectively unmaintained for structural changes |

### 2.2 Migration Issue: #150

**Title:** "Migrate protobuf to google.golang.org."  
**URL:** https://github.com/golang/groupcache/issues/150

| Attribute | Value |
|-----------|-------|
| Status | **Open** (since 2021-08-05 — ~4.5 years) |
| Assignee | None |
| Labels | None |
| Milestone | None |
| Linked PRs | None |
| Activity | No maintainer engagement visible |

**Verdict:** The official `golang/groupcache` repository has shown **no active interest** in migrating off the deprecated protobuf package. Issue #150 has languished without assignee, labels, or linked PRs for nearly 5 years.

### 2.3 Current go.mod in groupcache

```go
module github.com/golang/groupcache
go 1.20
require github.com/golang/protobuf v1.5.4
require google.golang.org/protobuf v1.33.0 // indirect
```

Groupcache still **directly requires** the deprecated module. There is no branch, PR, or commit in the official repo that removes this dependency.

---

## 3. Forks and Alternatives with Migration

### 3.1 Active Forks That Migrated

| Fork | Migration Status | Trade-offs |
|------|------------------|------------|
| `groupcache/groupcache-go` (thrawn01) | **Migrated** in V3 refactor (Apr 2024). Uses `buf` + updated protobuf API. | New module path, API changes, not a drop-in replacement for `go-git` |
| `ksong0xd/groupcache` | **Migrated** to proto3 + `google.golang.org/protobuf`. | Adds gRPC, Kubernetes dependencies; heavily diverged from upstream |
| `modernprogram/groupcache` | Fork of `mailgun/groupcache`; unclear if protobuf migrated. | Active releases (latest Jan 2026), but still appears to use deprecated dep |

### 3.2 Why Fork Substitution Is Not Viable for Symaira Vault

- `go-git` explicitly imports `github.com/golang/groupcache` — not a fork
- Swapping the module path requires a `replace` directive or forking `go-git` itself
- Both options introduce significant maintenance burden and compatibility risk
- `go-git` is a core dependency (Git integration); destabilizing it is unacceptable

---

## 4. go-git Upstream Assessment

| Attribute | Value |
|-----------|-------|
| go-git v5 | Still depends on `github.com/golang/groupcache` (latest commit, Nov 2024) |
| go-git v6 (in dev) | Still shows `github.com/golang/groupcache` in dependency tree |
| go-git activity | High — active development, but no move away from groupcache |

go-git is a widely used library (7K+ stars, consumed by Kubernetes ecosystem, Gitea, Pulumi). If go-git moves away from groupcache, that would break the chain for Symaira Vault automatically. However, there is **no indication** go-git plans to replace groupcache.

---

## 4.5 grpc Upstream Assessment

| Attribute | Value |
|-----------|-------|
| grpc v1.81.1 | Still depends on `github.com/golang/protobuf` v1.5.4 |
| grpc v1.81.1 (latest) | **Still depends on `github.com/golang/protobuf` v1.5.4** |
| grpc migration status | No active migration off deprecated protobuf observed |

**Verdict:** Even upgrading to the latest grpc release (v1.81.1) does **not** remove the deprecated `golang/protobuf` dependency. grpc remains a second, independent path for the deprecated module. This was verified by inspecting the grpc module graph — the `golang/protobuf` edge persists.

---

## 5. Risk Assessment

### 5.1 Functional Risk: **LOW**

- `github.com/golang/protobuf v1.5.4` is a compatibility shim over `google.golang.org/protobuf`
- No runtime bugs, security CVEs, or compilation failures attributed to this specific version
- The Go team maintains the shim; it will not be removed from the module proxy

### 5.2 Technical Debt Risk: **LOW–MEDIUM**

- `go mod tidy` and vulnerability scanners flag the deprecated module
- Creates noise in dependency audits (like the one that produced this work item)
- No actual blocking behavior — builds, tests, and releases continue to work

### 5.3 Future-Proofing Risk: **MEDIUM**

- If the Go team ever removes `github.com/golang/protobuf` from the module proxy (unlikely in the near term), all consumers would break
- More realistically: if `groupcache` becomes incompatible with future Go toolchain changes, the unmaintained state becomes a problem

---

## 6. Timeline Recommendation

### Scenario A: Wait for Upstream (Recommended)

**Probability:** Medium  
**Timeline:** Indefinite (years, not months)

Wait for one of these events:
1. `golang/groupcache` merges a protobuf migration PR (unlikely given 4.5-year inactivity on #150)
2. `go-git` replaces `groupcache` with an alternative or drops the dependency
3. The Go ecosystem collectively forks/migrates away from the official groupcache

**Why this is viable:** The deprecated module is a harmless shim. There is no urgency.

### Scenario B: Force Resolution

**Probability:** Achievable, but high cost  
**Timeline:** Days to weeks of engineering + ongoing maintenance

Options:
1. **Open PR to `golang/groupcache`** — Requires protobuf regeneration, testing, and maintainer review. Given repo inactivity, merge is uncertain.
2. **Open PR to `go-git`** — Replace groupcache or vendor a patched version. High review bar; may be rejected as out of scope.
3. **`replace` directive in Symaira Vault `go.mod`** — Pin to a forked groupcache. Fragile; breaks `go install` from remote; creates maintenance burden.

**Why this is NOT recommended:** The cost/benefit ratio is poor. The problem is cosmetic (deprecated flag), not functional.

### Scenario C: Accept Status Quo

**Probability:** Certain  
**Timeline:** Immediate

Acknowledge the deprecated transitive dependency, document it, and move on. Re-audit periodically (e.g., every 6 months).

---

## 7. Decision

### ✅ DECISION: Accept Status Quo with Periodic Re-assessment

**Rationale:**

1. **No functional impact.** `github.com/golang/protobuf v1.5.4` is a maintained compatibility wrapper. Builds pass. Tests pass. No CVEs.
2. **No viable upstream path.** `groupcache` issue #150 has been open since 2021 with zero maintainer engagement. The repository is effectively in maintenance-only mode.
3. **Intervention is disproportionately expensive.** Forcing a replacement would require either patching two upstream projects (`groupcache` + `go-git`) or maintaining a fork, all to remove a deprecation warning on a transitive dependency.
4. **Natural resolution is possible.** If `go-git` ever drops `groupcache`, or the Go ecosystem coalesces around an active fork, this resolves without Symaira Vault taking any action.

### Action Items

| Action | Owner | Frequency |
|--------|-------|-----------|
| Re-audit dependency tree for groupcache/protobuf changes | Symaira Vault maintainers | Every 6 months |
| Monitor `golang/groupcache#150` for any activity | Symaira Vault maintainers | Ad hoc |
| Monitor `go-git` release notes for groupcache replacement | Symaira Vault maintainers | Per go-git update |
| Monitor `grpc` release notes for protobuf migration | Symaira Vault maintainers | Per grpc update |
| Update this document if upstream situation changes | Symaira Vault maintainers | As needed |

---

## 8. Quarterly Re-Evaluation Log

| Date | Evaluator | Status | Notes |
|------|-----------|--------|-------|
| 2026-04-20 | Sisyphus-Junior | DEFER | groupcache issue #150 still open; no upstream migration |
| 2026-04-28 | Sisyphus | DEFER | Quarterly check: no upstream changes; scheduled workflow active |
| 2026-05-05 | Sisyphus | DEFER | Re-audit discovered **second path**: `grpc` → `golang/protobuf`. Tested grpc v1.81.0 upgrade — deprecated dep persists. No viable resolution path. |
| 2026-06-22 | Sisyphus-Junior | DEFER | Re-audit for #536: grpc at v1.81.1, still depends on `golang/protobuf`. groupcache #150 still open (no new activity since Apr 2024). No upstream changes. |
| 2026-06-29 | Sisyphus | DEFER | Quarterly re-audit for #584: groupcache still at v0.0.0-20241129210726 (no new commits since Nov 2024). grpc v1.81.1 still directly requires `github.com/golang/protobuf v1.5.4`. No upstream migration activity. Status quo remains. |
| 2026-07-07 | Sisyphus | DEFER | Re-audit for #617: groupcache issue #150 still open, no maintainer engagement. groupcache still directly requires `github.com/golang/protobuf v1.5.4`. grpc v1.81.1 still depends on `github.com/golang/protobuf v1.5.4`. Direct update is not possible; status quo maintained. |

---

## 9. References

### Upstream Issues
- [golang/groupcache #150 — Migrate protobuf to google.golang.org](https://github.com/golang/groupcache/issues/150) (Open since 2021-08-05)

### Upstream Repositories
- [golang/groupcache](https://github.com/golang/groupcache) — Official repo, effectively unmaintained for structural changes
- [go-git/go-git](https://github.com/go-git/go-git) — Active, still depends on official groupcache
- [groupcache/groupcache-go](https://github.com/groupcache/groupcache-go) — Active fork with V3 protobuf migration (not a drop-in replacement)

### Migration Documentation
- [Go Protobuf Migration Guide](https://deepwiki.com/golang/protobuf/5-migration-guide) — General guidance for `github.com/golang/protobuf` → `google.golang.org/protobuf`
- [github.com/golang/protobuf #1451 — Deprecated notice discussion](https://github.com/golang/protobuf/issues/1451)

### Related Ecosystem Migrations
- [grpc/grpc-go #6919 — Merged PR migrating off deprecated protobuf](https://github.com/grpc/grpc-go/issues/6919) (completed Jan 2024)
- [googleapis/google-cloud-go #4273 — Cloud client libraries migration](https://github.com/googleapis/google-cloud-go/issues/4273) (completed Apr 2024)

---

*Document generated as part of OPENPASS-467. Do not modify `go.mod` or source code based on this assessment without revisiting the Decision section above.*
