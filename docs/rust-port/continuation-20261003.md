# Vault continuation checkpoint, 2026-10-03

> Historical checkpoint, retained for reproducibility. The continuation branch
> was integrated in #1276 and no longer exists; start current work from `main`.
> The branch, worktree and clone instructions below describe the original
> checkpoint, not the current integration state.

## Goal and exact source

Continue the remaining bounded fixes in `danieljustus/symaira-vault` without needing a previous chat, local machine, or agent skill installation. Preserve the standalone Apache-2.0 credential service and the production Go fallback. This checkpoint is not a release, cutover, complete migration, or management-UI retirement.

- Continuation branch: `handoff/vault-continuation-20261003`.
- Basis code commit: `c72b91000006445a0f953a8b4cd5bfa1dcf1a9f1`.
- Its complete tree equals the regular squash integration of PR [#1272](https://github.com/danieljustus/symaira-vault/pull/1272), `31e5c56fa2e02d986e841d066e2595fbc7630211` on `main`.
- The continuation branch joins those two histories before documentation. Only documentation changes follow the basis code; this retains executable red-control predecessors as ordinary Git history.
- Read `docs/product-boundaries.md`, `docs/commercial-boundary.md`, `docs/rust-port/work-items.json`, and `docs/rust-port/contract-matrix.md` before enlarging scope or changing a migration acceptance state. Earlier resumption entries are historical, not current execution orders.

## Completed changes and verified integrations

The following PR states were reread from GitHub during closeout. Each entry is a completed regular integration, not a release claim.

| PR | Result | Main commit |
| --- | --- | --- |
| [#1228](https://github.com/danieljustus/symaira-vault/pull/1228) | HTTP overflow-peer isolation, secure-input/PTY regression and diagnostic repairs | `6f87e6f014865860ad97fc27c7e76a8f6084cbf8` |
| [#1262](https://github.com/danieljustus/symaira-vault/pull/1262) | Collision-safe CLI test roots, #1085 completed | `08f2d63230050c36278a665c9fab7a7ff28b59a3` |
| [#1263](https://github.com/danieljustus/symaira-vault/pull/1263) | Ten persisted re-encryption crash boundaries, #1003 completed | `cc184c8ddd255dc184b7c7999068927c6ad6aec7` |
| [#1265](https://github.com/danieljustus/symaira-vault/pull/1265) | Real Rust CLI bootstrap for Go test targets, #1259 completed | `e74797105a8fae520a64a6f914871dd0644b269f` |
| [#1266](https://github.com/danieljustus/symaira-vault/pull/1266) | Isolated STORE-004 drift checking and bounded descendant cleanup, #1264 completed | `78272b4dc6c25849f808bfa838262b3f76bcd634` |
| [#1267](https://github.com/danieljustus/symaira-vault/pull/1267) | Tracked Go source-inventory validation, #1128 completed | `f916c108ada7a7e753638f5f3e6371a9f2f549cd` |
| [#1268](https://github.com/danieljustus/symaira-vault/pull/1268) | Config-load approval-mode validation, #1224 completed | `6c4db8ae8813dda8cfe6c768a9fd9ad2092d5d26` |
| [#1269](https://github.com/danieljustus/symaira-vault/pull/1269) | Rooted oracle archive extraction, #1114 completed; six CodeQL findings confirmed fixed | `8dc53177a60755263eab179fb99239765d7bb9c9` |
| [#1270](https://github.com/danieljustus/symaira-vault/pull/1270) | Close empty native-helper stdin without writing, #1150 completed | `ec4eb72e8fd8e5a8a9aeba53466c0bdefd8e360e` |
| [#1271](https://github.com/danieljustus/symaira-vault/pull/1271) | Precise Git failure-stage and fixture-field diagnostics | `bd9850b46983654fcd352bfef3f48b65bee3cf63` |
| [#1272](https://github.com/danieljustus/symaira-vault/pull/1272) | Resolved Rust API entry policy, serialized/decoded/binary response masking, typed IPv6 authority checks | `31e5c56fa2e02d986e841d066e2595fbc7630211` |

Issue #978 was completed after the earlier #1218 integration. #1144 and #1151 were closed as not planned because the reported artifacts were absent from current main. PR #1227 was closed as redundant: its sole changed file already equals #1228 and main. None of these states is permission to delete older unrelated work.

## API security evidence and explicit limits

At exact `c72b9100`, a final independent read-only security review approved the complete three-file diff with no findings, tracing policy, request rendering, raw/decoded URL fields, binary response projection and authority controls. Six earlier reviews rejected real leaks; their explanations and repairs remain in the public #1272 comments and predecessor commits. Static approval is not runtime evidence.

| Command executed before integration | Actual result |
| --- | --- |
| `cargo test -p symvault-mcp --locked api_review_` | 26 passed |
| `cargo test -p symvault-mcp --locked` | 212 passed, zero failed/ignored |
| `cargo test -p symvault-cli --locked --test mcp_commands_contract` | 36 passed, two existing PTY-only exclusions |
| `cargo clippy -p symvault-mcp -p symvault-cli --all-targets --all-features --locked -- -D warnings` | Passed |
| `cargo build -p symvault-mcp --locked --lib` | Passed |
| `cargo fmt --all --check` and `git diff --check` | Passed |

Exact-head CI [37104261874](https://github.com/danieljustus/symaira-vault/actions/runs/37104261874) completed successfully, including Rust, Miri and protected `CI Success`. Native logs independently confirmed the exact set of all 26 `api_review_*` tests, not merely a filtered zero-test success, on both platforms:

- [macOS job 111149673485](https://github.com/danieljustus/symaira-vault/actions/runs/37104261874/job/111149673485).
- [Windows job 111149673651](https://github.com/danieljustus/symaira-vault/actions/runs/37104261874/job/111149673651).

The required gate and all review/file/closing-reference connections were completely enumerated before the normal non-admin merge. Watcher exit 124 earlier meant a 900-second observation deadline, not a failed CI job. No CI rerun was used as a repair.

Request escaping, outbound bytes, endpoint rejection, authentication and authority restrictions are preserved. Policy denial is asserted before credential reads or dispatch. Tests use synthetic isolated encrypted vaults and bounded loopback echo servers, including byte-preserving binary responses. Public `limit=50` remains visible. The accepted socket is explicitly switched to blocking mode before bounded I/O timeouts to preserve Darwin behavior.

The Go handler still needs resolved-entry policy alignment, now tracked separately in [#1274](https://github.com/danieljustus/symaira-vault/issues/1274). This is not full Go/Rust API parity, MCP-005 promotion, complete HTTP shutdown, cryptographic-format migration or cutover. The earlier attribution of runtime-policy work to #1015 was wrong: #1015 concerns store-fixture determinism.

## Immediate continuation and remaining gates

1. Finish existing Dependabot PR [#1225](https://github.com/danieljustus/symaira-vault/pull/1225), not a replacement implementation. Branch `dependabot/npm_and_yarn/editors/npm_and_yarn-cb24140fdc`, reviewed head `ce2f0dbdf3c8aa978545d9f277a70c7d68004157`. The patch changes only three lock-entry metadata fields for `brace-expansion` 1.1.18 to 1.1.21. Local `npm ci`, build, all 29 tests and registry-integrity verification passed; exact CI [37103575485](https://github.com/danieljustus/symaira-vault/actions/runs/37103575485) and `CI Success` passed. After #1272 integration, GitHub reports BEHIND. Update it by a regular base merge, repeat affected verification and independent exact-head review, then require fresh exact-head CI. Its old green result does not authorize a new head. No force push or admin bypass.
2. Keep the separate remaining `braces` stack-exhaustion advisory [#1273](https://github.com/danieljustus/symaira-vault/issues/1273) visible. `npm audit` reported one distinct high advisory GHSA-vfj7-8cjw-p6xm propagated to 29 dependency packages. The observed latest `braces` was 3.0.3 with no patched version listed. Do not call the audit clean, suppress it, or use a blind major-version audit fix.
3. Address [#1274](https://github.com/danieljustus/symaira-vault/issues/1274) only after tracing the actual Go policy action and defining corrected source-bound observations. Do not import the unrelated dirty Go-policy worktree wholesale.
4. #1073 and #1099 remain open. #1271 adds diagnostics, not a proven historical root-cause resolution. For #1073 obtain the precise case/field drift before changing classifiers or regenerating fixtures. For #1099 preserve stage, original Windows code-5 error and cleanup evidence; no blind retry, timeout increase or temp-root change. Windows permits more than one valid delete/open outcome; the allocator test protects distinct still-held names instead.
5. Select later independent work only after rereading its issue and ledger dependencies. The table below names the unresolved boundaries; it is not an instruction to start a global backlog or release sweep.

| Issue/group | Boundary and owner decision/evidence required |
| --- | --- |
| #1002 | Maintainer decision on versioned KDF/concurrency resource ceilings, envelope compatibility, migration and rollback |
| #1006 | Maintainer decision on aggregate memory/in-flight read budget and explicit Go/Rust compatibility |
| #1015 | Store ciphertext/temp-root noise versus meaningful exact-byte contract; repeated real generator evidence before normalization |
| #1026 | Deliberate corrected-oracle pin refresh or versioned historical Windows archive exception; preserve provenance |
| #1220 | Correct/freeze Go shutdown callback, drain, pending-approval and mutation semantics before claiming Rust graceful shutdown |
| #1145 | Ordinary Windows reader plus path-safe cleanup, redaction, bytes/timeouts/errors evidence on applicable Windows and ARM runtime |
| #1140 / #1237 | CONNECT implementation belongs to the historical unmerged candidate; current API echo-helper fix is not CONNECT acceptance |
| #870, #938, #1243, #1251 | Real device, biometric, Swift/native or iOS evidence is unavailable locally; macOS compilation is not substitution |
| #1236 through #1257 | Respect existing migration/dependency/release gates. No ledger promotion from a compiled crate, fixture, or historical CI alone |

## Delegated decisions, 2026-10-03

The maintainer delegated the remaining product and compatibility decisions on
2026-10-03 and requested their rationale in repository docs. The earlier table
is a historical checkpoint; product choices no longer require another
maintainer confirmation. [ADR 0007](../adr/0007-argon2-resource-policy.md) selects
versioned Argon2 execution budgets, explicit local legacy migration and rollback.
Its implementation/verification gates remain required before closing #1002.
Further decisions are recorded with their owning implementation as the relevant
boundaries are inspected. Device, biometric, signing and release observation
evidence still requires actual execution; delegation cannot replace it.

## Remote inputs and local inventory decisions

No local untracked source, stash or private service is an input to the continuation branch. Intake checked all registered worktrees, branch tips, stashes, tracked/untracked state and ignored-file inventories. No stashes were present. The active API and Dependabot verification worktrees were clean.

| Unit | Decision and reproducibility |
| --- | --- |
| Accepted production changes and all 26 API regressions | Published in main, #1272 source branch and this continuation history; all necessary source/lockfiles tracked |
| Original API test-only and rejected predecessor commits | Retained as ancestors of this continuation branch; use isolated Git checkouts for red controls, never alter main or the current candidate to reproduce them |
| Worker re-encryption predecessor | Published separately as `archive/vault-worker-reencrypt-20261002` at `36fcc5491dd657b0c07159c44ea8dd422384d7a3`; superseded provenance, not an accepted replacement for #1263 |
| Worker temporary-root predecessor | Published separately as `archive/vault-worker-temp-roots-20261002` at `72387f61885605f5e2a2eb53770caf83eb3ac254`; superseded provenance, not an accepted replacement for #1262 |
| Worker config predecessor | Published separately as `archive/vault-worker-approval-config-20261002` at `dae7b43e522fdf2a06d8fa76ecf0e45d3114df2e`; partial evidence, not integrated wholesale |
| Bootstrap worker alias | `e74797105a8fae520a64a6f914871dd0644b269f` is already the reachable #1265 main integration; no independent input |
| Dependabot verification alias | Contains no unique source: obtain exact `ce2f0dbd` from the #1225 remote branch or PR ref. Ignored node_modules are rebuilt with `npm ci` |
| Go URL-spelling probe | Public synthetic source/input/expected output retained in `docs/rust-port/evidence/api-1222/`; four real stdlib net/url observations, not generated by an LLM |
| Local sweep report and bounded CI-watch scripts | Do not upload raw internal reports with paths/operational metadata. Their relevant decisions, exact heads, public links and continuation instructions are translated into this document. Poll GitHub directly; the local watcher script is not a dependency |
| Superseded review prompts/results, local logs and scratch patches | Raw operational documents excluded; substantive findings and exact final evidence are in public PR comments, this checkpoint and tracked regression sources. Runtime tests reproduce the behavior; old invocations are historical, not regenerated receipts |
| Cargo target, Go caches/oracle binaries, node_modules, coverage and generated tsbuildinfo | Generated/cache units, excluded from Git; reproduce using the commands below and tracked lockfiles. No force-add or cache copying |
| Older ignored audit/agent/editor config, mobile frameworks, local databases, machine paths and macOS metadata | Outside this bounded work or sensitive/local-only; untouched, not needed to build/test the public checkout |
| Files named for another repository in a shared evidence folder | Unrelated work, excluded from this repository's handoff |

Three pre-existing dirty worktrees are explicitly outside the owned inputs: `migration/http-shutdown-resume-20260929`, `migration/mcp-api-go-policy-20260930`, `migration/mcp-api-review-fixes-20260930`. Their source and untracked files remain untouched; their successful bits do not silently validate or publish all their WIP. Older `fix/blocker-lane-20260930`, `handoff/20260930-cloud` and `fix/1226-factory-lint-20260930` are likewise not cleaned globally. No global branch-pruning helper was run because it could delete unrelated historical remote branches. Remote fetch and owned-branch checks were performed explicitly.

The main continuation needs no archive branch as a build input. The three archive refs retain original owned source evidence if a later audit asks for it. Original local worktrees are retained, not destroyed merely because the remote is available.

The frozen oracle archive tag is public and separately verified:

- `oracle/cxf-manifest-9acbc5c5` tag object `d2be8a52467f82d739eaea5c7afae621dca0e93f`.
- Peeled source `9acbc5c5d0f7f78cdb386da3d7117624f68e7844`.
- Fetch tags/history before oracle gates. The source is not a main ancestor; the approved archival tag preserves it. Do not replace this with a false ancestry claim or a fixture hash edit.

## Setup, test and safe startup

Work at the repository root. Observed local tools: macOS arm64, Rust/Cargo 1.98.0, Go 1.27.1 installed, Node 22.22.3, npm 10.9.8. The repository pins Rust 1.98.0 and Go 1.26.6; select the latter explicitly for Go oracle work. Node 20 is used by the editor CI; local Node 22 evidence is not an execution claim for Node 20.

Install existing platform build prerequisites and Git, rustup, Go, Node/npm and optionally gh. Use the checked-in workflows/Makefile for full native gates; do not install a new automation dependency. Cargo uses the tracked Cargo.lock; Go uses go.mod/go.sum; editors use editors/package-lock.json. Registry access to GitHub, crates.io, the public Go module proxy and npm is needed if the ordinary package caches are empty. The public pinned CoreKit Go module must download successfully; no sibling checkout or private replacement module is allowed. No Git submodule or Git LFS pointer is required by this checkpoint.

```sh
git clone --branch handoff/vault-continuation-20261003 \
  https://github.com/danieljustus/symaira-vault.git vault-continuation
cd vault-continuation
unset CARGO_TARGET_DIR SYMVAULT_VAULT SYMVAULT_PASSPHRASE SYMVAULT_ALLOW_ENV_PASSPHRASE
export GOTOOLCHAIN=go1.26.6 GOWORK=off
git fetch origin --tags
git rev-parse HEAD
git status --porcelain=v1 -uall
rustup toolchain install 1.98.0 --profile minimal --component rustfmt --component clippy
cargo fetch --locked
GOTOOLCHAIN=go1.26.6 GOWORK=off go mod download
cargo fmt --all --check
make docs-check
cargo test -p symvault-mcp --locked api_review_
cargo test -p symvault-mcp --locked
cargo test -p symvault-cli --locked --test mcp_commands_contract
cargo clippy -p symvault-mcp -p symvault-cli --all-targets --all-features --locked -- -D warnings
cargo build -p symvault-cli --locked
target/debug/symvault version
mkdir -p target/handoff
cp docs/rust-port/evidence/api-1222/url_oracle.go.txt target/handoff/url_oracle.go
GOTOOLCHAIN=go1.26.6 go run target/handoff/url_oracle.go \
  < docs/rust-port/evidence/api-1222/url_oracle.input.json \
  > target/handoff/url_oracle.actual.json
python3 -c 'import json; from pathlib import Path; actual=json.loads(Path("target/handoff/url_oracle.actual.json").read_text()); expected=json.loads(Path("docs/rust-port/evidence/api-1222/url_oracle.expected.json").read_text()); assert actual == expected and len(actual) == 4; print("Go URL oracle: 4 exact vectors passed")'
```

The probe source is retained with `.go.txt` to avoid changing generator source inventories. The commands materialize that public source in the ignored build directory and compare decoded JSON, including all four values and three escaped spellings. This generated copy is reproducible from Git, not an undeclared local dependency. Python 3 is required for the comparison and existing repository verification scripts.

For #1225, use a separate ordinary fresh clone of its remote branch, verify its exact head, and execute from `editors/`:

```sh
npm ci
npm run build
npm test
npm ls brace-expansion
npm audit --json
```

The last command is expected to exit nonzero for the separate #1273 finding. Inspect it, do not suppress it. Full repository follow-up commands are `make test`, `make lint`, `make build`, `make port-contract` and the workflow-specific native gates; the full set was not rerun merely for this documentation checkpoint.

No operator credential variables are required by the synthetic tests. Do not forward `SYMVAULT_VAULT`, `SYMVAULT_PASSPHRASE`, `SYMVAULT_ALLOW_ENV_PASSPHRASE` or credential-provider variables from a real installation. `GOTOOLCHAIN` and `GOWORK` are non-secret selectors. `GH_TOKEN` may be needed for authorized GitHub writes, but its value must come from the runner's approved secret provisioning and must never be recorded. Safe startup here means the `version` subcommand only, not opening an operator vault, daemon or keychain. The compatibility parser deliberately rejects `--version`; the first fresh-checkout attempt exited 1 for that incorrect documentation command, and the corrected subcommand exited 0 with `symvault dev`.

## Fresh-checkout evidence and target-cloud limits

An ordinary fresh clone from GitHub at `c836e32ef7328f04e977e67963b9ffafbc5c6513` was actually exercised on local macOS arm64. No linked worktree, stash, copied target directory, local untracked source or private sibling checkout was used. The full production/code/manifests diff against `c72b9100` was empty. `CARGO_TARGET_DIR` and operator vault/passphrase variables were removed; Go was explicitly 1.26.6 with `GOWORK=off`. Normal installed registry/module caches were reused; this is not an empty-cache network test or target-cloud execution.

| Fresh-clone command | Actual result |
| --- | --- |
| `rustup toolchain install 1.98.0 --profile minimal --component rustfmt --component clippy` | Exit 0 |
| `cargo fetch --locked` and `go mod download` | Exit 0 for both; pinned public dependencies resolved without sibling replacements |
| `cargo fmt --all --check` and `make docs-check` | Exit 0 for both |
| `cargo test -p symvault-mcp --locked api_review_` | Exit 0, exact set of 26 named cases passed |
| `cargo test -p symvault-mcp --locked` | Exit 0, 212 passed, zero failed/ignored |
| `cargo test -p symvault-cli --locked --test mcp_commands_contract` | Exit 0, 36 passed, two existing PTY exclusions |
| `cargo clippy -p symvault-mcp -p symvault-cli --all-targets --all-features --locked -- -D warnings` | Exit 0 |
| `cargo build -p symvault-cli --locked` | Exit 0, CLI artifact built in the fresh checkout |
| `target/debug/symvault version` | Exit 0, `symvault dev`; corrected the failed documentation-only `--version` attempt |
| Public Go URL probe and decoded-JSON equality check shown above | Exit 0, all four vectors and every spelling exactly matched |

The checkout had no tracked/untracked source changes after Rust/probe verification. Repository inventory confirmed no submodule or Git LFS input and that all referenced contracts exist. The final receipt edit only documents these outcomes; it does not alter the exercised code or test inputs.

A separate fresh GitHub clone of #1225 at exact `ce2f0dbdf3c8aa978545d9f277a70c7d68004157` passed `npm ci`, `npm run build`, all 29 tests and `npm ls brace-expansion` (1.1.21) on the same Node 22.22.3/npm 10.9.8 runtime. `npm audit --json` again exited 1 for exactly the one #1273 advisory propagated to 29 packages. The two build-generated tracked tsbuildinfo outputs are disposable verification outputs, not unpublished source. This is not fresh-head acceptance after a future base update and not a Node 20 execution claim.

Earlier native evidence remains scoped to `c72b9100` and run 37104261874. A documentation-only branch may have no Actions run due to path filtering; that must be reported as absent, not green. Main-merge CI, if pending, likewise does not inherit the PR-head conclusion.

Target agent cloud runtime, write permissions, secret provisioning and network policy: **not checked**. No target-cloud agent job, paid model/provider, production service, user keychain or physical iOS device was started by this handoff. Native macOS/Windows CI evidence belongs to the linked GitHub-hosted jobs, not to an arbitrary cloud environment. GUI, Touch ID, signed native apps and iOS/Windows ARM device acceptance require their actual platform and permissions.

## Operating rules for the next agent

Use isolated named branches and one writer per change unit. Read the actual code and its callers before patching. Preserve wire bytes, safety/approval checks, existing oracle pins and standalone-first behavior. Inventory added/removed tracked Go source as well as modified files. Generator changes can invalidate generator digests; re-freeze only the proven provenance fields using the real generator and keep behavioral vectors unchanged unless an explicitly reviewed contract changes them.

Create regular non-draft PRs for complete reviewed changes. Incomplete preservation work must be labelled honestly and must not auto-merge. Bind review and tests to the exact SHA; enumerate all gate-relevant GitHub connections through their last page. Required checks must be registered, completed and successful on that exact head. Never weaken protections, treat a missing check as success, use admin bypass or infer a merge from a successful push. Verify merge, issue closure and claim release separately. Do not commit/push unrelated work, delete original evidence, rotate credentials, change signing identity, deploy production, pay for an API, or perform a breaking/major migration without the appropriate separate approval.

Next bounded task: refresh and finish #1225 through normal protections, then choose #1274 or a separately proven independent issue. Recheck GitHub because this document is a snapshot, not a lease on remote state.
