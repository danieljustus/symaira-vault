# Rust MCP deadline diagnostic continuation

## Goal and source identity

Repository: `danieljustus/symaira-vault`. Remote branch: `handoff/20261012-rust-wip`.
Base code commit: `2baba416c6297837c2195ab34d9de874cb5fbd20`. Related draft PR [#1321](https://github.com/danieljustus/symaira-vault/pull/1321) remains separate and is not updated here.

This preserves locale-independent fixture controls and the source-bound original Linux/x86 deadline diagnostic, including generated-input capture at consumption and its pinned-format correction. The exact diagnostic patch and source identities are versioned under `scripts/rust-port/`; the diagnostic base `01f7daae181eba3a34bc90382cfb58e7fa9925c8` remains in branch ancestry. CoreKit is pinned to public `27177f25f551cecefa7bd6c4524abf175b3a75c7`.

## Concrete next task and actual checks

### Windows fixture CI repair

The failed Windows execution at `75632b48201b41ed7b37ad8897afff0ce5c86984`
was investigated with a separately retained real capture at
`e76c311a28148bb6367fb327b1cc11959cb9a6e2` in
[run 38225199721](https://github.com/danieljustus/symaira-vault/actions/runs/38225199721).
Only `timeout_protocol_error` differed: the filtered self-child returned success
instead of executing its existing sleeping test and reaching the one-second
deadline. Historical `TestMain` returned immediately on Windows because the
suite opt-in is deliberately absent from the production child's environment.

The correction admits the deliberately injected timeout-child marker in the
test entrypoint. `windows-timeout-child-admission-v1` applies only that exact
entrypoint delta in the two disposable Windows oracle contexts, records its
original/materialized hashes and diff, and includes it in the complete compiler
input inventory before building. This is a separately bound test preparation,
not unchanged historical replay. Immutable reference commits, frozen fixture
bytes, production filtering and the one-second assertion remain unchanged.

Local controls pass: eight compiler/source controls (one compiler-dependent
case separately opt-in), 20 oracle controls and 12 diagnostic controls. A real
macOS compiler regression also passed both 13-case lanes and the intentional
invalid-cache rejection before this Windows-only correction; that result does
not establish Windows acceptance. Independent review approved the source and
provenance delta and required the deterministic adapter mutation controls in
CI. `mcp-oracle-controls` now runs those controls; its compiler-dependent case
remains separately opt-in. Three production Go timeout tests and package vet
also pass locally. Native CI for the final repair is still pending. Resolve
that gate before continuing the original formatting/compiler/diagnostic-admission
task below.

```sh
python3 -B -m unittest discover -s scripts/rust-port -p test_mcp_deadline_diagnostic.py -v
```

Actual prepublication result: all 12 noncompiling controls pass, exit 0. They include real file/descriptor capture, patch applicability and fail-closed entrypoints; they are not native deadline observations.

Next verify the whole formatting gate on this exact source in a non-nested isolated checkout, then reconcile the retained compiler receipt and independently authorize the existing source-bound Linux/x86 diagnostic. Read `.github/workflows/rust-mcp-process.yml` and `scripts/rust-port/mcp_deadline_diagnostic.py`; do not supply invented admission hashes or dispatch before the source/compiler prerequisites pass.

## Unresolved inputs and acceptance gates

### Diagnostic source repair (#1378)

The admission review of `1d238722038124b00a7dbbd384782f644cbe7c30`
returned `REQUEST_CHANGES`; that commit is not admitted. The repair preserves
the product source, 150 ms request budget, 100/500 ms assertions, owning suite
counts and default concurrency. Only the frozen diagnostic patch changes its
test server: transient read timeouts retain partial headers and retry within
the existing stop/deadline bound. The added write timeout is removed.

Post-suite provenance rejection now produces a nonzero diagnostic exit while
retaining the original suite exit independently. All diagnostic control steps
use the admitted Python. Diagnostic-only step limits total 111 minutes inside
a 120-minute job, including 10 minutes for upload and 9 minutes of job margin.
The original ordinary 40-minute job limit and product timing limits are unchanged.
These are limits, not a measured runtime or a guarantee against runner failure.

Local checks: 13 noncompiling controls, 20 oracle controls, and two compiled
Rust 1.98.0 header-reader regressions pass. The socket control waits for actual
50 ms read timeouts and exercises delayed/partial headers, cumulative size
limits, EOF, cancellation and deadline rejection. It compiles the exact helper
from the pinned patch using only the standard library; it does not execute the
owning suite or establish Linux-native acceptance. Ordinary CI runs it separately;
the diagnostic lane excludes it to preserve compiler-input and one-shot boundaries.

A new exact-commit independent review is still required, including transitive
executed scripts and retained-output privacy. Do not reuse the rejected review
digest. Runner tools, caches, tracing rights and capacity remain unverified and
must fail closed. Before an authorized dispatch, record consumption of the one
allowed attempt durably, then retain its returned run ID and exact HEAD. Never
retry an ambiguous dispatch or a rejected/failed run. Clear the two admission
variables after the run terminates; do not revoke them while the job is queued.
No settings write, diagnostic dispatch, merge or release is part of this repair.

- The original Linux broker deadline observation was approximately 914 ms and failed the strict acceptance threshold. Keep the original failure; a diagnostic is not acceptance and a relaxed threshold is not a repair.
- Prior local strict Clippy and no-run compiler receipts cover 36 compiled test programs, zero executed native tests. They are not a full native suite or diagnostic acceptance; raw host receipts are not published by this source-only checkpoint.
- The diagnostic requires independently reviewed source/admission identity, full generated-input closure and its original Linux/x86 environment. Keep repository-variable names and workflow admission logic intact. Required target values/access remain unprovisioned by this handoff.
- Existing MCP oracle/provenance correction and all required native runtime, publication, integration, release and retirement gates remain open. No actual credential-store access is needed or allowed for these fixture tests.
- Target cloud Linux/x86 runtime, tracing rights and workflow variables: not checked.

## Self-maps runtime-input class (#1380)

Authorization: the user explicitly approved, on 2026-10-13, a typed runtime-input class for `/proc/<pid>/maps` evidence, covering design, implementation and independent review. That approval does not perform a diagnostic dispatch: the authorization allows one additional dispatch only after independent review and passed evidence gates, and none was made here. The admission variables and once-only rules are unchanged.

Class `self_maps_runtime`, version 1, is the only representation of these reads. Each record binds one raw entry marker and one raw exit marker of the same reader, the descriptor, buffer address, requested and returned counts, the reader pathname, and the SHA256 of an exclusive `.runtime` blob copied from the reader buffer while it is stopped at syscall exit. Every observed maps path, including rejected variants, stays in `observed`; every read, including repeats, stays in the raw syscall transcript and typed records, and each self-maps entry has a `self_maps_entry` line that must match one record one-to-one. Runtime bytes are never reopened, snapshotted, compared with before/after inventories, or treated as lease-protected generated input. Admission requires the observed self-maps paths and the verified records to be the same set.

Supported model (everything else fails closed):
- Only `read(0)` whose descriptor resolves exactly to `/proc/<reader pid>/maps`, with reader pid equal to tgid. pread, readv, preadv, preadv2, sendfile, splice, copy_file_range and mmap on that path are rejected. Other proc files stay observed and then fail closure as unbound inputs.
- The reader is single-task at entry and at exit. No live CLONE_VM or CLONE_FILES sharer may exist anywhere in the traced tree. A sharer is any traced child created by clone, clone3 or vfork with CLONE_VM or CLONE_FILES and without CLONE_THREAD; it is removed only when it execs or exits. The check is global and conservative; a normal vfork followed by exec is not permanently rejected.
- While a self-maps read is pending, the only stop accepted is the reader's own syscall-exit stop. Any other signal, ptrace event, stop or exit of any traced task, and any pending record at termination, fails the capture. This global rule can reject a capture when unrelated traced processes generate events during a read. That is intended fail-closed behavior; how often it fires under parallel rustc is unknown until native CI.
- Exit must report no error and 0 <= returned <= requested. A zero-length read (EOF) is recorded. Bounds per capture: 8 MiB per read, 1 GiB of retained runtime bytes and 262144 records; exceeding any bound fails closed.
- `/etc/gitconfig` is an owning inventory root when present. Its before/after identity is mandatory; only path, mode, size and SHA256 are retained, never its content.

Limits, not claims: the output is not claimed to be independent of maps bytes. Race freedom against external same-UID writers (for example process_vm_writev from an unrelated process) is not claimed. The glibc `pthread_getattr_np` reader hypothesis is unverified. If a real compiler reads its maps while multi-task, capture fails closed and the diagnostic stays blocked; no product change is made. Whether the real compiler does so is unknown until a native run. Retained runtime blobs contain runner pathnames and address ranges, so they need a privacy review before publication.

Actual evidence: native CI 38412064106 at BASE 29aca3be passed on Linux, macOS and Windows, including the Linux FIONBIO regression. The new native Linux/x86 self-maps controls skip on macOS and are not executed by local checks; they await CI on this commit. Independent review of this commit is pending. Local macOS results at this commit: 30 diagnostic controls on Python 3.14 (24 passed, 6 skipped as native Linux/x86_64-only) and 30 on Python 3.13 (24 passed, 6 skipped); 20 oracle controls passed on Python 3.14; ruff F,E9 clean. The retained repair-1379 clippy capture is rejected by the typed validator because it has no runtime record. No diagnostic run, dispatch, push, merge or release is part of this change. Product thresholds (150 ms request budget, 100/500 ms assertions), the original 914 ms failure, suite argv and counts, leases and generated-input protection, the original target and once-only dispatch are unchanged.

## Shared boundaries

### Explicit runner preparation after the first admitted attempt (#1379)

Run `38312126593` at `6173807fa7e2a1f00fef3b79c8d5029df120c646`
failed before generator or owning-suite execution. Rustup discovery unexpectedly
installed the absent toolchain, then rejected missing rustfmt. Its attempt is
consumed; its evidence and reviewed source remain historical, not acceptance.

The follow-up separates explicitly authorized preparation from execution:
the exact commit/review/attempt admission is checked before preparation;
Python 3.13, Go 1.26.6, Rust 1.98.0 with rustfmt/Clippy and locked Cargo/Go
dependencies are prepared before staging. Both immutable Go reference module
sets and the product module set are downloaded. A separate file-only native
capture checks ptrace/read leases, pidfd and subreaper facilities without
compiling or running product tests. Preparation output is retained separately.
The job ceiling is now 150 minutes: existing execution ceilings 111 minutes,
preparation ceilings 31 minutes and 8 minutes of margin. Ordinary jobs retain
40 minutes; all product timing budgets and test invocations are unchanged.

Discovery sets `RUSTUP_AUTO_INSTALL=0` explicitly, including against an inherited
opt-in. Execution copies only prepared dependency caches into private state;
Cargo is offline and Go child builds preserve `GOPROXY=off`/`GOSUMDB=off`.
A real-rustup regression uses an empty home and a rejecting loopback distribution
server to verify no requests, downloads or installed toolchains. This is a
lookup regression, not native timing evidence. A changed source still requires
a fresh exact-commit independent review before the newly authorized single run.

This is preserved work in progress, not migration completion or merge/release approval. Preserve exact Go/Rust byte contracts, original failed captures, source/compiler provenance, security policies and independent native-platform gates. Cross-compilation and source-only tests do not prove native execution. Never manufacture expected results, weaken a deadline, discard a mismatching row or change an oracle only to make a comparison pass. Signing, releases, productive cutover, Go retirement and destructive cleanup require separate authorization. Do not start paid models or services.

Local automatic continuation has been disabled and the owned unfinished work parked. This document does not restart automation. Existing remote CI may run from the ordinary push; no workflow dispatch, merge, tag or release is requested.

## Reproduction environment

Start at the repository root of a direct GitHub clone and check out the immutable final HEAD provided by the external verification receipt. Do not substitute the branch's later tip. Use Python 3 (closeout host: 3.14.2), Git (closeout host: 2.54.0) and the exact Rust 1.98.0 components in `rust-toolchain.toml`. `Cargo.toml`/`Cargo.lock` and, for Go oracles, `go.mod`/`go.sum` remain authoritative. GitHub and the public package registries must be reachable. No package installation or cloud runtime is implied by these instructions.

For local Mac development, respect the host's existing storage/build launcher and reserve policy. The host's mounted-drive paths and private launcher are not cloud inputs: use ordinary owned output/temp/cache directories on a suitable cloud filesystem instead, without weakening product permission checks. Use isolated HOME/XDG fixture state, never real user stores. Native Apple GUI, Keychain/Touch ID, signing and filesystem tests require the real supported OS/hardware and authorization. Native Linux and Windows observations must run on those systems.

Fresh-checkout verification at the final handoff HEAD is pending until the separate PR comment is published. The external comment records exact commands, exits, failures and runtime limits without recursively changing this commit. A successful source inventory or Python test is not a full application build.

## Retained and excluded inputs

Build outputs, package caches, Python bytecode, local control databases, private orchestration reports and the completed local cache-cleanup script are not shipped. None is an allowed replacement for missing source. Originals remain local. Historical local acceptance receipts are not silently treated as public or independently verified by this document; any needed unpublished immutable receipt remains an explicit blocker below. No credentials, `.env` values, production data, personal memory or signing keys are included. Provision target credentials only through the operator's approved secret manager if a later explicitly authorized operation needs them.

No submodules or Git LFS inputs were found in the inspected source inventory. Check locks and any downstream platform-specific dependencies again before their own gates. The portable source checkpoint is separate from native-runtime, access and acceptance readiness.
