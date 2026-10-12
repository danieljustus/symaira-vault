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

## Shared boundaries

This is preserved work in progress, not migration completion or merge/release approval. Preserve exact Go/Rust byte contracts, original failed captures, source/compiler provenance, security policies and independent native-platform gates. Cross-compilation and source-only tests do not prove native execution. Never manufacture expected results, weaken a deadline, discard a mismatching row or change an oracle only to make a comparison pass. Signing, releases, productive cutover, Go retirement and destructive cleanup require separate authorization. Do not start paid models or services.

Local automatic continuation has been disabled and the owned unfinished work parked. This document does not restart automation. Existing remote CI may run from the ordinary push; no workflow dispatch, merge, tag or release is requested.

## Reproduction environment

Start at the repository root of a direct GitHub clone and check out the immutable final HEAD provided by the external verification receipt. Do not substitute the branch's later tip. Use Python 3 (closeout host: 3.14.2), Git (closeout host: 2.54.0) and the exact Rust 1.98.0 components in `rust-toolchain.toml`. `Cargo.toml`/`Cargo.lock` and, for Go oracles, `go.mod`/`go.sum` remain authoritative. GitHub and the public package registries must be reachable. No package installation or cloud runtime is implied by these instructions.

For local Mac development, respect the host's existing storage/build launcher and reserve policy. The host's mounted-drive paths and private launcher are not cloud inputs: use ordinary owned output/temp/cache directories on a suitable cloud filesystem instead, without weakening product permission checks. Use isolated HOME/XDG fixture state, never real user stores. Native Apple GUI, Keychain/Touch ID, signing and filesystem tests require the real supported OS/hardware and authorization. Native Linux and Windows observations must run on those systems.

Fresh-checkout verification at the final handoff HEAD is pending until the separate PR comment is published. The external comment records exact commands, exits, failures and runtime limits without recursively changing this commit. A successful source inventory or Python test is not a full application build.

## Retained and excluded inputs

Build outputs, package caches, Python bytecode, local control databases, private orchestration reports and the completed local cache-cleanup script are not shipped. None is an allowed replacement for missing source. Originals remain local. Historical local acceptance receipts are not silently treated as public or independently verified by this document; any needed unpublished immutable receipt remains an explicit blocker below. No credentials, `.env` values, production data, personal memory or signing keys are included. Provision target credentials only through the operator's approved secret manager if a later explicitly authorized operation needs them.

No submodules or Git LFS inputs were found in the inspected source inventory. Check locks and any downstream platform-specific dependencies again before their own gates. The portable source checkpoint is separate from native-runtime, access and acceptance readiness.
