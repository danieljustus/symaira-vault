# Symaira Vault Rust Migration Implementation Plan

## Bounded Git descendant-cleanup observation — 2026-10-03

While validating #1233, the unchanged Go Git-I/O oracle reproduced the precise
#1073 drift `GIT-002-go-timeout.expected.descendant_cleanup: expected=true
actual=false` in a managed Linux container. An immediate `kill -0` observation
can see a terminated descendant before the host reaps it. The generator now
waits at most two seconds for that PID to disappear, matching the observation
allowance in the existing native Rust test. The production twenty-second Git
timeout, kill behavior, immutable Go source pin and all transport vectors stay
unchanged. A real child-process negative control proves that a live descendant
is still rejected within the bound and a killed/reaped child is accepted.

Generation followed by the Go freshness check and native Rust Git differential
passes under the container's orphan-reaping wrapper. Only the generator digest
changes in the source-bound fixture. No classifier, production timeout or
expected success outcome is relaxed. This fixes the reproduced observation
race; it does not establish the exact field that drifted in the older five-case
CI runs cited by #1073. Native protected CI and that historical comparison
remain required before claiming the original flake completely resolved.

## Integrated Unix stdio clipboard signals — 2026-09-29

Candidate `b92054f8dc6fa83f99aeaf7c37821e89cd00803d` shares one synchronized
process signal state between hidden input and the active clipboard timer.
Actual Go and Rust child processes prove SIGINT/SIGTERM clear the clipboard
and cancel concurrent hidden input; SIGHUP clears the active timer. A later
idle signal regains its OS default. The CLI installs this router only for
stdio, including piped input without a terminal. HTTP shutdown is separate.

Complete native Darwin/arm64 and Linux/arm64 gates pass:91 core,177 MCP,
36 CLI and60/53 platform tests, source-bound Go differentials, strict Clippy/
formatting and the17-action PTY gate (five restoration checks/two idle signals).
Four Darwin/one Linux host opt-ins remain ignored; two ordinary PTY helpers
are separately exercised by the acceptance gate. Focused process contracts
also passed ten repeated runs each before integration verification.

`clipboard-signals-receipt-b92054f8.json` in both build roots binds the exact
candidate, Cargo paths, Go fixtures and log hashes. HTTP signal fan-out and
graceful shutdown, host clipboard/autotype, Windows TTY and remaining native
targets stay open. No real clipboard or credential provider was exercised.


## Integrated MCP clipboard dispatch — 2026-09-29

Candidate `d5bacb7925232c2e08213be0b8564798f5576486` connects
`copy_to_clipboard` through the existing injected clipboard boundary and
approval/scope checks. Sixteen cases recorded from the actual Go dispatcher
cover preflight ordering, approval reuse, missing values, provider errors,
TTL clearing and timer replacement/runtime-drop cancellation. The production
CLI supplies its existing macOS adapter; tests use synthetic clipboard state.

Independent native Darwin/arm64 and Linux/arm64 gates pass the complete MCP
call/fixture differential, 91 core, 176 MCP, 36 CLI and 59/52 platform tests,
strict all-target Clippy and formatting. The existing 17-action controlling-PTY
gate also passes, including five restoration checks and two idle signals.
Four Darwin/one Linux host-integration opt-ins remain ignored; the two ordinary
PTY helpers are exercised by the dedicated acceptance gate.

`clipboard-receipt-d5bacb79.json` in both existing build roots binds candidate,
Cargo paths, the 16-case fixture and logs. Log SHA-256:
Darwin `0140d58a9881e16d82eafd2ab0dce8ebda47cfd79057ae37327ce6c5eea6bfe3`;
Linux `9d208e8340c64dc1fabd739fd26220caabdf7a1f2b2a9725fb6679fc4a24c9c3`.
Signal-triggered clipboard clearing is separate pending work. Native host
clipboard/autotype, Windows TTY and other required targets remain unverified;
MCP-003 and RUST-010 remain open. No host clipboard or credential state changed.

## Integrated Unix terminal signals — 2026-09-29

Candidate `7be90e81454f1b192f200ba8e496f9ef8009c31e` passes the complete
MCP call/fixture differential, 91 core, 175 MCP, 35 CLI and 59/52 platform
tests on native Darwin/Linux ARM64, plus strict all-target Clippy and formatting.
Four Darwin and one Linux platform opt-ins remain ignored; the dedicated
controlling-PTY acceptance explicitly runs the normal suite's opt-in helper.

The actual Go terminal signal-cancellation oracle and Rust process acceptance
cover SIGINT and SIGTERM during secure input, idle stdio, and ordinary approval.
The PTY driver records 17 actions (10 critical approval, one execute approval,
six hidden inputs), five cooked-mode restoration checks and two idle default
terminations. Canceled inputs do not mutate the vault; subsequent input works.
Ordinary approval restores the terminal before terminating with the original
signal. The process-owned router is installed only by the standalone Unix
stdio MCP CLI when a controlling terminal exists.

`secure-input-signals-receipt-7be90e81.json` in both existing build roots binds
the final candidate, Cargo manifest paths, fixture and logs. Log SHA-256:
Darwin `30b725b82575584be855cd7a9fc080622723bf1f4d629ef4a55d286811388ab2`;
Linux `a7431ffc0f8a69026b1d8864f6bed93efa18cb2e7ee4f7db57f5a2aaf8f4982d`.
This supersedes the earlier Unix external-signal gap. Windows TTY, other required
native targets, GUI and remaining MCP tools stay open. No release, cutover,
Go removal or host credential operation was performed.

## Integrated secure terminal input — 2026-09-29

Candidate `c00841be7cee780d91bbe68376ebda895196ea14` connects secure_input and
request_credential to the existing encrypted Store, shared scope/approval checks,
audit and a hidden controlling-TTY reader. Eleven source-bound actual Go handler
cases and Go's real go-tty rune-editing oracle cover mutation/error semantics.
The generated Go Unicode 15 printable table has an executable freshness check.
Rust deliberately hides characters that Go's go-tty reader echoes.

Independent native Darwin/arm64 and Linux/arm64 gates pass the full MCP
differential, 91 core, 175 MCP, 35 CLI and 59/52 platform tests, plus strict
Clippy/fmt. Four Darwin/one Linux host-integration opt-ins remain ignored; the
two ordinary PTY helpers are exercised through dedicated real controlling-PTY
acceptance. Its 11 prompts prove hidden input, scope approval, Ctrl-C no-write,
ECHO/ICANON restoration and a successful following request with piped MCP stdin.
`secure-input-receipt-c00841be.json` in both build roots binds logs, metadata and
fixture hashes to the candidate. No host credentials or system trust changed.
External SIGINT/SIGTERM restoration, GUI, Windows and remaining native targets
are still open; MCP-003 remains in progress.


## Integrated verified local HTTPS — 2026-09-29

Candidate `3698d45b095c94817ff65ee2de37cf60eac5360a` adds certificate-verified
HTTPS for numeric loopback and statically pinned localhost targets. Request URL
substitution must preserve the validated scheme and authority. Public DNS and
redirects remain rejected. No installed trust settings or provider were used.

The actual Go API handler at `864f1ad1` produces three TLS cases: trusted local
success, wrong hostname, and untrusted root. Rust reuses the production client
builder with a private fixture CA and test-only dial pinning for the wrong-host
case. It compares status/body/rejection and the actual count of received HTTP
requests (one on success, zero on TLS rejection). Full CLI API semantics remain
covered by the existing HTTP replay. The fixture preserves observed outcomes;
no expected value overwrites a handler result.

Independent clean Darwin/arm64 and Linux/arm64 gates pass complete Go MCP,
template and HTTPS freshness/differentials, 91 core tests, 173 MCP tests,
35 CLI contracts and one controlling-PTY acceptance. Two opt-in helpers run
through that dedicated PTY gate. Strict all-target Clippy and fmt pass on both.
`api-https-receipt-3698d45b.json` in both build roots records source metadata and
fixture/log hashes. MCP-003/BROKER-002 remain open for public DNS/redirects,
other tools and remaining native targets. No publication, cutover or Go removal.


## Integrated embedded API template catalog — 2026-09-29

Candidate `aab7422b730b399d2b0dbc774199505c02852c92` loads all 17 existing Go
YAML assets directly through compile-time inclusion, with no second asset copy.
Per-call custom files retain precedence; a truly absent directory/file falls
back to the matching built-in. Existing malformed, symlinked, inaccessible or
otherwise invalid custom paths fail closed. This is intentionally stricter than
Go's fallback after any stat error and its willingness to follow symlinks.

A source-bound actual Go `apitemplates.Load` fixture pins template.go, auth.go and
all 17 asset blobs at c94a10d7. Its 24 cases compare every loaded field, custom
precedence, absence, malformed overrides and unsafe/unknown names. Unknown-name
errors match exactly; malformed YAML compares rejection rather than parser text.
Unix dangling-symlink controls run separately. The full Make MCP gate now includes
fixture freshness and Rust replay; existing CI invokes that gate.

Independent clean Darwin/arm64 and Linux/arm64 gates pass Go freshness/full MCP
differentials, 91 core tests, 171 MCP tests, 35 CLI contracts and one controlling
PTY acceptance. Two ordinary opt-in helpers execute in that dedicated gate.
Strict all-target Clippy and fmt pass on both hosts. Receipts
`api-builtins-receipt-aab7422b.json` in the Vault/native-linux build roots retain
source metadata, fixture and log hashes.

MCP-003/BROKER-002 remain open: built-in HTTPS endpoints were not executed, and
transport still accepts only loopback HTTP with redirects disabled. TLS, public
DNS, other tools and required native targets remain outstanding. No provider
calls, publication, cutover, Go removal or trust changes occurred.

## Integrated API authentication and substitutions — 2026-09-29

Candidate `f47b2fdb74e0ad0172aa195c6a185f2f42c411af` adds basic, custom-header, query-parameter
and substitution-only authentication to the preceding Bearer path. It preserves
Go's default-header, caller-header, substitution and final authentication order,
including body/query/path/header substitution and automatic JSON Content-Type.
All credential access uses the existing scoped entry path and critical approval.
HTTP remains restricted to loopback; TLS and redirects are not enabled.

The actual pinned Go handler emits 15 cases with seven upstream requests. Real
Rust CLI replay checks methods, URI, selected headers, bodies and results; denial
cases make no upstream request. A Darwin-only harness defect was reproduced:
accepted sockets inherited O_NONBLOCK, returning WouldBlock before request data.
The listener now explicitly uses blocking accepted sockets with its original
bounded timeout. Five complete CLI repetitions passed after that root fix.

Independent clean-candidate Darwin/arm64 and Linux/arm64 gates pass the full Go
MCP differential, 91 core tests, 169 MCP tests, 35 CLI contracts and one dedicated
controlling-PTY acceptance test. Two ordinary opt-in helpers remain ignored in
the ordinary suite and execute via that PTY gate. Strict all-target Clippy and
formatting pass on both hosts, with source-path metadata and log hashes in
`api-semantics-receipt-f47b2fdb.json` under the existing build roots.

The earlier cadfa parent run is not accepted as full evidence: its Make wrapper
selected an older worktree; the subsequent direct candidate test exposed the
socket defect. The corrected current runs use direct Cargo in this worktree.
MCP-003/BROKER-002 remain open for built-in templates, TLS/redirects, other tools
and required native targets. No live provider, release, cutover or Go removal.

## Integrated custom Bearer API request — 2026-09-29

Candidate `ca1dba8db88c149b94676d91b031ba909eff3a5a` connects bounded custom
Bearer GET templates to the assembled CLI MCP handler. Command capability,
profile allowlist, endpoint/method guards, scope and critical approval precede
the credential read and loopback request. Templates reload on each call: a
same-handler revocation test changes the YAML and proves no second request.
Reads are bounded and reject static symlinks; these path checks are not a
race-proof descriptor-relative opening protocol.

The actual Go handler oracle is source-bound to `c94a10d7`; real Rust CLI replay
compares exact results, denials and request counts. Recursive entry values and
generic sensitive patterns are masked without replacing a literal `[REDACTED]`.
Sensitive response headers are filtered and the API's100KiB truncation preserves
Go invalid-UTF8 behavior. The generic broker still rejects bodies exceeding16MiB.
Fixture SHA256: `0e14eb3bf935dc50433f8ef29707c95cfa06a3980d295320ff3b6c87dff31c3c`.

Independent clean-candidate Darwin/arm64 and Linux/arm64 pass the full Go MCP
differential,91 core tests,169 MCP tests,35 CLI contracts and the dedicated real
PTY acceptance test. Two ordinary opt-in PTY helpers are ignored and explicitly
executed by that gate. No failures. Source metadata, log hashes and receipts
`api-request-receipt-ca1dba8d.json` remain in the existing Vault/native-linux build
roots. Linux emits an unused timeout-helper warning; shared-path cleanup is queued.

Basic/header/query auth, substitutions, bodies, caller headers, built-in templates,
TLS and remaining native platforms remain open. MCP-003/BROKER-002 stay in progress;
no remote candidate run, release, installed cutover or Go removal is claimed.


## Integrated real Unix approval acceptance — 2026-09-29

Candidate `58e06e4bad4853d5ababaf2f42e31791547b5286` includes the preceding
write/execute approval slices and the actual CLI runtime assembly correction:
`execute_with_secret` is available only with command capability, then filtered
by the profile allowlist. Tests also prove explicit exclusion and absent capability.

`make mcp-approval-pty-acceptance` drives the assembled `mcp_commands::run`
stdio service through a real controlling terminal while MCP uses separate pipes.
It approves a critical write and a command with empty secret references, then
rejects another write with the exact user-denial response and unchanged state.
A Python standard-library runner checks two critical prompts, one command prompt,
three answers, bounded process-group cleanup and a successful protocol receipt.
A no-terminal invocation fails closed. The identity, vault and MemoryKeyring are
synthetic; this does not exercise `main` bootstrap, human credentials or GUI.

Independent clean-candidate Go1.26.6 MCP differential and Rust gates pass on
Darwin/arm64 and Linux/arm64: 167 MCP tests, 32 CLI contract tests, and the dedicated
PTY parent test invoking its child helper. The ordinary suite explicitly ignores
the two opt-in PTY entrypoints; they are executed by the dedicated gate. No failures.
Receipts `pty-receipt-58e06e4b.json` are retained in the existing Vault and native-linux
build roots. Native CI now checks Go MCP fixture freshness; Unix CI invokes the PTY
gate. That wiring has not been run remotely on this candidate.

The integrated check exposed checkout-dependent Go prompt fixtures. Only the
Directory/Git/Project context rows are now omitted by a declared normalization;
all approval observations, details, risk, counters, answers, audit and state fields
remain unchanged. Production Go source binding is unchanged; generator digest is
`cdc1abdb75d04992e5fe49869cd2daf25741ecc0a046ab84b799094fafc55c8e`.
MCP-003 remains in progress for other tools, GUI, Windows TTY and remaining native
targets. No publication, installed cutover or Go removal occurred.


## Integrated set/delete approval evidence — 2026-09-29

Candidate `c4a71828f7d109445062cfb952218385120c98d7` adds shared platform-seam
approval to stdio `set_entry_field` and `delete_entry` while preserving the
existing HTTP queue path. Critical writes never offer remembered approval.
Argument/scope checks precede approval; denied, absent-TTY, timeout and prompt
I/O failures leave the synthetic vault unchanged. Invalid constructed approval
modes fail closed. Audit order and consecutive prompt counters match Go.

The oracle verifies production Git blobs at `cfbfd59a` before invoking actual
Go handlers and separately binds its generator/helpers. Real Go counterexamples
cover separate path/field sanitization, unterminated escapes, OSC termination,
byte controls, malformed UTF8 replacement and an empty sanitized field. The
new differential is included in the existing native MCP CI gate.

Independent clean-candidate Darwin/arm64 and Linux/arm64 checks pass: full MCP
call differential, all 167 MCP tests and 26 filtered CLI MCP tests, zero failed
or ignored. Receipts `write-tty-receipt-c4a71828.json` are under the existing
Vault and native-linux build roots. The approval provider is injected here;
actual controlling-PTY acceptance, Windows TTY implementation, GUI providers,
remaining handlers and other required native targets remain open. MCP-003
stays in progress; no release, installed cutover or real vault operation occurred.


## Integrated execute-with-secret approval evidence — 2026-09-29

Candidate `cfbfd59a8a4580e8547e278ff8b9de6c7e806967` composes the shared
executor, source-bound Go15 environment-name/redaction contract and direct
controlling-TTY approval seam. Production Go handler oracles exercise granted,
denied, remembered, helper-error and consecutive-grant cases. The fixture
builds its already-bound Go child as `true`/`true.exe`; it needs no Unix command.
Rust compares the actual prompt `secrets_accessed` sequence `[0, 1]` to Go,
as well as prompt count, cache behavior and audit order. The terminal seam is
mocked; this does not claim a physical terminal or GUI approval acceptance run.

Independent checks on clean exact candidate HEAD pass on Darwin/arm64 and
Linux/arm64: full `make mcp-call-differential`, all 165 MCP tests, and 26 filtered
CLI MCP tests (13 unit and 13 contract), zero failed or ignored. Receipts:
`../builds/symaira-vault/mcp-execute-approval-20260929/coordinator-receipt-cfbfd59a.json`
and `../builds/native-linux-20260929/vault-approval-receipt-cfbfd59a.json`.
Explicit manifests, Cargo metadata and compiler paths bind the evidence.
MCP-003 remains in progress: GUI, other handlers, remaining native targets and
complete integrated ledger checks are still required. No publication or cutover.


> **For Hermes:** Use subagent-driven-development to implement independent work
> items, but keep parity-sensitive cascading slices under one coordinator. Work
> strictly in dependency order from `work-items.json`.

**Goal:** Replace the Go backend and gomobile bridge with an idiomatic, safe Rust
implementation without changing observable behavior or vault data.

**Architecture:** Keep Go as a black-box oracle while Rust crates are added only
when their first vertical slice starts. Every slice adds Go-generated fixtures,
Rust tests, and a differential case before expanding scope. Cutover is dual-
binary and reversible; Go removal is a later release step.

**Tech stack:** Rust 1.98 / edition 2024, Cargo workspace, clap, serde, age,
zeroize/secrecy, candidate rmcp/keyring/gix adapters, nextest, proptest, insta,
llvm-cov, audit, deny, Miri, cargo-fuzz, native CI.

---

## Global execution protocol

For every task:

1. Re-read `git status --short --branch` and the affected Go implementation/tests.
2. Add or regenerate the Go-oracle fixture first; prove the drift test fails if
   the source contract changes.
3. Add the smallest Rust behavior that consumes the same fixture.
4. Run the focused Rust test and Go↔Rust differential case.
5. Run `cargo fmt`, `cargo check`, Clippy, affected nextest/doctests, and affected Go tests.
6. Update `contract-matrix.md` only when evidence is executable in CI.
7. Update exactly one item in `work-items.json`; do not mark downstream work ready
   before all dependencies pass.
8. Commit one coherent slice when explicitly operating on a task branch. Never
   commit or push from `main`.

No task may read the real keychain or vault. Use fresh HOME/XDG roots, fixed UTC,
fixed locale, generated identities, local-only remotes, and loopback servers.

### Task 1: Freeze the oracle and create the neutral harness

**Objective:** Make CLI, filesystem, process, and protocol comparisons data-driven.

**Files:**
- Create: `scripts/rust-port/cmd/portgen/`
- Create: `scripts/rust-port/cmd/diffharness/`
- Create: `scripts/rust-port/internal/diff/`
- Create: `testdata/port/cli/command-tree.json`
- Create: `testdata/port/cli/cases.json`
- Create: `testdata/port/filesystem/`
- Modify: `Makefile`
- Modify: `.github/workflows/ci.yml`

**Steps:**
1. Pin the Go oracle commit/release in fixture metadata.
2. Generate the full Cobra tree including hidden commands, aliases, groups,
   argument rules, local/persistent flags, defaults, annotations, and help.
3. Implement a harness that captures raw streams, status/signal, recursive
   file manifests, modes, hashes, and timeouts under isolated HOME/XDG.
4. Add deterministic normalizers only for temp roots and explicitly fixed fields.
5. Add `make port-fixtures-check` and `make differential-go-selftest`.
6. Prove the harness detects an intentional local mismatch, then revert it.
7. Run `GOTOOLCHAIN=go1.26.6 make test-fast docs-check port-fixtures-check`.

**Expected:** Go self-comparison passes; a modified golden fixture fails loudly.

### Task 2: Initialize the Rust workspace and `version` slice

**Objective:** Establish a fully gated Rust repository with one byte-exact command.

**Files:**
- Create: `rust-toolchain.toml`
- Create: `Cargo.toml`
- Create: `Cargo.lock`
- Create: `deny.toml`
- Create: `crates/symvault-core/Cargo.toml`
- Create: `crates/symvault-core/src/lib.rs`
- Create: `crates/symvault-cli/Cargo.toml`
- Create: `crates/symvault-cli/src/main.rs`
- Create: `crates/symvault-cli/tests/version.rs`
- Modify: `Makefile`
- Modify: `.github/workflows/ci.yml`

**Steps:**
1. Pin Rust 1.98 with rustfmt and Clippy; set workspace resolver 3, edition 2024,
   `rust-version = "1.98"`, Apache-2.0, and `#![deny(unsafe_code)]`.
2. Add only `symvault-core` and `symvault-cli`; no empty future crates.
3. Write failing byte-parity tests for `version`, `--version`, JSON, and errors.
4. Implement the minimal clap entrypoint and build metadata injection.
5. Add standard Cargo gates, nextest, doctests, audit, and deny to Make/CI.
6. Measure release binary/startup as an early signal, clearly labelled partial.

**Expected:** Go remains production; Rust `version` matches byte-for-byte and all
Rust gates pass on macOS, Linux, and Windows.

### Task 3: Port pure core contracts

**Objective:** Move deterministic logic without I/O into `symvault-core`, with
all evaluation clocks, request context, and mutable transition state supplied
explicitly by the caller.

**Files:**
- Create/modify: `crates/symvault-core/src/{error,secret_ref,redact,policy,quota,password,totp,types}.rs`
- Create: `crates/symvault-core/tests/fixtures.rs`
- Create: `testdata/port/core/`

**Steps:**
1. Freeze exit taxonomy, secret-reference parsing, redaction, policy/tier rules,
   pure quota/rate-limit transitions, type inference, password policies, and
   fixed-clock TOTP vectors in the contract rows, including `POLICY-001` and
   `QUOTA-001`. For `POLICY-001`, exercise only pure `Engine.Evaluate` branches
   with an explicit `EvalContext`; exclude its `RateLimiter` and `AuditLogFunc`
   side effects. Keep YAML field-presence/config override handling in `CFG-002`
   under `RUST-007`, and keep approval/MCP filtering and call-time enforcement
   for `RUST-010` through the relevant MCP rows. Keep the persisted quota adapter
   and registry wrapper cases in the later `QUOTA-002` row owned by `RUST-007`.
2. Before generating any `QUOTA-001` fixture or porting its Rust code, add the
   narrow production-compatible Go oracle seam required by the row:
   `internal/policy.TransitionRateLimit(state RateLimitState, limits RateLimitLimits,
   now time.Time, event RateLimitEvent) -> (nextState RateLimitState,
   result RateLimitResult)`. Keep it pure over a language-neutral in-memory
   state carrying `tokens`, `capacity`, `refillRate`, `lastRefill`, `dailyCount`,
   `dailyWindowStart`, and `maxPerDay`; the existing `AgentRateLimiter` wrapper
   supplies `time.Now()` and locking without widening the pure seam. The helper
   covers only explicit `set_limits` and `allow` events and returns the next
   bucket state plus the allow/result value.
3. Make the `QUOTA-001` fixture generator call that real production helper with
   explicit timestamps and events. It must not duplicate transition logic or
   mutate private limiter fields. Keep `.quotas.json` persistence, OS locking,
   and the `AgentRateLimiter` registry wrapper fixture layer out of Task 3;
   those cases belong to `QUOTA-002` under `RUST-007`.
4. Keep the pure boundary explicit: `POLICY-001` uses `Engine.Evaluate` only
   for pure branches with a complete `EvalContext` supplied explicitly; its
   `RateLimiter` and `AuditLogFunc` side effects are excluded. Tier evaluation
   applies deterministic presets with exact values/copy behavior; YAML
   field-presence/config override belongs to `CFG-002`/`RUST-007`; rate-limit
   code advances an in-memory state machine from an explicit clock and state in
   `QUOTA-001`, while persistence and registry behavior remain in `QUOTA-002`.
5. Keep these integrations out of Task 3: policy YAML/filesystem loading,
   runtime context plus git/env discovery, approval queues, MCP tool filtering/
   call-time enforcement, and policy audit/enforcement wiring. YAML precedence
   is implemented at `RUST-007`; approval and MCP enforcement are implemented
   later in `RUST-010` through `MCP-002`/`MCP-003`; the audit chain itself is
   covered by `RUST-006`. Platform adapters are implemented at their later
   boundary.
6. Add failing Rust fixture/property tests per module, using only generated
   JSON vectors and isolated deterministic inputs.
7. Implement explicit enums/newtypes; use `secrecy`/`zeroize` for secret-bearing values.
8. Fuzz parsers and path/reference normalization.
9. Run core Rust gates and focused Go oracle tests.

**Expected:** `symvault-core` passes the `RUST-003` contract rows without Tokio,
clap, HTTP, filesystem, keyring, git, approval, MCP, or TUI dependencies;
subsequent adapter work consumes the same pure contracts without widening them.

**Completed:** The pure-core slice passes for `CRYPTO-005`, `POLICY-001`, and
`QUOTA-001`, including Go-generated fixtures, deterministic property coverage,
and integrated Miri. The reusable error taxonomy is also ported, but the full
binary-facing `CLI-005` row remains `TODO` until `RUST-009` exercises invalid
argument, configuration, authentication, not-found, and leakage behavior.

### Task 4: Prove age and KDF interoperability

**Objective:** Port credential cryptography before any Rust storage writes.

**Files:**
- Create: `crates/symvault-crypto/`
- Create: `testdata/port/crypto/`
- Extend: `scripts/rust-port/cmd/diffharness/`

**Steps:**
1. Generate safe fixed X25519 identity/fingerprint vectors and scrypt/argon2id
   fixtures through Go production helpers.
2. Add Go-encrypt→Rust-decrypt and Rust-encrypt→Go-decrypt tests.
3. Cover multi-recipient add/remove, malformed headers, wrong passphrases,
   parameter limits, zero-key healing, and KDF migration detection.
4. Ensure secret types do not implement revealing `Debug`/`Display` and wipe buffers.
5. Add property/fuzz tests for untrusted envelope/KDF parsing and run Miri on pure code.

**Expected:** Existing copied test vaults are mutually readable; no Rust code writes
production data yet.

### Task 5: Port read-only storage, then write paths

**Objective:** Make Rust open, inspect, search, and finally mutate isolated vaults.

**Files:**
- Create: `crates/symvault-store/`
- Create: `testdata/port/store/`
- Extend: `scripts/rust-port/cmd/diffharness/`

**Steps:**
1. Freeze entry YAML, metadata, layout, legacy roots, recipients, manifests, and index formats.
2. Port read-only open/list/get/find/verify paths first.
3. Add filesystem type/mode/hash comparisons and plaintext-leak scans.
4. Port atomic write/delete/re-encrypt and interruption/rollback semantics.
5. Add symlink, traversal, read-only, concurrent, and corrupt-file tests.
6. Run Go↔Rust round trips in both write directions.

**Expected:** Rust-written test vaults reopen in Go with identical semantic state,
and vice versa.

### Task 6: Port the audit chain

**Objective:** Preserve the keyed tamper-evidence model exactly.

**Files:**
- Create: `crates/symvault-store/src/audit/`
- Create: `testdata/port/audit/`

**Steps:**
1. Generate fixed-key/fixed-clock canonical JSON and HMAC chain vectors in Go.
2. Port `kid`, previous-HMAC linking, chain-reset detection, rotation archive,
   multi-key verification, retention, redaction, and exports.
3. Add mutation tests for reordering, truncation, insertion, key mismatch, and reset.
4. Byte-compare canonical entries and exported evidence.

**Expected:** Go and Rust verify each other's audit logs and reject the same attacks.

### Task 7: Port configuration and platform session adapters

**Objective:** Preserve unlock/session behavior, persisted quotas, and OS integrations behind injected traits.

**Files:**
- Extend: `symvault-core` config types
- Create: `crates/symvault-platform/`
- Create: `testdata/port/config/`, `testdata/port/session/`, `testdata/port/quotas/`

**Steps:**
1. Freeze YAML defaults/precedence/legacy paths and exact writer behavior.
2. Port config parsing/validation without UI dependencies.
3. Define full side-effect traits for keyring, clock, Touch ID, clipboard,
   autotype, secure UI, notifications, daemon lifecycle, and quota storage.
4. Port memory/injected implementations first; then explicit native backends.
5. After `RUST-005` storage foundations, port the `QUOTA-002` filesystem-backed
   adapter: `.quotas.json` schema and 0700/0600 modes, `New`/`Increment`/`Check`/
   `Reset`/`Close`, closed/malformed/I/O errors, durable writes, Unix `flock`,
   Windows `LockFileEx`, and same-process/cross-process concurrency. Add the
   separate public-wrapper fixtures for `AgentRateLimiter` unknown-agent,
   `HasLimits`, per-agent isolation, and `Cleanup`; do not duplicate the
   `QUOTA-001` transition helper.
6. Verify service/account names, session idle/max TTL, non-refreshing probes,
   unavailable/cancel behavior, and no secret exposure.

**Expected:** the Go-derived config/session/quota fixtures and injected platform
contract tests pass locally. The macOS native adapter slice now compiles and
runs non-interactive capability, escaping, LocalAuthentication availability,
and launchd plist tests. An explicit ignored macOS arm64 smoke also completed a
real Keychain binary round trip in a generated test-only namespace and a real
launchd install/status/uninstall cycle under a disposable home tree. Apple's
Keychain Services does not honor private `HOME` as an isolated keychain, so the
keyring result is diagnostic rather than isolated-keychain acceptance. Touch ID
authentication prompts, clipboard/autotype permission behavior, GUI secure
input/notification delivery, and Windows/native non-macOS keyring evidence
remain blockers; the `RUST-007` item stays open.

### Task 8: Port git, reconciliation, import/export, and intake

**Objective:** Complete the storage lifecycle against isolated infrastructure.

**Files:**
- Create: `crates/symvault-sync/`
- Create: `testdata/port/{git,import,export,intake}/`

**Steps:**
1. Spike `gix` against all GIT matrix rows; record gaps before choosing it.
2. Port repository init/commit/remotes/push/pull and deterministic reconciliation.
3. Port backup/restore with traversal defense and exact archive manifests.
4. Port importer/quarantine/export behavior from Go-generated fixtures.
5. Port intake watch/disable with fake-clock and filesystem-event adapters.
6. Fuzz import and archive parsers; run local bare-remote differential cases.

**Expected:** all storage lifecycle rows pass on native OS jobs.

### Task 9: Port the complete CLI and TUI

**Objective:** Make Rust cover every non-MCP command while Go remains production.

**Files:**
- Extend: `crates/symvault-cli/`
- Create: `crates/symvault-cli/tests/cli_contract.rs`
- Create: `testdata/port/tui/`

**Steps:**
1. Build the full clap tree from frozen inventory, preserving hidden aliases.
2. Port commands by vertical family: auth/admin, CRUD/file, recipients/device,
   policy/share, template/run, sync/remote, update/doctor, then TUI.
3. For each family, write failing black-box cases before handlers.
4. Generate and compare completions/manpages; classify only unavoidable framework text differences.
5. Add PTY tests for prompts, editor flows, cancellation, and TUI key behavior.

**Expected:** every non-MCP CLI case passes through Rust with exact stream/exit behavior.

### Task 10: Port MCP stdio

**Objective:** Preserve all 35 tools and raw protocol behavior with zero stdout pollution.

**Files:**
- Create: `crates/symvault-mcp/`
- Create: `testdata/port/mcp/`
- Extend: `scripts/rust-port/cmd/diffharness/`

**Steps:**
1. Snapshot tool definitions for each agent tier/runtime availability combination.
2. Spike `rmcp` 3.2.0 against raw line/framed behavior; keep it only behind a
   compatibility adapter and only if all required hooks exist.
3. Port initialize/list/call, notifications, cancellation, bounds, aliases,
   scope enforcement, approval queues, policy-driven MCP tool filtering and
   call-time enforcement, redaction, and structured content. This is the
   `POLICY-001` integration owner for the `MCP-002`/`MCP-003` rows; include the
   policy audit/enforcement wiring here rather than in the pure core slice.
4. Add raw-byte differential cases, property tests, and fuzzing.
5. Assert stderr-only diagnostics and scan all outputs for generated fixture secrets.

**Expected:** stdio transcripts match and no tool can bypass list-time/call-time authorization.

### Task 11: Port HTTP/SSE, OAuth, broker, and command execution

**Objective:** Complete network and process boundaries without broadening exposure.

**Files:**
- Extend: `crates/symvault-mcp/`
- Create: `testdata/port/{http,oauth,broker}/`

**Steps:**
1. Freeze HTTP routes/status/headers/SSE, bearer/scoped-token storage, OAuth
   discovery/DCR/PKCE/refresh, origin checks, request limits, and shutdown.
2. Port HTTP/SSE and auth against loopback transcript fixtures.
3. Port run/broker/API template behavior with injected process and HTTP adapters.
4. Test process-tree cancellation, PTY behavior, SSRF/path policy, TLS, timeout,
   and complete secret redaction on every error path.
5. Run MCP conformance plus Symaira-specific raw differential tests.

**Expected:** network and broker matrix rows pass without real external services.

### Task 12: Replace gomobile with the Rust Swift bridge

**Objective:** Ship one Rust crypto/storage implementation to macOS and iOS clients.

**Files:**
- Create: `crates/symvault-ffi/`
- Modify: `client/Package.swift`
- Modify: `client/project.yml`
- Modify: `client/Sources/SymvaultKit/VaultClient.swift`
- Modify: `scripts/build-vaultcore.sh`
- Create: Swift integration tests matching every `pkg/mobilebind` function

**Steps:**
1. Freeze the current string/bytes/JSON bridge API and errors.
2. Spike UniFFI and a narrow C ABI; measure generated API, license impact,
   XCFramework size, host-app RSS, and credential-extension RSS.
3. Choose and document one bridge, then implement all FFI rows.
4. Build macOS and iOS simulator/device frameworks; run Swift tests.
5. Verify Go and Rust frameworks produce mutually readable test vaults.

**Expected:** clients no longer require gomobile for candidate builds; real-device
budget evidence is recorded before cutover.

### Task 13: Value gate and dual-binary prerelease

**Objective:** Decide whether the representative Rust implementation earns cutover.

**Files:**
- Create: `scripts/rust-port/cmd/valuegate/`
- Create: `docs/rust-port/value-gate-<date>.json`
- Modify: release workflow and packaging only after the gate passes

**Steps:**
1. Build release Go and Rust binaries from clean caches and warm caches on the same host.
2. Run at least 100 startup and representative command samples after warmups.
3. Measure size, RSS, startup p95, CRUD/search/MCP p95, and full gate duration.
4. Fail unless the threshold in `baseline-20260905.json` passes.
5. If it fails, keep Go production and optimize or stop; do not redefine the metric.
6. If it passes, ship a prerelease containing Rust `symvault` plus `symvault-go`.
7. Verify archives, packages, signatures, SBOMs, provenance, notarization,
   Homebrew/Scoop/Docker/Nix/MCPB, and rollback by public artifact readback.

**Expected:** a reversible prerelease with measured value and complete parity.

### Task 14: Stable cutover and delayed Go removal

**Objective:** Finish without destroying rollback.

**Files:**
- Modify: `AGENTS.md`, `ARCHITECTURE.md`, `README.md`, build/release docs and workflows
- Remove Go source only in a separate post-stable change

**Steps:**
1. Run native macOS/Linux/Windows suites and FreeBSD artifact smoke.
2. Run signed/notarized macOS app and iOS device smoke against copied test data.
3. Release stable Rust primary with the Go fallback still packaged.
4. Operate one stable release without unexplained parity defects.
5. Tag the final dual-binary rollback point and document exact rollback commands.
6. In a separate reviewed change, remove Go source, go.mod/go.sum, Go CI,
   GoReleaser-only assumptions, and the current-release fallback.
7. Verify zero tracked backend Go files while preserving Swift/editor sources,
   release names, data compatibility, and immutable rollback artifacts.

**Expected:** Rust is the sole backend source; the final dual release remains a
verified external rollback point.
