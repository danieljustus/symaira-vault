# Local-first completion of the Rust port

Decided 2026-10-30. The remaining Rust migration is finished on one local
branch and reaches `main` through a single closing pull request. Per-slice pull
requests and per-slice hosted CI runs are suspended for the port.

## Rules

1. **Branch.** All port work lands on `local/rust-port` (worktree
   `Symaira_Dev/Worktrees/symaira-vault/local-rust-port` on the MacBook).
   Slice branches may exist locally and are merged into it after their gate.
   No new pull requests for port slices.
2. **Backup push, no CI.** `git push origin local/rust-port` is allowed at any
   time and is expected after every integrated slice. No workflow triggers on
   `local/**` branches, so a push costs no CI time. Do not rename the branch to
   `main`, `migration/**` or `feat/1239-tui`; those names trigger workflows.
3. **Gate.** A slice is integrated only after
   `scripts/rust-port/local-gate.sh all` exits 0 on a clean tree:
   - `macos`: native Darwin/arm64, mirroring ci.yml `rust-native`:
     `rust-lint rust-check mcp-call-fixtures-check rust-test`,
     `config-cli-differential` (with `TMPDIR` below `/private/var`, which the
     trusted-alias auth case requires) and `mcp-approval-pty-acceptance`.
     When Go code changed against `origin/main`, the changed packages run
     with `-race`; any change outside `scripts/` (or to `go.mod`/`go.sum`)
     also runs the full Go suite as ci.yml `test` does on macOS (go.mod
     `toolchain` as `GOTOOLCHAIN`, no
     `-race`, `CGO_ENABLED=0`, `-timeout=30m`, same `-skip`, after removing
     stale Go evidence packages under `target/`). The full `-race` suite
     stays with CI's ubuntu job: locally `cmd/crud` alone exceeded go test's
     default 10m timeout under `-race` (receipt `7faf3b57` macos exit 2).
   - `linux`: native Linux/arm64 container (`scripts/rust-port/local-gate/Dockerfile`,
     pins mirror `.github/workflows/ci.yml`), `rust-gates-core port-contract
     mcp-approval-pty-acceptance`. Miri (about one hour) is opt-in with
     `RUN_MIRI=1` and required for slices that change `crates/symvault-core`.
   - Both lanes also run the area process contracts of the former area
     workflows through `make local-area` (see "Area process contracts" below),
     one make target at a time; the log has an `area-target: <name> exit=<n>`
     line per target and `area-summary:` at the end.
   Each run appends a receipt (SHA, target, exit, log, `area_targets`) to
   `target/local-gate/receipts.jsonl` unless `LOCAL_GATE_RECEIPTS` points
   elsewhere. The gate runs in the live working tree (only the clean check
   happens at start): do not edit, stash-pop or generate fixtures in this
   worktree until it finishes; park unfinished work with `git stash` first.
   A receipt's `exit` is evidence only together with its log (`Summary` line,
   no `make: ***`/`FAILED` lines).
4. **Matrix wording.** A row may be promoted with the label
   `PASS (local)`: name the SHA and both receipts (`macos`, `linux`). Never
   write that a row ran in hosted CI when it did not. `PASS (local)` rows are
   confirmed or corrected by the closing CI run.
5. **Closing PR.** When the backlog is done: merge current `main` into
   `local/rust-port`, rerun the gate, open one pull request, fix what hosted CI
   finds, merge. Release, cutover and Go removal (RUST-013 to RUST-015) stay
   separate authorizations.
6. **Oracle pins survive the squash.** `main` allows only squash or rebase
   merges with linear history, so every local SHA changes on merge. Oracle
   pins resolve their revision with `git rev-parse <sha>^{commit}` and
   `git show <sha>:<path>` (`scripts/rust-port/internal/provenance`), which
   need the object, not ancestry. Pins may therefore name `local/rust-port`
   commits. Before merging the closing PR, push the permanent tag
   `rust-port/local-history` at the branch tip; CI checks out with
   `fetch-depth: 0`, which fetches tags, so every pinned commit stays
   resolvable. Never delete that tag.

## Known limits of the local gate

- Linux runs on Ubuntu 24.04 arm64 (git from the git-core PPA, because this
  repository's worktrees need git >= 2.48), CI on Ubuntu 24.04 x86_64. Defects
  that depend on the CPU architecture surface only in the closing CI run.
- Hosted macOS keychain tests (`keychain-native`) and the Go matrix jobs
  (`test`, `build`, `integration-test`, `smoke-test`) are not part of the local
  gate. Go is the frozen oracle; it is tested only when a slice edits Go
  code (see rule 3).
- Findings accumulate until the closing PR instead of surfacing per slice.
- The Linux container uses one cargo target volume per worktree
  (`symvault-gate-target-<sha256(root)[:12]>`); a shared volume reused test
  binaries with another worktree's compile-time fixture paths. Old volumes
  of removed worktrees are caches and may be deleted with `docker volume rm`.
- The area process contracts run locally (next section), but their hosted
  receipts, artifact uploads and the Windows legs do not exist locally;
  differences are listed there. `keychain-native` (hosted macOS keychain) and
  the TUI contract on macOS stay out (real pasteboard).

## Area process contracts

The 25 area workflows ran Python process contracts and named Go/cargo tests
that nextest does not: the 20 contract workflows (`rust-http-*` x10,
`rust-mcp-http-process`, `rust-mcp-process`, `rust-api-transport`,
`rust-broker-connect`, `rust-broker-egress`, `rust-cli-artifacts`,
`rust-intake-cli`, `rust-serve-cli`, `kdf-resource-policy`,
`vault-read-resource-policy`, `mcp-http-shutdown`, `rust-tui`) and five more
(`rust-signal-process`, `rust-store`, `rust-store-observations`,
`rust-sync-observations`, `rust-pairing`). All 25 map to a target below or to a
row of "Deviations". `make local-area` (`LOCAL_AREA_TARGETS` in the Makefile)
runs the targets on top of the older differential targets; `make
local-area-list LOCAL_AREA_LANE=macos|linux` prints the exact list of a lane.
Each target runs the workflow's contract step plus the
`test_*_contract.py` / `*_mutation.py` negative controls and the named
Go/cargo tests the workflow ran with it, then
`scripts/rust-port/gate_area_check.py`, which ports the workflow's inline
`python3 - <<PY` assertions one for one (see "Exact counts" below).
Platform scope is macOS arm64 and Linux; Windows steps are void. Every target
below runs in both lanes, because hosted CI ran each contract on ubuntu and
macOS (`rust-http-*.yml` on ubuntu, the same HTTP contracts on macOS through
`rust-http-macos.yml` and `rust-macos-satellites.yml`, which assert the same
values); the two lane-only targets are marked. The area targets never run in
parallel (`.NOTPARALLEL`).

| Target | Workflow(s) | Contract step and negative controls |
|---|---|---|
| `http-framing-contract` | rust-http-framing | `http_framing_contract.py` |
| `http-head-contract` | rust-http-head | `http_head_contract.py` |
| `http-origin-contract` | rust-http-origin | `http_origin_contract.py` |
| `http-slow-peer-contract` | rust-http-read-deadlines | `http_slow_peer_contract.py` |
| `http-timeout-contract` | rust-http-timeouts | `http_timeout_contract.py` |
| `http-tls-contract` | rust-http-tls | `http_tls_contract.py` |
| `http-write-contract` | rust-http-write | `test_http_write_contract.py`, `go test ./scripts/rust-port/internal/diff`, `test_oracle_build.py`, `http_write_contract.py --tls-output-probe-only`, `http_write_mutation.py` (run by `area_http_write_mutation.sh` in a detached worktree of `HEAD` with its own cargo target dir: the live tree and `target/debug/symvault` are never touched, and a guard fails the target and restores `http.rs` if they change), `http_write_contract.py` |
| `worktree-prune-check` | (local) | `check_worktree_prune.py` fails on any `git worktree prune/repair`, `git gc`, `git prune` in `scripts/` or the Makefile and on missing container git guards; `test_check_worktree_prune.py` holds its negative controls |
| `area-check-selftest` | (local) | `test_gate_area_check.py`: shrunken, partial and malformed receipts and logs must fail `gate_area_check.py` |
| `mcp-named-tests` | rust-http-* (the `symvault-mcp --all-targets` steps), rust-mcp-http-process, rust-mcp-process, rust-api-transport | `cargo test -p symvault-mcp --all-targets` with the 22 named tests the workflows required and the exact total, `symvault-core` (`mcp_tls_settings_survive_config_roundtrip`), `mcp_commands::tests`, the two `api_template_fixture` tests, `go env GOVERSION` = go1.26.6 |
| `signal-process-contract` | rust-signal-process | `cargo test run_commands`, `signal-process-differential`, receipt with 33 rows per implementation |
| `store-live-contract` | rust-store | `symvault-store` tests, five named Go live-acceptance tests (`go test ./internal/vault`) |
| `store-observations-contract` | rust-store-observations | `go test -race storegen` with two required names, `storegen --check`, go1.26.6 |
| `sync-observations-contract` | rust-sync-observations | `go test -race syncgen`, `TestCreateBackup_NormalizesTarMemberSeparators`, three required names, `syncgen --portable --check`, `gitio --check` |
| `pairing-oracle-contract` | rust-pairing | `area_pairing_oracle.sh`: stateful CLI differential against Go v0.22.1, import quarantine against `3232e31f`, auth root-trust, startup profile (each asserts the cargo test ran and did not print the "skipping Go differential" notice), the `caserun`/`devicelistdriver`/`diff` Go tests, HTTP-001 keyring isolation, toolchain identity. `pairing-differential`, `config-profile-differential`, `device-list-differential` are separate targets of the differential list |
| `http-oauth-contract` | rust-http-oauth | oracle-runner build and `test_oracle_build.py`, `http_oauth_contract.py` |
| `http-process-contract` | rust-mcp-http-process | `test_http_process_contract.py`, `http_process_contract.py` |
| `mcp-http-replay-contract` | (local; HTTP-001, no workflow step) | `test_http_replay_contract.py`, `http_replay_contract.py` (24 s on the MacBook) against the Go oracle at the pinned commit; profile `http-replay`: 276 cases per implementation (case list and order imported from the driver), 194 identical, 71 declared (ADR 0032; labels equal `DECLARED`), 8 health-clock (semantic), 2 final-identical (Go-only interim `100 Continue`), `route-head-health`, and the driver's own `compare` re-run over the receipt |
| `mcp-http-token-contract` | (local; HTTP-002, no workflow step) | `timestamp-fixtures-check`, `test_http_replay_contract.py`, `http_token_contract.py` (real clock; 243 s on the MacBook at load 15); profile `http-token`: 180 token-state cases, 70 startup/storage scenarios, 1 dynamic clock scenario, 21 duplicate-key reload steps, 2 stale-revocation scenarios per implementation, each re-checked with the driver's own `check_*` functions |
| `toolhash-process-contract` | (local; TOOLHASH-001, no workflow step) | `test_toolhash_process_contract.py`, Go CLI and `toolhashseed` built from this checkout, `toolhash_process_contract.py`; profile `toolhash`: Go-recorded registry hash stamped by both CLIs (`new`, `rotate`), 14 byte-identical HTTP outcomes with the hand-written drift/scope/policy expectations, 8 identical audit rows (ids masked); negative control `--drop-audit-ids` must fail on the audit rows |
| `mcp-process-contract` | rust-mcp-process | `test_mcp_oracle.py`, `test_mcp_process_contract.py`, `make mcp-ordered-fixtures-check`, `mcp_process_contract.py --reference mcp-anomaly-ordered-v1` |
| `api-transport-contract` | rust-api-transport | `test_api_transport_contract.py`, `api_transport_contract.py` (probe example) |
| `broker-connect-contract` | rust-broker-connect | `connect_contract.py` (probe example) |
| `broker-egress-contract` | rust-broker-egress | `egress_contract.py` (CLI and probe), `cligap` for `symvault broker` / `symvault run` |
| `cli-artifacts-contract` | rust-cli-artifacts | `go test ./scripts/rust-port/cmd/cligap`, Go manual-page tests, `make port-fixtures-check`, `manual_path_contract_test.py`, `test_cli_artifacts_contract.py`, `cli_artifacts_contract.py --require-native-shells`, `cligap` |
| `intake-cli-contract` | rust-intake-cli | `intake_watch_contract.py`, `cligap` for `symvault intake` |
| `serve-cli-contract` | rust-serve-cli | `serve_contract.py`, `cligap` for `symvault serve` |
| `kdf-resource-policy-contract` | kdf-resource-policy | `check_argon2_upstream.py`, `kdf_policy_fixtures.py`, third-party argon2 tests, Go `-race` KDF tests (required names), `symvault-crypto` and migration tests, `migrate_kdf_differential` against a Go CLI built for that one command |
| `read-resource-policy-contract` | vault-read-resource-policy | Go `-race` `TestResourcePolicy*` (required names), `refresh-read-policy-fixtures.py --check`, Rust store/template/mcp policy tests |
| `mcp-http-shutdown-contract` | mcp-http-shutdown | Go `-race` shutdown, approval and authorization tests (required names); Rust leg: `test_http_drain_contract.py`, the `HttpShutdown` drain unit tests, `http_drain_contract.py` (Go oracle vs Rust CLI drain of a real `mcp` HTTP server, 15 signal runs per implementation) |
| `tui-named-tests` | rust-tui | the five named `tui::tests::` browser cases of the CLI binary (the whole `-p symvault-cli -p symvault-platform` run is `rust-test`) |
| `tui-contract` (linux only) | rust-tui | `tui_harness_test.py`, `tui_contract.py` (fifteen Go/Rust cases under a private Xvfb/xclip), receipt replay, `tui_mutation_test.py` |
| `tui-harness-check` (macos only) | rust-tui | `tui_harness_test.py` only |

Where the gate differs from the hosted workflows:

- **TUI on macOS.** `tui_contract.py` on Darwin reads and writes the real
  pasteboard and asserts `GITHUB_ACTIONS=true` plus
  `SYMVAULT_DISPOSABLE_NATIVE_RUNNER=1`. The local gate never touches the
  clipboard, so the macOS lane runs the harness checks only. The macOS half of
  the contract (and native clipboard TTL behavior) stays a closing-CI result.
- **Exact counts.** `gate_area_check.py receipt PATH --profile NAME` ports the
  workflows' inline checks: exact row, declared-difference and process counts,
  required case names, the last case of each run, per-peer and per-process
  invariants, `oracle_commit`, compiler version, frame totals. `passed`, a
  clean tree before (and, where the workflow asserted it, after) the run,
  `candidate_commit` = HEAD and `native_os` = the host are required keys; a
  missing key, a one-row receipt or a wrong count exits 1
  (`test_gate_area_check.py` feeds every profile removed keys, truncated lists
  and wrong values). Logs are checked the same way (`log-ok` with exact name
  prefixes, `--sum-passed`, `N passed; 0 failed; 0 ignored` totals; `go-json`
  names; `gaps --exact-path/--min-paths`). One value differs from the workflows:
  the `symvault-mcp --all-targets` total is 429 (`AREA_MCP_TEST_COUNT`), the
  workflows still say 246, which the tree outgrew; raise the constant when
  tests are added. `native_os` must equal the host's (the workflows accepted
  any of the three).
- **Live Go.** `kdf-resource-policy-contract`, `read-resource-policy-contract`,
  `mcp-http-shutdown-contract` and several contracts run the frozen Go oracle
  (race tests, oracle builds). They are the first things to retire or re-source
  when Go is removed (P40a).
- **Toolchains.** HTTP and `mcp-process` contracts pin `GO_TOOLCHAIN`
  (go1.26.6, the MCP oracle refuses anything else); the other contracts use
  `BUILD_GO_TOOLCHAIN` like their workflows. All Python runs use python3.13
  when present (the TUI contract asserts it). The Linux image installs it from
  deadsnakes, plus zsh, fish, xvfb and xclip (the workflows' own apt steps);
  macOS needs Homebrew `python3.13`, `bash` and `fish`.
- **Binaries.** Contracts run against a private copy of the CLI/probe under
  `$(CARGO_TARGET_DIR)/area-evidence/bin`, because another build in the shared
  target dir changes the hash a contract checks before and after. The TUI
  candidate is built with the acceptance profile
  (`CARGO_PROFILE_DEV_DEBUG=0`, no incremental) into
  `area-evidence/tui-candidate` (about 1 GB), as `tui_contract.py` rebuilds and
  byte-compares.
- **Evidence.** Receipts and logs live in `$(CARGO_TARGET_DIR)/area-evidence`
  (`AREA_EVIDENCE`), not in uploaded artifacts.

Known state: the targets and checks are under review on `local/gate-area`
(macOS arm64 host and Ubuntu 24.04 arm64 container); the receipts and their
logs, not this paragraph, are the evidence. Fixed since the first review round:
`kdf-resource-policy-contract` flaked because `kdf_policy_fixtures.py` blanked
`HOME` and set `GOTOOLCHAIN=go1.26.6`, so cmd/go exec'd the `~/go/bin/go1.26.6`
wrapper (which needs `$HOME/sdk`, exit 1 with no output) or downloaded a
toolchain and modules into the blank HOME; the driver now resolves
`GOROOT`/caches from the caller's environment first and runs
`<GOROOT>/bin/go` with `GOTOOLCHAIN=local`, printing the child's stderr on
failure (its fixture's `driver_digest` changed with the script, so
`kdf-policy-v1.json` was regenerated with `--generate`; same identity,
passphrase, parameters and Go version, fresh ciphertext). `device_list_differential.py`
got the same hardening. `http-write-contract` no longer mutates the live tree.

Running them:

- `scripts/rust-port/local-gate.sh macos-area|linux-area` runs only that lane's
  `local-area` targets (receipt target `macos-area` / `linux-area`);
  `LOCAL_AREA_ONLY="<targets>"` narrows further, but only in these two modes:
  `macos|linux|all` exit 2 when it is set, and a narrowed run logs
  `area-partial: true` and records `"partial":true` in its receipt. Each
  receipt also records `area_expected` (what `make local-area-list` printed for
  the lane) and `area_complete`, true only for an unnarrowed run that executed
  exactly that list, exited 0 and ran on a clean tree (`ALLOW_DIRTY=1` runs
  have `dirty: true` and are never complete); a run whose executed list differs
  fails. `test_local_area_list.py` pins each lane's 51 targets (so a target
  removed from the Makefile fails `area-check-selftest`), and
  `area_http_write_mutation.sh` / `area_pairing_oracle.sh` remove their scratch
  worktrees through `worktree_remove.sh` (refuses symlinks and paths outside the
  evidence dir; deletes only the admin dir whose `gitdir` names that tree).
  `make <target>` runs one contract directly; the contracts need a clean tree.
  `local-gate-area.sh` also fails (and, when the run started clean, restores
  the tracked files of) a run that changed the tracked tree, and forwards
  TERM/INT to the running target before doing so.
- Never run both lanes, or a gate and a contract, against the same worktree or
  cargo target dir at once: the contracts compare source inventories and
  binary hashes before and after (concurrent lanes produced "tree dirty" and
  "binary hash changed" failures during development of this change).
  `http_write_mutation.py` itself runs on a scratch copy under
  `area-evidence/mutation-tree` with `area-evidence/mutation-target` (a second
  cargo target dir, a few GB).
- `LOCAL_GATE_MOUNT_AS=<path of another worktree>` makes the Linux lane mount
  this worktree at that path and reuse that worktree's cargo target volume,
  instead of creating a new multi-GB volume when disk is tight.
- Each receipt carries `area_targets` (`name:exit,...`) parsed from the log, so
  it names every area target it covered. The `Summary`/`area-summary` rule from
  rule 3 applies.

### Deviations from the hosted workflows

| Workflow step | Local handling |
|---|---|
| `cargo fmt`, `cargo clippy` in every area workflow | `rust-lint` (macOS lane) and `rust-gates-core` (Linux lane) |
| Windows branches and legs, Winsock ETW trace, upload-artifact steps | void; evidence stays in `$(CARGO_TARGET_DIR)/area-evidence` |
| `rust-http-macos.yml`, `rust-macos-satellites.yml` | consolidated hosted jobs of the same contracts, same values; run by the per-contract targets |
| `rust-http-head` second part (`http_process_contract` / `http_oauth_contract` receipts) and `rust-http-oauth` "original strict HTTP corpus" | `http-process-contract` (stricter, from `rust-mcp-http-process.yml`) and `http-oauth-contract` |
| `symvault-mcp --all-targets` total 246 | 429 (see "Exact counts") |
| `rust-store` `SYMVAULT_RUN_WINDOWS_CROSSLANG=1` | Windows only |
| `rust-pairing` "Verify complete port contract on native macOS" (`make port-contract` with the backend selectors unset) | **not run on macOS locally** (15 to 18 minutes hosted); the Linux lane runs `port-contract`; the macOS result stays a closing-CI result |
| `rust-pairing` `native_closeout.py portable` | **not run**: it forces `CARGO_TARGET_DIR` to `<repo>/target` and builds there. Its content is covered by `policy-fixtures-check` (`policygen --check`, in `port-contract`), `device_pairing_cli` and the `symvault-core`/`symvault-platform` all-targets run (`rust-test`) |
| `native_closeout.py keyring`, `daemon`, `clipboard` | **void locally**: they need a disposable runner (real keychain/Secret Service, launchd, pasteboard) and assert `GITHUB_ACTIONS=true`; closing CI |
| `rust-tui` macOS half of `tui_contract.py` | closing CI (real pasteboard), see "TUI on macOS" |
| `rust-tui` whole `cargo test -p symvault-cli -p symvault-platform --all-targets` | `rust-test`; the named browser cases run in `tui-named-tests` |
| `clipboard-linux-differential`, `tool-registry-hash-differential` (new on `local/rust-port`) | not steps of any workflow; both are `port-contract` members (Linux lane). `mcp-http-replay-contract`, `mcp-http-token-contract` and `toolhash-process-contract` are not workflow steps either, but are area targets (rows above): they need a real clock, several seconds of waiting and a Go oracle, which the area targets provide |
| `rust-audit.yml`, `codeql.yml`, `deferred-deps-check.yml`, `macos-*.yml`, `release.yml`, `ci.yml` | not area workflows |

### Measured run times

Wall-clock seconds per target of the final full `macos-area` and `linux-area`
runs at `20291611` (48 targets each at that time, exit 0, receipts `partial: false`,
`area_complete: true`), measured on the MacBook (arm64) with a 1-minute load
average of about 5 to 27 (other worktrees ran cargo and docker in parallel;
`area-load:` lines in the log show the load at each target's start).
`n/a` = the target does not exist in that lane. Both runs used
warm cargo target directories; the first run after a cold start adds the
compile to `mcp-init-differential`, `mcp-list-differential`,
`mcp-call-differential`, `http-write-contract` and `mcp-process-contract`
(the first, cold macOS lane on `ca0f2300` took 72 minutes at load 7 to 65).

| Target | macOS (s) | Linux (s) |
|---|---|---|
| `mcp-init-differential` | 3 | 2 |
| `mcp-stdio-differential` | 1 | 0 |
| `mcp-list-differential` | 223 | 83 |
| `mcp-call-differential` | 248 | 117 |
| `mcp-clipboard-signals-differential` | 1 | 0 |
| `mcp-execute-api-policy-differential` | 251 | 77 |
| `mcp-oauth-contract` | 2 | 6 |
| `api-templates-differential` | 2 | 0 |
| `config-profile-differential` | 11 | 14 |
| `config-session-differential` | 20 | 18 |
| `cfg-overrides-fixtures-check` | 5 | 2 |
| `device-list-differential` | 10 | 6 |
| `device-session-differential` | 7 | 8 |
| `pairing-differential` | 7 | 10 |
| `git-offline-differential` | 1 | 1 |
| `git-winner-differential` | 1 | 0 |
| `rust-007-differential` | 8 | 6 |
| `store004-isolation-check` | 2 | 2 |
| `update-fixtures-check` | 15 | 6 |
| `area-check-selftest` | 3 | 2 |
| `worktree-prune-check` | 0 | 0 |
| `http-framing-contract` | 8 | 4 |
| `http-head-contract` | 5 | 5 |
| `http-origin-contract` | 6 | 4 |
| `http-slow-peer-contract` | 25 | 24 |
| `http-timeout-contract` | 63 | 60 |
| `http-tls-contract` | 92 | 94 |
| `http-write-contract` | 397 | 385 |
| `http-oauth-contract` | 32 | 44 |
| `http-process-contract` | 41 | 64 |
| `mcp-process-contract` | 431 | 101 |
| `mcp-named-tests` | 97 | 67 |
| `api-transport-contract` | 12 | 8 |
| `broker-connect-contract` | 5 | 3 |
| `broker-egress-contract` | 34 | 30 |
| `cli-artifacts-contract` | 73 | 38 |
| `intake-cli-contract` | 20 | 13 |
| `serve-cli-contract` | 25 | 17 |
| `kdf-resource-policy-contract` | 54 | 172 |
| `read-resource-policy-contract` | 63 | 89 |
| `mcp-http-shutdown-contract` | 8 | 7 |
| `signal-process-contract` | 83 | 77 |
| `store-live-contract` | 20 | 26 |
| `store-observations-contract` | 66 | 24 |
| `sync-observations-contract` | 56 | 32 |
| `pairing-oracle-contract` | 67 | 21 |
| `tui-named-tests` | 1 | 0 |
| `tui-harness-check` | 1 | n/a |
| `tui-contract` | n/a | 228 |
| **sum** | **2606** | **1997** |

A full lane takes about 43 minutes on macOS and about
33 minutes on Linux when warm.

Findings of the first full runs on `ca0f2300` and what changed:

- `mcp-named-tests` (macOS): the `symvault-mcp --all-targets` total was 304, the
  gate expected 296: the merged MCP authz-order slice added 8 tests. The constant
  `AREA_MCP_TEST_COUNT` is now 304 (the count is the same on Linux).
- `mcp-named-tests` (macOS, `ae6f8340`): the total was 305, the gate expected
  304: `crates/symvault-mcp/tests/apitemplate_assets_sync.rs` (the crate-local
  API template drift guard added by `37376a4a`, H1) is one new, legitimate test.
  `AREA_MCP_TEST_COUNT` is now 305; the guard returns early (still a passing
  test) once the Go copy is deleted, so the count survives Go removal.
- `mcp-named-tests` (`local/anomaly`): the `symvault-mcp --all-targets` total is
  now 408 (measured: 0 failed, also under `TZ=Pacific/Kiritimati`, i.e. at 03:00
  local): the MCP anomaly detector added 9 unit tests (`anomaly.rs`), the 3
  `anomaly_replay` tests (Go-recorded `anomaly-detector.json`) and the 10
  `anomaly_dispatch` tests. `AREA_MCP_TEST_COUNT` was 408. The security review
  fix (warning lines written with an error-ignoring `writeln!` to the locked
  stderr after the audit row and the approval-cache invalidation; a poisoned
  detector lock recovered instead of dropping alerts) added 5 unit and 2
  `anomaly_dispatch` tests: `AREA_MCP_TEST_COUNT` is now 415.
- `http-write-contract` (macOS): one run at load 40 to 120 failed `actual
  progressing output required` (the slow reader of `rust/tls-output` received no
  byte within 34 seconds, the Go side and `rust/tcp-output` progressed). Reruns
  at load 8 to 13 passed (402 s). Timing-sensitive; run the gate below a
  1-minute load average of about 16.
- `signal-process-contract`: the earlier exit 2 at load 122 did not reproduce.
  Three consecutive macOS runs at load 14 to 17 passed (82 to 87 s) and the full
  runs of both lanes passed it.
- `kdf-resource-policy-contract` and `tui-named-tests` (Linux only):
  `gate_area_check.py log-ok LOG --exact-prefix X name ...` failed with
  `unrecognized arguments` because the container's `python3` is 3.12, whose
  argparse rejects positional names after options. The parser now accepts them
  (`parse_known_args`, with a negative control in `test_gate_area_check.py`).
- Container hygiene: `area_http_write_mutation.sh` and `area_pairing_oracle.sh`
  ran `git worktree prune` inside the Linux container. Host worktree paths do
  not exist there, so git deleted the `.git/worktrees/*` admin dirs of the host
  worktrees. Both scripts now unregister only their own scratch worktree
  (`remove_worktree_only`), the container runs with `gc.auto=0`,
  `gc.worktreePruneExpire=never`, `maintenance.auto=false` (environment and
  `/etc/gitconfig` of the image), and the `worktree-prune-check` target fails the
  gate on any `git worktree prune|repair`, `git gc` or `git prune` in `scripts/`
  or the Makefile. Never run those commands in a gate script or container.
- The gate image tag is `symvault-local-gate:1-<hash of the Dockerfile>`: a
  shared plain tag was retagged under a running lane by another worktree's
  concurrent build.

## Pull requests folded in at the start

| PR | Result |
|---|---|
| #1559 CLI local bool flags | merged into `local/rust-port` |
| #1561 git C locale | merged; doc conflict in `resumption.md` resolved by keeping both sections |
| #1536 to #1539, #1541 codeql-action 4.39.1 | merged |
| #1537 taiki-e/install-action 2.87.32 | merged |
| #1540 cargo minor/patch group | merged, subject to the local gate |
| #1542 Go aws-sdk patch group | **not** taken: it changes `go.sum`, which the frozen oracle fixtures bind (`fixture_binds_go_sources_and_corekit_pin`) and invalidates the flake `vendorHash`; no value while Go is frozen |

## Baseline

Corrected 2026-10-30: the first version of `local-gate.sh` ran each target
function under `set +e`, which disabled errexit inside the function, so a
failed `make` was masked by the status of its last command. Every `macos`
receipt before the fix reported exit 0 although `config-cli-differential`
failed on all of them (`4b474490`, `e0dad172`, `4ffada3a`, `98554d82`) and
`rust-test` failed on `f77c1657`; `make` stopped there, so the remaining
`port-contract` targets and `mcp-approval-pty-acceptance` did not run on
macOS. Those receipts are invalidated in the receipts file. The `linux`
receipts are unaffected (`docker run` is the function's last command).
The fix runs each target in `(set -e; run_<target>)`; a negative control (a
fake `make` that fails only `rust-lint`) records exit 0 with the old script
and 7 with the new one.

Linux passed on `98554d82` (58 min including Miri) and on `f77c1657`.
Fixed on the way: `fuzz/Cargo.lock` lagged the sha2 0.11.1 pin from #1540
(`4ffada3a`).
