# STORE-004 oracle cancellation and pipe ownership

Issue: [#1312](https://github.com/danieljustus/symaira-vault/issues/1312).
Baseline: `061682058ccd7faa0a2f57381b01172bd066dddd`.

## Observed failure and diagnostic boundary

The native macOS Go job in [run 37212723431](https://github.com/danieljustus/symaira-vault/actions/runs/37212723431/job/111466986993) failed
`TestRunOracleTimeoutCleansProcessGroup/parent-cancel=true` at its five-second
return bound. The original five successful local race runs did not reproduce or
explain that failure.

A subsequent 50-iteration Darwin arm64 **Go 1.26.6** race diagnostic reproduced
the same parent-cancellation return-bound failure. At the failed assertion, the
published descendant PID was absent, but both `os/exec` output-copy goroutines
were waiting for EOF and `Cmd.Wait` was blocked in `awaitGoroutines`. The caller
had left its separate five-second wait and begun removing the runtime directory
without joining those goroutines. This proves the unbounded inherited-pipe join
and premature resource teardown, not the identity of the remaining pipe holder.
The exact fork ordering and pipe-holder PID in the hosted failure are still
unconfirmed. No broader native failure is attributed to this change.

The same diagnostic also observed an empty, partially published readiness PID
and a data race after early test failure restored package globals while the
oracle goroutine was still executing. This is a distinct test rendezvous defect.

## Executable regression before repair

`TestRunOracleCancellationJoinsInheritedPipes` creates a real, separately owned
Unix process group that holds the oracle leader's stdout/stderr handles. The
leader exits and is reaped **before** parent cancellation. The test owns and
terminates the external holder; it is not claimed to reproduce the original
shell fork ordering. This deterministically isolates the confirmed pipe-join
boundary rather than depending on a probabilistic fork race.

With the final regression test and the baseline `main.go` in an isolated local
clone, all three executions failed with
`oracle did not join inherited pipes within cleanup bound` (Go command exit 1).
The control wrapper required exactly those three failures and exited 0 only
because the expected defect was reproduced. The repaired lifecycle passes the
regression and rejects any remaining oracle I/O goroutines after return.

## Ownership decision

Use the existing process-group/job-object operations and Go `os/exec` ownership:

1. Set `Cmd.Cancel` to terminate the complete owned process tree instead of
   racing default direct-child cancellation against a second caller-owned kill.
2. Set `WaitDelay` to two seconds, matching the existing differential harness.
   This bounds inherited-pipe cleanup, including an already-reaped leader.
3. Call `Cmd.Wait` synchronously. Do not remove source/runtime directories or
   return while process output goroutines remain unjoined.
4. Preserve cancellation, wait, group-kill and close errors. Report
   `ErrWaitDelay`, and attempt owned-group termination on that error even when
   natural leader exit preceded the context deadline.
5. Preserve Windows suspended-start, assignment-failure reaping and retryable
   job-handle ownership. Those platform helpers are unchanged.

No timeout was increased. The Unix deadline and parent-cancellation tests now
publish the deepest SIGTERM-resistant descendant atomically and join the oracle
before restoring globals, including assertion-failure paths.

## Provenance and local verification

All seven existing generator files remain working-tree-bound. The six production
source files remain `git show`-bound to
`caadd5ef95e8f19fabd3ae3d2c04caa296f2fd44` / `v0.22.1`. Two actual Go 1.26.6
captures were byte-identical; both complete frozen outcome payloads and all
other metadata were unchanged. Only `generator_digest` changed. Rust computes
that digest from the actual generator files, so there is no expected digest
literal to update. Resource-policy source membership is immutable-pin-bound;
its producer and source pin were not changed or weakened.

The final source passed these native Darwin checks, with explicit Go 1.26.6 and
an isolated per-worktree Cargo target directory:

- Complete generator tests, both ordinary and race-enabled; both cancellation
  subcases and the inherited-pipe regression executed.
- Generator `-check`, `go vet`, and scoped `golangci-lint` (zero issues).
- Meaningful disposable mutations: `entry_exists: true` to `false`, and group
  `SIGKILL` to `SIGTERM`; each valid control first passed, each mutation was
  rejected specifically as fixture drift, and verification did not rewrite it.
- Complete `symvault-store` tests (126 unit tests plus integration targets),
  including both STORE-004 replay/provenance tests; strict all-target/all-feature
  Clippy and scoped Rust format verification.
- Windows test-binary cross-compilation, preparation only, not native proof.

A 20-iteration repaired race stress passed both subcases every time before a
lint-only removal of a redundant error conversion. Full affected Go and Rust
checks were rerun after that final source edit. Workspace-wide `cargo fmt --all`
encountered the pre-existing nested-worktree discovery of excluded
`third_party/argon2` against the outer checkout; no unrelated manifest was
changed. Scoped `cargo fmt -p symvault-store --check` passed.

## Remaining integration gates

Fresh hosted native macOS, Unix and Windows acceptance and an independent
candidate-bound review are required before integration. A PR, a local pass or
Windows cross-compilation is not that evidence. Keep #1312 open until the
complete acceptance is integrated. This is not migration completion, release,
cutover or removal of the Go oracle.
