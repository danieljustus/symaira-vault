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
   - `macos`: native Darwin/arm64, `rust-lint rust-check rust-test
     port-contract mcp-approval-pty-acceptance`. When Go code changed against
     `origin/main`: changes only under `scripts/` race-test just those
     packages; any other Go, `go.mod` or `go.sum` change runs `make test`.
   - `linux`: native Linux/arm64 container (`scripts/rust-port/local-gate/Dockerfile`,
     pins mirror `.github/workflows/ci.yml`), `rust-gates-core port-contract
     mcp-approval-pty-acceptance rust-miri`.
   Each run appends a receipt (SHA, target, exit, log) to
   `target/local-gate/receipts.jsonl` unless `LOCAL_GATE_RECEIPTS` points
   elsewhere.
4. **Matrix wording.** A row may be promoted with the label
   `PASS (local)`: name the SHA and both receipts (`macos`, `linux`). Never
   write that a row ran in hosted CI when it did not. `PASS (local)` rows are
   confirmed or corrected by the closing CI run.
5. **Closing PR.** When the backlog is done: merge current `main` into
   `local/rust-port`, rerun the gate, open one pull request, fix what hosted CI
   finds, merge. Release, cutover and Go removal (RUST-013 to RUST-015) stay
   separate authorizations.

## Known limits of the local gate

- Linux runs on arm64 Debian bookworm, CI on x86_64 Ubuntu 24.04. Defects that
  depend on the CPU architecture, glibc version or Ubuntu packaging surface only
  in the closing CI run.
- Hosted macOS keychain tests (`keychain-native`) and the Go matrix jobs
  (`test`, `build`, `integration-test`, `smoke-test`) are not part of the local
  gate. Go is the frozen oracle; it is tested only when a slice edits Go
  code (see rule 3).
- Findings accumulate until the closing PR instead of surfacing per slice.

## Pull requests folded in at the start

| PR | Result |
|---|---|
| #1559 CLI local bool flags | merged into `local/rust-port` |
| #1561 git C locale | merged; doc conflict in `resumption.md` resolved by keeping both sections |
| #1536 to #1539, #1541 codeql-action 4.39.1 | merged |
| #1537 taiki-e/install-action 2.87.32 | merged |
| #1540 cargo minor/patch group | merged, subject to the local gate |
| #1542 Go aws-sdk patch group | **not** taken: it changes `go.sum`, which the frozen oracle fixtures bind (`fixture_binds_go_sources_and_corekit_pin`) and invalidates the flake `vendorHash`; no value while Go is frozen |
