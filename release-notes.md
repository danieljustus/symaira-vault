## What's changed

### Features
- #594 `symvault run` and `symvault template` improvements — closes #590, #591, #592, #593
  - Load environment-variable mappings from a file with `--env-file` (`-f`).
  - Pass positional `KEY=ref` arguments to `symvault template generate`.
  - Add `--prefix` to enumerate entry fields as individual refs.
  - Add `--passthrough` to allow specific parent environment variables through to the child process.
  - Forward stdin to child processes in `symvault run` so heredocs and piped input work.

### Fixes
- #613 Harden `symvault set` secret input, centralize "vault not initialized" error handling, remove dead `cmd/port_utils.go`, and unify the LRU-backed cache eviction path — closes #608, #609, #610, #611
- #600 Fix `go vet` failure in `passphrase_env_test.go` and resolve a `goconst` lint finding in `internal/policy/authorizer.go` — closes #595, #596
- #606 Correct `.goreleaser.yml` license from MIT to Apache-2.0 and document v0.9.0 `run`/`template` features — closes #597, #598

### Tests
- #607 Improve patch coverage for `run`/`template`/`runner` error branches — closes #599
- #615 Add policy authorizer tests to restore the overall coverage baseline — closes #614

### Dependencies
- #605 Bump the Go dependency group with 4 updates

### CI
- #601 Bump `goreleaser/goreleaser-action` from 7.2.2 to 7.2.3
- #602 Bump `golangci/golangci-lint-action` from 9.2.1 to 9.3.0
- #603 Bump `docker/setup-qemu-action` from 4.1.0 to 4.2.0
- #604 Bump `actions/attest-build-provenance` from 4.1.0 to 4.1.1

### Docs
- #612 Remove the retired Go Report Card badge from the README

**Full Changelog**: https://github.com/danieljustus/symaira-vault/compare/v0.8.1...v0.9.0
