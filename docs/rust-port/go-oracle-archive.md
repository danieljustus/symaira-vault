# Go oracle archive: what the Go-free gates replay, and what was retired

The Rust tests in the CAP-CLI-B families no longer run Go. Each one either
replays a recording made once from the pinned Go oracle (replay-or-fail: a
missing or stale recording is a failure, never a skip), compares a committed
golden, or hashes a frozen input. This file records how each was converted and
the few things that were retired instead.

## Recapture (capture side, needs Go; never part of a gate)

```sh
SYMVAULT_ORACLE=capture SYMVAULT_GO_BINARY=<oracle> \
  [SYMVAULT_GO_BINARY_<first 8 hex of the oracle commit>=<oracle>] \
  cargo test -p symvault-cli --test <name> --locked
```

`common/go_oracle.rs` (transcripts, `testdata/port/cli-transcripts/`) and
`common/go_oracle_ext.rs` (keyed observations,
`testdata/port/cli-observations/`) verify the oracle binary's
`vcs.revision`/`vcs.modified`, refuse to
overwrite a recording with a different value unless the test declares the
normalization under which two captures are the same. Capture is deterministic:
two consecutive captures of the same test produce byte-identical files.

Recordings never carry the capturing machine's paths. Per-run directories are
stored as placeholders (`<ROOT:n>` / `<TMPFILE>` in transcripts; `<ROOT>`,
`<HOME>`, `<VAULT>`, `<TMP>` inside the base64 file bodies of frozen vault
trees, restored to the current run's directories on replay), and a capture
refuses to write a recording containing `/Volumes/`, `/Users/`, `/var/folders/`
or `/private/var/` (`common/operator_paths.rs`, base64 decoded).
`recordings_have_no_operator_paths.rs` rescans every committed recording.

## Conversions

| Family | Go-free mechanism |
|---|---|
| `cli_help`, `cli_help_subcommand`, `cli_get_list_help_differential`, `cli_completion_args`, `cli_dynamic_setup_help`, `cli_update_help`, `cli_generate_manpages`, `audit_commands`, `run_passthrough` | Go transcripts under `testdata/port/cli-transcripts/<test>.json`, compared exactly against the Rust CLI (help/manpages are full-text goldens) |
| `add_form_differential`, `set_differential`, `config_fix_differential`, `zero_key_differential` | keyed Go observations under `testdata/port/cli-observations/`; `zero_key` replays against frozen Go-made vaults |
| `agent_audit`, `agent_token`, `agent_upgrade_biometric`, `edit`, `migrate_v4`, `doctor_keyring`, `template_custom`, `mcp_payment_perplexity`, `mcp_set_auth_method`, `config_rewrite_differential` | Go transcripts as above; `make config-rewrite-differential` is Go-free (`check_config_rewrite.sh --capture` is the capture side) |
| `approval_pair_differential` | the Go handler responses (HMAC/mTLS pairing exchange) were recorded once into `cli-transcripts/approval_pair_differential.json` and replayed against the Rust server; the Go server `tests/approval_pair_server/main.go` is deleted |
| `symvault-ffi` `interop.rs` | `mobilebindgen --drive` verdicts and Go-sealed ciphertexts recorded into `cli-observations/ffi_interop.json`; replay unlocks/reads Go-written vaults with current Rust and decrypts Go ciphertexts and the earlier Rust-sealed ones. Together with `fixture_replay.rs` (`testdata/port/ffi/mobilebind.json`) this covers every Go<->Rust direction except the one below |
| `output_modes` Touch ID | the Go and Rust `touchIDAvailable` of the same sandbox are recorded (`cli-observations/output_modes.json`, oracle `bf7f687b`); replay asserts the attestation (Go == Rust) and, on a darwin host, that the live Rust probe equals the recorded value |
| `symvault-store` `manifest_keys.rs`, `src/tests.rs` (STORE-004) | the `git show <commit>:<path>` provenance digests are frozen constants (`SOURCE_DIGEST`, `STORE004_SOURCE_DIGEST`, `STORE004_GENERATOR_DIGEST`; generator input from `testdata/port/go-snapshots`); no git history or Go tree is read |
| `symvault-mcp` `apitemplate_assets_sync.rs` | frozen sha256 list of the 17 built-in templates (identical to the Go embed when frozen) |

Makefile: `differential-go-selftest` and `crypto-fuzz-smoke` deleted
(`rust-fuzz-smoke` stays); `mcp-oauth-contract` runs only the cargo tests;
`ffi-differential` no longer depends on `ffi-fixtures-check` or the Go driver
(`ffi-fixtures-check`/`-generate` remain as capture-side targets).

## Retired / not replayable (with reason)

- `approval_queue_differential.rs` + `tests/approval_queue_server/main.go`:
  deleted. It was already documented as a "pre-removal cross-check" of the Go
  handler; the same exchanges are asserted Go-free by
  `approval_queue_replay.rs` against the frozen `testdata/port/approval/queue.json`
  (and `approval_e2e.rs` for the mTLS flow).
- FFI interop, direction "Go opens something the *current* Rust code just
  wrote": cannot be replayed (the bytes depend on the current build). It is a
  capture-only check; replay covers Go-written and previously Rust-sealed data.
- Touch ID: the Go answer on a host other than the recording host is not
  re-established by replay (it is a property of the Mac's sensor); replay checks
  that the live Rust probe still equals the value Go and Rust agreed on when
  recorded, so a darwin host with a different sensor fails instead of passing.
