# Go oracle archive and frozen-fixture verification

The Rust port was verified against a Go oracle: generators under
`scripts/rust-port/cmd/**` recorded the frozen fixtures in `testdata/port/**`
and the `crates/*/tests/fixtures/**` corpora from pinned Go revisions. The
Rust-only repository keeps the **fixtures** and the **proof that they are
unchanged and still tied to a retrievable oracle revision**; it no longer
re-runs any Go generator. This page records what replaced the generators and how
to regenerate a fixture on purpose.

## What `make fixtures-verify` proves

`scripts/rust-port/fixtures_verify.py` (Python standard library and `git`; no
Go, no network):

1. **Bytes.** `testdata/port/FROZEN.sha256` lists `sha256  path` (the
   `sha256sum -c` format) for every frozen fixture. The frozen set is the file
   set matched by these globs relative to the repository root:
   `testdata/**` (including `testdata/importer/**`),
   `crates/*/tests/fixtures/**`, `crates/symvault-mcp/testdata/**`,
   `scripts/rust-port/fixtures/**`, and the detached oracle programs
   `scripts/rust-port/*.go.txt`. A changed, deleted or unlisted file fails.
2. **Pins.** Every oracle commit a fixture names (`commit`, `commit_sha`,
   `oracle_commit`, `oracle_commit_sha`, `base_commit`, `source_commit`,
   `revision`) must satisfy `git cat-file -e <sha>^{commit}` and must be contained
   in a branch or tag (`git for-each-ref --contains`). A loose object that no ref
   holds fails. `candidate_commit` (CI receipt evidence) and `corekit_revision`
   (an external module) are not oracle pins and are ignored.
3. **Digests.** Each digest a fixture records is classified when the manifests
   are written (`FROZEN.oracle.json`) and re-derived on every check:
   * `recomputed` - rebuilt from `git cat-file blob <sha>:<file>` with the
     provenance algorithm (`scripts/rust-port/internal/provenance`: `name NUL
     content NUL` per declared file, `go.mod`/`go.sum` excluded from the
     enforced pin set; variants with the module files, sorted names, or no
     closing NUL cover the older generators), or from per-file `sha256` maps.
   * `recorded` - the generator used an algorithm this tool does not
     reproduce, or the block has no commit to read blobs from. The claimed
     value is stored in `FROZEN.oracle.json` and a check requires the fixture
     to still claim exactly it.
   * `no-digest` - the oracle block carries no digest of that kind.

`make fixtures-verify FIXTURE="path [path...]"` limits the byte, pin and digest
checks to those files or directories (the per-row `*-fixtures-check` and
`*-differential` targets use this, then run their existing cargo replay).
`make oracle-reachability-check` additionally requires every pinned commit,
including the constants of `scripts/rust-port/mcp_oracle.py`, to be reachable
from a ref.

Accepted limit (plan risk R11): this proves the frozen bytes are unchanged and
the pinned oracle is still addressable. It does not prove that a generator would
still reproduce them; the generators stay reproducible from the tag below.

### Freezing

The manifests are rewritten only at a freeze, never by a check:

```sh
python3 scripts/rust-port/fixtures_verify.py --write   # then review `git diff --stat`
```

`--write` records digest classes and, for generator digests, the ref whose
blobs they are recomputed from (`--generator-ref`, default tag
`legacy/go-oracle`, else `HEAD`). Every pinned commit and that ref must be held
by a branch or tag **before** any `git gc`; local `oracle/*` tags, `legacy/go-oracle`
and `rust-port/local-history` are the holders.

Negative controls (`python3 -B scripts/rust-port/test_fixtures_verify.py`): a
flipped fixture byte, an unknown commit (even after a re-freeze), a deleted
manifest line, a commit no ref holds, and a tampered recomputable digest each
exit 1.

## Archived Go oracle

The Go backend, the generators and the tools that built them live at the tag
`legacy/go-oracle` (created by the coordinator at the last Go-green commit; the
local-history tag `rust-port/local-history` marks the same line). Nothing in
the current tree needs them.

To regenerate a fixture deliberately:

```sh
git worktree add --detach ../symvault-go-oracle legacy/go-oracle
cd ../symvault-go-oracle
make <removed-target>        # the target from the table below, run in the old tree
# copy the regenerated fixture back, review the semantic delta, then in the
# current tree: python3 scripts/rust-port/fixtures_verify.py --write
```

Requirements are those of the old tree (Go toolchain pinned in `go.mod`, a
clean worktree whose oracle sources equal the pinned blobs; the generators
refuse a stale pin). Regeneration must preserve all case payloads and security
controls or receive a separate semantic review (`docs/rust-port/README.md`,
"Fixture input provenance").

### Removed `*-fixtures-generate` / `*-regenerate` targets

| removed target | what it ran | writes |
|---|---|---|
| `port-fixtures-generate` | scripts/rust-port/cmd/portgen | $(PORT_CLI_FIXTURE) |
| `keyring-key-fixtures-generate` | scripts/rust-port/cmd/keyringkeygen | $(KEYRING_KEY_FIXTURE) |
| `biometric-fixtures-generate` | scripts/rust-port/cmd/biometricgen | $(BIOMETRIC_FIXTURE) |
| `quota-fixtures-generate` | scripts/rust-port/cmd/quotagen | $(PORT_QUOTA_FIXTURE) |
| `core-fixtures-generate` | scripts/rust-port/cmd/coregen | $(PORT_CRYPTO_FIXTURE), $(PORT_ERROR_FIXTURE), $(PORT_REDACT_FIXTURE), $(PORT_SECRET_REF_FIXTURE) |
| `mcp-init-fixtures-generate` | scripts/rust-port/cmd/mcpinitgen | $(PORT_MCP_INIT_FIXTURE) |
| `mcp-stdio-fixtures-generate` | scripts/rust-port/cmd/mcpstdiogen | $(PORT_MCP_STDIO_FIXTURE) |
| `git-winner-fixtures-generate` | scripts/rust-port/cmd/gitwinnergen | $(PORT_GIT_WINNER_FIXTURE) |
| `git-offline-fixtures-generate` | scripts/rust-port/cmd/gitofflinegen | $(PORT_GIT_OFFLINE_FIXTURE) |
| `policy-fixtures-generate` | scripts/rust-port/cmd/policygen | $(PORT_POLICY_FIXTURE) |
| `pairing-fixtures-generate` | scripts/rust-port/cmd/pairinggen | $(PORT_PAIRING_FIXTURE) |
| `device-session-fixtures-generate` | go test ./internal/pairing -run ^TestDeviceSessionFixture$ | testdata/port/device_sessions/contract.json |
| `approval-fixtures-generate` | scripts/rust-port/cmd/approvalgen | testdata/port/approval/queue.json, testdata/port/approval/certs |
| `approval-tls-fixtures-generate` | scripts/rust-port/cmd/approvaltlsgen | testdata/port/approval/mtls_settings.json, testdata/port/approval/certs |
| `device-approval-fixtures-generate` | scripts/rust-port/cmd/deviceapprovalgen | testdata/port/approval/device-approvals.json |
| `device-enroll-fixtures-generate` | scripts/rust-port/cmd/deviceenrollgen | testdata/port/approval/device-enroll.json |
| `cfg-fixtures-generate` | scripts/rust-port/cmd/configpathgen | $(CFG_PATH_FIXTURE) |
| `cfg-precedence-fixtures-generate` | scripts/rust-port/cmd/configprecedencegen | $(CFG_PRECEDENCE_FIXTURE) |
| `cfg-overrides-fixtures-generate` | scripts/rust-port/cmd/configoverridesgen | testdata/port/config/overrides.json |
| `cfg-sections-fixtures-generate` | scripts/rust-port/cmd/configsectionsgen | $(CFG_SECTIONS_FIXTURE) |
| `cfg-bytes-fixtures-generate` | scripts/rust-port/cmd/configbytesgen | $(CFG_BYTES_FIXTURE) |
| `mcp-anomaly-fixtures-generate` | scripts/rust-port/cmd/anomalygen | testdata/port/mcp/anomaly-detector.json |
| `rust-007-fixtures-generate` | scripts/rust-port/cmd/configgen, scripts/rust-port/cmd/sessionquotagen | $(PORT_CONFIG_FIXTURE), $(PORT_PERSISTENT_QUOTA_FIXTURE), $(PORT_PLATFORM_FIXTURE), $(PORT_SESSION_FIXTURE) |
| `config-rewrite-fixtures-generate` | scripts/rust-port/cmd/configrewritegen | testdata/port/config/rewrite.json |
| `import-cli-regenerate` | scripts/rust-port/check_import_cli.sh | crates/symvault-cli/tests/fixtures/import-command/cases.json |
| `yaml-scalar-regenerate` | scripts/rust-port/cmd/yamlscalargen | testdata/port/cli/yaml-scalars.json |
| `output-modes-regenerate` | scripts/rust-port/check_output_modes_cli.sh | testdata/port/cli/output-modes.json |
| `timestamp-fixtures-generate` | scripts/rust-port/go_timestamp_fixtures.py | the timestamp tables named in the script |
| `store-reopen-fixture` | scripts/rust-port/cmd/storereopen | testdata/port/store/reopen.json |
| `audit-fixtures-generate` | go test ./internal/audit -run ^TestAuditFixture$ | testdata/port/audit/audit.json |
| `ffi-fixtures-generate` | scripts/rust-port/cmd/mobilebindgen | testdata/port/ffi/mobilebind.json |
| `desktop-linux-fixtures-generate` | scripts/rust-port/cmd/desktopgen | $(DESKTOP_LINUX_FIXTURE) |
| `get-clipboard-fixtures-generate` | go test ./cmd -run ^TestGenerateGetClipboardFixture$; go test ./internal/ui -run ^TestGenerateTUIClipboardFixture$; go test ./internal/mcp/server -run ^TestGenerateMCPClipboardAutoClearFixture$; go test ./cmd -run ^TestGenerateGetClipboardDarwinFixture$ | testdata/port/platform/get_clipboard.json, tui_clipboard.json, get_clipboard_darwin.json, testdata/port/mcp/clipboard-auto-clear.json |
| `clipboard-linux-fixtures-generate` | go test ./internal/mcp/server -run ^TestGenerateMCPCopyClipboardLinuxFixture$; go test ./cmd -run ^TestGenerateGetClipboardLinuxFixture$ | testdata/port/mcp/copy-clipboard-linux.json, testdata/port/platform/get_clipboard_linux.json |
| `mcp-sharing-fixtures-generate` | go test ./internal/mcp/server -run ^TestGenerateMCPSharingFixture$ | testdata/port/mcp/tools-sharing.json |
| `policy-context-fixtures-generate` | go test ./internal/policy -run ^TestGeneratePolicyBuildContextFixture$ | testdata/port/mcp/policy-build-context.json |

The recipes are in the Makefile at `legacy/go-oracle` (or at commit `c069d3f2`,
the base this table was taken from). `mcp-http-init-fixtures-generate` and
`mcp-http-ratelimit-fixtures-generate` are not listed: they belong to the HTTP
process-contract rows that are converted separately.

### Check targets that no longer re-run Go

Every `*-fixtures-check` / `*-differential` target that used to run a Go
generator `--check` (or a `go test` fixture check) now runs
`make fixtures-verify FIXTURE=<its fixtures>` and then its existing cargo
replay. The CLI scripts `check_yaml_syntax_cli.sh`, `check_error_taxonomy_cli.sh`,
`check_import_cli.sh`, `check_export_cli.sh`, `check_output_modes_cli.sh` and
`check_pass_gpg.sh` follow the same pattern (`check_pass_gpg.sh` still requires a
system `gpg` and fails closed without it). `scripts/rust-port/gen_config_schema.py`
is gone: `crates/symvault-core/src/config_schema.rs` is hand-maintained.

## Go-free test replay: what the Rust tests replay, and what was retired

The Rust tests in the CAP-CLI-B families no longer run Go. Each one either
replays a recording made once from the pinned Go oracle (replay-or-fail: a
missing or stale recording is a failure, never a skip), compares a committed
golden, or hashes a frozen input. This file records how each was converted and
the few things that were retired instead.

### Recapture (needs the archived Go tree; not possible from this tree)

The Rust tests are **replay-only**: `common/go_oracle.rs` (transcripts,
`testdata/port/cli-transcripts/`) and `common/go_oracle_ext.rs` (keyed
observations, `testdata/port/cli-observations/`) no longer have a capture mode,
and `SYMVAULT_ORACLE=capture` is not read any more. A missing or stale recording
fails the test.

To record again on purpose, use the archived tree and the helpers as they were
there (they verify the oracle binary's `vcs.revision`/`vcs.modified` and refuse
to overwrite a recording with a different value unless the test declares the
normalization):

```sh
git worktree add --detach ../symvault-go-oracle legacy/go-oracle
cd ../symvault-go-oracle
# build the oracle binary there (Go toolchain from go.mod), then:
SYMVAULT_ORACLE=capture SYMVAULT_GO_BINARY=<oracle> \
  cargo test -p symvault-cli --test <name> --locked
# copy the changed recordings back, review the delta, then in the current tree:
python3 scripts/rust-port/fixtures_verify.py --write
```

The same applies to every removed `*-capture` / `go-attest-*` /
`go-observations-capture*` Makefile target: the recipes are in the Makefile at
`legacy/go-oracle`. Capture is deterministic: two consecutive captures of the same test
produce byte-identical files.

Recordings never carry the capturing machine's paths. Per-run directories are
stored as placeholders (`<ROOT:n>` / `<TMPFILE>` in transcripts; `<ROOT>`,
`<HOME>`, `<VAULT>`, `<TMP>` inside the base64 file bodies of frozen vault
trees, restored to the current run's directories on replay), and a capture
refuses to write a recording containing `/Volumes/`, `/Users/`, `/var/folders/`
or `/private/var/` (`common/operator_paths.rs`, base64 decoded).
`recordings_have_no_operator_paths.rs` rescans every committed recording.

### Conversions

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
(`ffi-fixtures-check` is a `fixtures-verify` row; regeneration needs the
archived generator at tag `legacy/go-oracle`).

### Retired / not replayable (with reason)

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
- `doctor_keyring` real-login-keychain test (orphan counting, `--fix-dry-run`):
  retired. It was opt-in and skipped by default; there is no Go-free
  replacement against a real keychain.
- STORE-004 and `manifest_keys` digests and the apitemplate sha list are frozen
  constants: they detect edits to the fixtures or templates, not drift in the
  (now removed) Go sources.
- `edit_differential` runs Rust `init` live and compares it with the recorded Go
  seed run; `approval_pair_differential` replays a handler that mirrors the Go
  enroll-code handler (404/403/401/503, 30 s HMAC window, pinned certificate
  fingerprint), not the Go handler itself.
