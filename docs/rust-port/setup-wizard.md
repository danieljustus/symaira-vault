# `symvault setup` wizard: native port, evidence and residuals (SETUP-001)

Native since `local/setup`; Go oracle `1f965f6e` (`internal/ui/wizard`, `cmd/admin/setup.go`).
Rendering is ratatui/crossterm; the step list, defaults, validation texts, resume file,
apply order and the Go quirks that decide what ends up on disk are Go's (see the module doc of
`crates/symvault-cli/src/setup_wizard.rs`).

## Review findings fixed (REQUEST_CHANGES -> re-review)

| Finding | Fix |
|---|---|
| HIGH: stale `setup` pins in `error-taxonomy-known-divergences.json` / `KNOWN_BODY_DIVERGENCES` | Removed; the pinned file now has zero cases, `NOT_NATIVE` is gone, the pin mechanism keeps a synthetic negative control (`known_divergence_pin_detects_unrelated_changes`) |
| HIGH: recipients step accepted typing (Go's `textarea` is never focused, so it drops every key) | `TextArea` starts blurred like `textarea.New()` and ignores all keys; Enter on the blank area and Ctrl+S save immediately, so no `recipients.txt` is written |
| Durable evidence | `crates/symvault-cli/tests/setup_wizard_differential.rs` (below) |
| MEDIUM: passphrase not zeroized | `Passphrase(Zeroizing<Vec<u8>>)` in `WizardState` (redacted `Debug`), `TextInput` buffer is `Zeroizing<Vec<char>>` (password inputs allocate their limit up front so typing never reallocates), `PassphraseStep::passphrase()` returns `Zeroizing`, strength/validation read a `Zeroizing<String>` |
| LOW: `touch_id_available` used `!is_test_or_ci()` | Probe is `touch_id_available()` like Go's `session.BiometricAvailable()`. Only exception: the explicit test hook `SYMVAULT_TEST_TOUCH_ID=unavailable` (a no-cgo Go oracle cannot see biometrics, so the differential must run Rust without them too) |
| LOW: `authMethod` set by `replacen` on rendered YAML | `Config.auth_method` is set on the typed config; only Go's `omitempty` case (Auth step skipped, empty method) still drops the trailing `authMethod` line, because the typed enum cannot be empty |
| LOW: TUI bytes | Out of scope by design, stated in the test header and below |

## Evidence

`cargo test -p symvault-cli --test setup_wizard_differential` (macOS, `local/setup`):

* `native_matches_recorded_go_results` (no Go needed): 27 scenarios replayed against
  `testdata/port/cli/setup-wizard/go-results.json`, 0 differences. The recording holds the
  normalized Go results plus the `go init` vault seed, so Go-initialized vaults need no Go.
* `native_matches_live_go_oracle` (`SYMVAULT_GO_BINARY`, `make setup-wizard-differential`):
  27 scenarios against Go and Rust, 0 differences, and the live Go result equals the recording
  (the recording cannot go stale). With the variable set nothing is skipped: a missing binary, fewer
  than 27 scenarios or an unreached scripted screen fails.
* Driver/comparator self-tests: PTY capture, exit code, signal, missed screen + kill, `Either`,
  alternate-screen extraction, normalizers, token-order normalization and a mutation control that
  changes each compared field (exit code, signal, ok, reached screens, post-TUI text, run label and
  count, file mode, file text, extra file, missing file, Go open check).
* Negative control for finding 2: with the old focused textarea the differential fails
  (`existing_git_recipients_ctrl_s: a typed recipient reached recipients.txt`).

Provenance of the recording: oracle commit `1f965f6e56f2507b9183cf30b822f58f7badb951` built from a
detached worktree, `go1.26.10 CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 -trimpath`, binary sha256
`a6c47be09d8b5213404f9b62d23b13ed93d469ff792a51bd1e8b667286d00ab6`; regenerate with the ignored
`record_go_results` (needs `SYMVAULT_GO_BINARY`, `SYMVAULT_GO_ORACLE_COMMIT`,
`SYMVAULT_GO_ORACLE_BUILD`).

Scenarios (27): the 18 earlier ones (happy, no-resume, abort/resume, Ctrl+C, Esc twice, bad
passphrase, agent install failure with and without `--keep-on-error`, custom/invalid profile, git
sync, git multi-device, go back, summary cancel, re-configure, re-configure with agent failure,
custom vault path) plus: Go-initialized vault + git sync + multi-device + a typed age1 recipient
(Ctrl+S and Enter variants, both must leave no `recipients.txt`), the same without recipients,
HTTP-transport agent through a resume file (creates the scoped token before the always-failing
installer), stale/corrupt resume file, `n` at the resume prompt, pre-flight failure (resume file with
`age1short`), vault-init failure (`entries` is a regular file; Go ignores the error and reports
success). Every run is checked to reach all scripted screens and exit by itself.

Compared per scenario: exit code and signal of every run; reached screens; the text printed after the
alternate-screen exit (stdout and stderr share the PTY: `Error:` lines, pause notice, panic banner),
ANSI-stripped; the sandbox file manifest (path, kind, mode, normalized text or size); and that the Go
binary opens a copy of every vault left behind (`symvault --vault <copy> list`, interop of
`identity.age`).

## Excluded, with reasons

* TUI bytes: frames, colors, cursor movement, spinner and everything written inside the alternate
  screen. bubbletea and ratatui render differently by design; behavior is covered by the scripted
  screens, not their pixels.
* Go's panic goroutine dump (cut from the Go side; Rust prints none).
* `.git` internals except `HEAD` and `config`; the `cwd` and `tmp` sandbox directories.
* Normalized: timestamps, token ids/hashes/prefixes, age public keys, resume-file name hashes,
  `tool_registry_hash`, sandbox root, and the order of `mcp-tokens.json` entries (random ids).

## Known differences vs Go (pinned, not hidden)

* `.git/config` of a **new** vault with git sync (`git_sync`, `git_multidevice`): Rust creates the
  repository through `symvault_sync::GitRepository::init` (git CLI) so the file also holds
  `repositoryformatversion`, `filemode`, `logallrefupdates`, `ignorecase`, `precomposeunicode` and a
  `[user]` block (`Symaira Vault <symvault@example.com>`); Go's go-git `PlainInit` writes only
  `bare = false`. With exactly those keys removed the files are equal
  (`accepted_git_config_divergence`), and the test fails if the difference disappears. Shared with
  `symvault init`, not wizard-specific.
* `tool_registry_hash` of tokens created by the HTTP-agent path: Rust stamps the constant
  `PINNED_TOOL_REGISTRY_HASH` (`01c5ea51...`, observed from an older oracle); the Go build at
  `1f965f6e` computes `bccf8c7e...`. The same constant feeds `agent install`/`agent token`. Normalized
  in the differential; the value is a registry-hash gap of those commands, not of the wizard.

## Residuals

* **Touch ID is unverified.** A no-cgo Go oracle can never report biometrics, so the Auth step,
  `SaveBiometricPassphrase` and `authMethod: touchid` have no Go evidence. A cgo transcript on a Mac
  with Touch ID (or a documented Go-side stub) is required before the row can be called equivalent.
* The differential was run on macOS only. The PTY driver self-tests are `cfg(unix)`; the recording
  replay is skipped on other hosts; a live Linux run (Go and Rust on Linux, different config paths)
  was not executed.
* Windows: not supported by the wizard test (`cfg(unix)`).
* TUI rendering is not compared (see above).
