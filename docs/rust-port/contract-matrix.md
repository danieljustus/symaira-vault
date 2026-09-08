# Rust port contract matrix

`TODO` means the contract is identified but does not yet have a language-neutral
fixture and Rust parity test. `PASS` requires an executable test in CI; prose or
compilation is not evidence. Platform-scoped `PASS` rows also require native
runtime evidence for each claimed platform; a host-only run is not platform
coverage. The Go oracle is commit `caadd5e` / release
`v0.22.1` until deliberately advanced before the first implementation PR. The
`AUDIT-001`/`AUDIT-002` vectors deliberately advance only their production-Go
oracle to commit `a57f565a`; all other rows retain the baseline oracle.

| ID | Seam | Fixture / input | Go oracle | Expected contract | Rust evidence | Platforms | Compare | Status |
|---|---|---|---|---|---|---|---|---|
| CLI-001 | Version | `version`, output variants, extra args, `--version` | Go binary | exact exit/stdout/stderr and schema | `symvault-cli/tests/version.rs` + staged differential suite | macOS/Linux/Windows | bytes | PASS |
| CLI-002 | Command tree | every visible/hidden command | `cmd.NewRootCmd()` generator | paths, aliases, groups, arity, annotations | inventory drift test | all | semantic + bytes | TODO |
| CLI-003 | Flags | local/inherited flags and defaults | Cobra generator | names, shorthands, types, defaults, required/conflicts | inventory drift test | all | semantic | TODO |
| CLI-004 | Help/completions/manpages | all commands, four shells, man tree | Go generators | stable content and executable completions | snapshots + shell checks | all | bytes/declared normalization | TODO |
| CLI-005 | Error taxonomy | invalid args/config/auth/not-found | Go binary | exit codes 0–10, stream placement, no secret leakage | differential cases | all | bytes | TODO |
| CLI-006 | Output modes | text/JSON/YAML/NDJSON capable commands | Go binary | field names, ordering, omission, newline behavior | differential cases | all | bytes/semantic by row | TODO |
| CLI-007 | Signals | long-running watch/MCP/broker | Go binary | cancellation, flushing, process-tree cleanup, exit 130 where defined | signal harness | macOS/Linux/Windows equivalent | semantic | TODO |
| CFG-001 | Defaults | empty HOME/XDG | Go loader | XDG defaults and legacy fallback | config fixtures | all | semantic | TODO |
| CFG-002 | Precedence | flags/env/current/legacy config combinations | Go loader | exact precedence and validation | table-driven fixtures | all | semantic | TODO |
| CFG-003 | Config bytes | canonical/unknown/corrupt YAML | Go loader/writer | keys, durations, unknown-field behavior, modes | round-trip tests | all | bytes + semantic | TODO |
| CRYPTO-001 | X25519 identity | fixed safe test identities | Go crypto | public key and fingerprint parity | cross-language vectors | all | bytes | PASS |
| CRYPTO-002 | age entry encryption | deterministic plaintext corpus | Go crypto | mutual Go↔Rust decryption; recipient behavior | differential vectors | all/iOS | cross-decrypt | PASS |
| CRYPTO-003 | passphrase envelopes | legacy scrypt and current argon2id fixtures | Go crypto | mutual decrypt, parameter parsing, migration flags | fixture/property tests | all/iOS | bytes + cross-decrypt | PASS |
| CRYPTO-004 | re-encryption | multi-recipient add/remove corpus | Go vault | all retained recipients decrypt; removed recipients fail | end-to-end fixtures | all | semantic | PASS |
| CRYPTO-005 | password/TOTP | fixed RNG/clock vectors | Go generators | character policy, TOTP code/period/expiry | unit/property tests | all | bytes | PASS |
| POLICY-001 | policy/tier evaluation | versioned rule cases with explicit `EvalContext` fields (agent/path/tags/working dir/env/action/tool/UTC clock/secret count), plus read-only/standard/admin tier inputs; no YAML/filesystem/runtime discovery or YAML field-presence precedence | `internal/policy.(*Policy).Validate`, `internal/policy.NewEngine`, `(*policy.Engine).Evaluate`, `(*policy.TimeRange).Contains`, `internal/config.GetPreset`, `internal/config.ApplyTierPreset` | deterministic validation, priority ordering, condition matching, wrap-around time ranges, default deny/result shape, and exact tier preset values/copy behavior; `Engine.Evaluate` is exercised only for pure branches with an explicit `EvalContext`, with `RateLimiter` and `AuditLogFunc` side effects excluded; rate-limit behavior belongs to `QUOTA-001`/`QUOTA-002`. Policy loading and runtime discovery remain outside this row; YAML field-presence/config override remains `CFG-002`/`RUST-007`; approval queues and MCP tool filtering/call-time enforcement belong to `RUST-010` through `MCP-002`/`MCP-003`, including later policy audit/enforcement integration. | Go-generated JSON vectors consumed by `symvault-core` unit/property tests; fixed-context differential cases; provenance and source/generator digest drift gate in `policygen`; `cargo +nightly miri test -p symvault-core` | macOS/Linux/Windows/FreeBSD | semantic + bytes for serialized results | PASS |
| QUOTA-001 | pure quota/rate-limit bucket transitions | Before any fixture generation or porting, add a narrow production-compatible Go seam: pure `internal/policy.TransitionRateLimit(state RateLimitState, limits RateLimitLimits, now time.Time, event RateLimitEvent) -> (nextState RateLimitState, result RateLimitResult)` over language-neutral in-memory state carrying `tokens`, `capacity`, `refillRate`, `lastRefill`, `dailyCount`, `dailyWindowStart`, and `maxPerDay`; cover only explicit `set_limits` and `allow` events, refill, daily-window rollover, and limit decisions; no registry, filesystem, or process locking | the required `internal/policy.TransitionRateLimit` seam | deterministic single-bucket state transitions from explicit state/time/limits; `AgentRateLimiter` unknown-agent, `HasLimits`, per-agent isolation, and `Cleanup` are excluded and specified by the `QUOTA-002` wrapper fixture layer | Go-generated JSON transition vectors from the production helper plus Rust property tests over explicit clock/state; differential evidence in `symvault-core`; no `PASS` until fixtures/tests run in CI | macOS/Linux/Windows/FreeBSD | semantic state-transition comparison | PASS |
| QUOTA-002 | persistent quotas and registry wrapper | versioned `.quotas.json` layout (`{"counters":{...}}`), vault-directory/file modes (0700/0600), `New`/`Increment`/`Check`/`Reset`/`Close`, closed/malformed/I/O errors, same-process and cross-process concurrency; Unix `flock` and Windows `LockFileEx`; plus a separate public-wrapper fixture layer for `AgentRateLimiter` unknown-agent behavior, `HasLimits`, per-agent isolation, and `Cleanup`; no copied transition logic or private-field mutation | `internal/quotas.New`, `(*quotas.QuotaCounter).Increment`, `Check`, `Reset`, `Close`, plus `internal/policy.NewAgentRateLimiter`, `(*policy.AgentRateLimiter).Allow`, `SetLimits`, `HasLimits`, and `Cleanup` | exact `.quotas.json` bytes/schema, modes, durable reset/increment/check behavior, error outcomes after close/corrupt/I/O failures, process-safe Unix/Windows locking and concurrent updates, and executable registry-wrapper semantics; pure bucket transitions remain `QUOTA-001` | Go-generated JSON/filesystem manifests and concurrency transcripts plus wrapper fixtures consumed by `symvault-platform` tests; native Unix/Windows evidence; no `PASS` until fixtures/tests run in CI | macOS/Linux/Windows/FreeBSD | bytes + metadata + side effects + semantic | TODO |
| STORE-001 | vault layout | fresh and legacy vault trees | Go init/open | paths, files, modes, migration and no data loss | filesystem manifest | all | metadata + hashes | PASS |
| STORE-002 | entry model | minimal/full/nested/large values | Go loader | YAML shape, metadata, ordering, limits, type inference | fixture suite | all/iOS | bytes + semantic | PASS |
| STORE-003 | safe filesystem | symlink/traversal/read-only/partial write | Go fs/vault | fail closed, atomicity, modes, cleanup | adversarial tests | all | side effects | PASS |
| STORE-004 | manifests | valid/tampered/out-of-band entries | Go manifest code | exact verification and diagnostics | fixture suite | all/iOS | bytes + semantic | PASS |
| STORE-005 | encrypted search index | build/load/stale/corrupt/concurrent | Go vault | no plaintext on disk; matching and invalidation parity | index fixtures | all | side effects + semantic | PASS |
| AUDIT-001 | HMAC chain | fixed key/clock/event corpus | Go audit | canonical JSON, HMAC chain, `kid`, reset detection | byte vectors; local macOS differential only; CI/native matrix pending | all | bytes | in_progress |
| AUDIT-002 | key rotation/export | pre/post-rotation logs | Go audit | archive naming, verification, redaction, filters | fixture suite; local macOS differential only; CI/native matrix pending | all | bytes + metadata | in_progress |
| SESSION-001 | cache | save/load/touch/expiry/revoke | Go session | idle/max TTL and non-refreshing probes | fake-clock tests | all | semantic | TODO |
| SESSION-002 | OS keyring | memory backend + native smoke | Go session | service/account names, binary payload, unavailable behavior | injected + native tests | native OS | semantic | TODO |
| SESSION-003 | Touch ID | available/unavailable/cancel/failure | Go Darwin bridge | prompts, fallback, no passphrase exposure | adapter + signed-app smoke | macOS | semantic | TODO |
| PLATFORM-001 | clipboard/autotype | fake backend + native smoke | Go adapters | permission, clear timer, field routing, cancellation | adapter/native tests | native OS | semantic | TODO |
| PLATFORM-002 | secure UI/notifications/daemon | injected platform commands | Go adapters | backend selection, escaping, timeouts, lifecycle | adapter tests | native OS | semantic | TODO |
| GIT-001 | init/commit/log | isolated local repositories | Go `go-git` | refs, messages, dirty state, gitignore behavior | `testdata/port/sync/sync.json` generated by `syncgen`; `symvault-sync/tests/contracts.rs` | all | semantic | PASS |
| GIT-002 | push/pull/auth | local bare remote and failures | Go `go-git` | auth order, branch behavior, timeout and errors | `testdata/port/sync/sync.json` generated by `syncgen`; candidate local-bare test in `symvault-sync/tests/contracts.rs` | all | semantic | in_progress |
| GIT-003 | reconciliation | divergent versions/conflicts | Go sync | lossless deterministic conflict-copy projection; version-winner parity remains pending | `testdata/port/sync/sync.json` generated by `syncgen`; lossless projection and order-independence tests in `symvault-sync/tests/contracts.rs` | all | hashes + semantic | in_progress |
| IO-001 | importers | CSV/Bitwarden/1PUX corpora | Go importer | accepted data, quarantine, mapping, negative cases; pass adapter excluded until external gpg is exercised | Go-generated `testdata/port/sync/sync.json`; exact CSV/Bitwarden/1PUX Rust projections and quarantine tests | all | semantic | PASS |
| IO-002 | export/backup/restore | fixed vault | Go commands | export bytes plus archive members, modes, restore and traversal defense; compressed container bytes excluded | Go-generated `testdata/port/sync/sync.json`; byte export and archive manifest/restore/traversal tests | all | bytes + metadata | PASS |
| IO-003 | intake/watch | isolated directory events | Go intake | portable staging/dedupe/debounce evidence only; native watcher behavior remains unproven | Go-generated portable case plus Rust `scan_at`/process tests; native watcher test not present | native OS | semantic | in_progress |
| MCP-001 | initialize | raw line/framed requests | Go stdio server | IDs, versions, instructions, capabilities, notifications | raw-frame harness | all | bytes/semantic | TODO |
| MCP-002 | tool surface | agent tiers and runtime capabilities | Go `tools/list` | all 35 definitions, schema, order, annotations, availability | registry snapshots | all | bytes/semantic | TODO |
| MCP-003 | tool calls | success/invalid/scope/backend corpus | Go server | result envelopes, `structuredContent`, errors, redaction | differential suite | all | bytes/semantic | TODO |
| MCP-004 | stdio hygiene | malformed/oversized/cancelled streams | Go server | zero stdout pollution, bounded input, clean shutdown | raw-frame/property/fuzz | all | raw bytes | TODO |
| HTTP-001 | MCP HTTP/SSE | request/session/replay matrix | Go HTTP server | routes, statuses, headers, SSE framing, shutdown | HTTP transcript tests | all | bytes/semantic | TODO |
| HTTP-002 | bearer/scoped tokens | issue/use/expire/revoke/rotate | Go auth | storage bytes, scopes, TTL, aliases, failure codes | fake-clock fixtures | all | bytes + semantic | TODO |
| HTTP-003 | OAuth/PKCE/DCR | discovery/register/authorize/token/refresh | Go auth server | endpoints, validation, persistence, single-use rotation | protocol suite | all | transcript + bytes | TODO |
| HTTP-004 | origin/TLS/limits | hostile hosts/origins/bodies/timeouts | Go server | CSRF/host checks, request bounds, TLS behavior | adversarial suite | all | semantic | TODO |
| BROKER-001 | command execution | fake executables and process trees | Go run/broker | env injection, PTY, timeout, cleanup, redaction | process harness | native OS | semantic | TODO |
| BROKER-002 | outbound API/templates | loopback HTTP server | Go broker/template | SSRF policy, headers/body, secret non-exposure | HTTP transcript tests | all | bytes/semantic | TODO |
| FFI-001 | mobile API | every `pkg/mobilebind` function | Go XCFramework | signatures, JSON, bytes, errors | Swift/Rust integration tests | macOS/iOS | bytes/semantic | TODO |
| FFI-002 | extension budget | read/decrypt/list fixture | Go and Rust frameworks | measured RSS and latency on real device | device report | iOS | measured | TODO |
| DIST-001 | targets | current build matrix | Go release | linux/windows/freebsd amd64+arm64; darwin amd64+arm64 | native/cross smoke | all | executable | TODO |
| DIST-002 | archives/packages | release snapshot | GoReleaser | names, members, completions, manpages, MCPB, DEB/RPM/APK | manifest script | all | metadata + hashes | TODO |
| DIST-003 | trust chain | signed prerelease | current workflow | checksums, cosign, SBOM, provenance, macOS signing/notarization | release readback | all | cryptographic | TODO |
| DIST-004 | Homebrew/Scoop/Docker/Nix | isolated installs | current release | install, version, init, persisted paths | ecosystem smoke | relevant OS | semantic | TODO |
| DIST-005 | rollback | Rust-written copied vault | frozen Go fallback | Go opens and mutates safely after rollback | release harness | all | semantic + hashes | TODO |
| VALUE-001 | value gate | representative release builds | measured Go baseline | >=20% size or RSS gain; <=10% p95 regression | paired benchmark JSON | macOS arm64 + CI sample | measured | TODO |

> RUST-006 local executable evidence: `make audit-differential` passed twice from clean `target/audit` outputs on macOS, plus the focused Rust audit test (canonicalization, mutation/reorder/reset negatives, rotation, count/age retention, export ordering, filtering, and redaction) and deny-warnings Clippy checks. The fixture is generated through the production Go audit package and is provenance-bound to Go commit `a57f565a`, including both build-tagged keystore implementations. This local run does not establish CI or native Linux/Windows/FreeBSD evidence, so `AUDIT-001` and `AUDIT-002` remain `in_progress` and make no platform-wide `PASS` claim.
>
> RUST-007 local executable evidence: `cargo test -p symvault-core -p symvault-platform`, deny-warnings Clippy, `GOWORK=off go test ./internal/config ./internal/session ./internal/quotas ./scripts/rust-port/cmd/quotagen`, and the Go quota fixture check passed in this worktree. This does not promote CFG/SESSION/PLATFORM/QUOTA-002 to `PASS`: native OS keyring/UI/daemon evidence and CI fixture integration remain required.
>
> RUST-005 executable evidence in this worktree was run on macOS. Linux, Windows, FreeBSD, and iOS-native evidence remains outside this run; the shared Rust paths avoid OS-specific APIs, while native filesystem gates must still run on those targets before a platform-specific release claim.

## Rules

- Every `TODO` receives a deterministic generator or explicit live-test protocol
  before its Rust implementation is considered complete.
- Ciphertext randomness is never normalized into false byte parity. Validate
  mutual decryption, recipient semantics, and parsed format invariants instead.
- Every ignored or normalized field is named here with a reason before use.
- Fixtures use generated test identities and isolated HOME/XDG/keyring backends;
  they never copy data from a real vault.
- Go bugs are not silently preserved or silently fixed. Record a versioned
  contract change first, then update both implementations or the oracle.
