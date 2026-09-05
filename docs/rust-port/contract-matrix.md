# Rust port contract matrix

`TODO` means the contract is identified but does not yet have a language-neutral
fixture and Rust parity test. `PASS` requires an executable test in CI; prose or
compilation is not evidence. The Go oracle is commit `caadd5e` / release
`v0.22.1` until deliberately advanced before the first implementation PR.

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
| CRYPTO-001 | X25519 identity | fixed safe test identities | Go crypto | public key and fingerprint parity | cross-language vectors | all | bytes | TODO |
| CRYPTO-002 | age entry encryption | deterministic plaintext corpus | Go crypto | mutual Go↔Rust decryption; recipient behavior | differential vectors | all/iOS | cross-decrypt | TODO |
| CRYPTO-003 | passphrase envelopes | legacy scrypt and current argon2id fixtures | Go crypto | mutual decrypt, parameter parsing, migration flags | fixture/property tests | all/iOS | bytes + cross-decrypt | TODO |
| CRYPTO-004 | re-encryption | multi-recipient add/remove corpus | Go vault | all retained recipients decrypt; removed recipients fail | end-to-end fixtures | all | semantic | TODO |
| CRYPTO-005 | password/TOTP | fixed RNG/clock vectors | Go generators | character policy, TOTP code/period/expiry | unit/property tests | all | bytes | TODO |
| STORE-001 | vault layout | fresh and legacy vault trees | Go init/open | paths, files, modes, migration and no data loss | filesystem manifest | all | metadata + hashes | TODO |
| STORE-002 | entry model | minimal/full/nested/large values | Go loader | YAML shape, metadata, ordering, limits, type inference | fixture suite | all/iOS | bytes + semantic | TODO |
| STORE-003 | safe filesystem | symlink/traversal/read-only/partial write | Go fs/vault | fail closed, atomicity, modes, cleanup | adversarial tests | all | side effects | TODO |
| STORE-004 | manifests | valid/tampered/out-of-band entries | Go manifest code | exact verification and diagnostics | fixture suite | all/iOS | bytes + semantic | TODO |
| STORE-005 | encrypted search index | build/load/stale/corrupt/concurrent | Go vault | no plaintext on disk; matching and invalidation parity | index fixtures | all | side effects + semantic | TODO |
| AUDIT-001 | HMAC chain | fixed key/clock/event corpus | Go audit | canonical JSON, HMAC chain, `kid`, reset detection | byte vectors | all | bytes | TODO |
| AUDIT-002 | key rotation/export | pre/post-rotation logs | Go audit | archive naming, verification, redaction, filters | fixture suite | all | bytes + metadata | TODO |
| SESSION-001 | cache | save/load/touch/expiry/revoke | Go session | idle/max TTL and non-refreshing probes | fake-clock tests | all | semantic | TODO |
| SESSION-002 | OS keyring | memory backend + native smoke | Go session | service/account names, binary payload, unavailable behavior | injected + native tests | native OS | semantic | TODO |
| SESSION-003 | Touch ID | available/unavailable/cancel/failure | Go Darwin bridge | prompts, fallback, no passphrase exposure | adapter + signed-app smoke | macOS | semantic | TODO |
| PLATFORM-001 | clipboard/autotype | fake backend + native smoke | Go adapters | permission, clear timer, field routing, cancellation | adapter/native tests | native OS | semantic | TODO |
| PLATFORM-002 | secure UI/notifications/daemon | injected platform commands | Go adapters | backend selection, escaping, timeouts, lifecycle | adapter tests | native OS | semantic | TODO |
| GIT-001 | init/commit/log | isolated local repositories | Go `go-git` | refs, messages, dirty state, gitignore behavior | repository snapshots | all | semantic | TODO |
| GIT-002 | push/pull/auth | local bare remote and failures | Go `go-git` | auth order, branch behavior, timeout and errors | fake/local remote | all | semantic | TODO |
| GIT-003 | reconciliation | divergent versions/conflicts | Go sync | deterministic winner and lossless conflict copies | fixture suite | all | hashes + semantic | TODO |
| IO-001 | importers | CSV/Bitwarden/1PUX/pass corpora | Go importer | accepted data, quarantine, mapping, negative cases | golden/property/fuzz | all | semantic | TODO |
| IO-002 | export/backup/restore | fixed vault | Go commands | bytes, archive members, modes, traversal defense | differential suite | all | bytes + metadata | TODO |
| IO-003 | intake/watch | isolated directory events | Go intake | staging, dedupe, debounce, disable behavior | fake-clock/watch tests | native OS | semantic | TODO |
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
