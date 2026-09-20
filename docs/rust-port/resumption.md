# Rust migration handover — 2026-09-09

## Zwischenstand 2026-09-18 (nach `56e0c83c`, ersetzt nichts darunter)

- **Gepusht:** `56e0c83c` auf `migration/rust-batch-20260916`, Draft PR #1069.
- **Drei native CI-Fehler von `dce458bf` root-cause-behoben** (`d9bc4f0f`):
  Windows-XDG-Pfad parität zu Go komponentenweise gejoint (`xdg_base`/`xdg_root`),
  `share revoke`-Differential sortiert jetzt (Go iteriert eine Map: 3 verschiedene
  Reihenfolgen in 12 Läufen des gepinnten Oracles, also kein Vertrag), macOS
  `ShareStore::read_verified` gegen Symlink-Präfix kanonisiert (Reproduktion:
  Fehler `ENOTDIR` mit Symlink-`TMPDIR`, identisch zum CI-Fehler).
- **Human-TTY-Approval portiert** (`e89a633c`, `bc44b3b6`): `crates/symvault-platform/src/approval.rs`
  mit Prompt-Renderer, Go-Duration-Text, Timeout, Raw-Mode-Restore und
  `/dev/tty`-Zugriff über `rustix` (Crate bleibt `#![deny(unsafe_code)]`).
  Review hat drei Abweichungen gefunden und korrigiert: Enter kommt im Raw-Mode als
  `\r` (nicht `\n`), Cooked-Mode wird vor dem Acknowledge wiederhergestellt,
  Zeilen werden nach Runen (nicht Bytes) gepolstert.
- **MCP `approve_share` verbunden** (`0d5abe96`): menschliche Bestätigung
  verpflichtend, Selbstfreigabe vor dem Prompt verweigert, fehlende TTY fail-closed,
  Grant wird unter Sperre erneut geprüft, Nicht-Bestätigung lehnt ab (wie Go).
  8 neue Protokolltests; Workspace 655/655 grün.
- **CI-Laufzeit gemessen und halbiert** (`56e0c83c`): Der Job `Rust` war mit 33,7 min
  der kritische Pfad, davon ~22 min Miri. Miri läuft jetzt als eigener paralleler
  Job; `make rust-gates` behält seine Bedeutung (`rust-gates-core` + `rust-miri`).
  Basis: `docs/rust-port/ci-runtime.md`. Erwartung ~22 min; nächster Hebel ist die
  Per-Test-Messung der Miri-Laufzeit (läuft).
- **CLI-Lückeninventur erzeugt** (`docs/rust-port/cli-gap-inventory.md`): 11 von 45
  Top-Level-Gruppen fehlen komplett, dazu 30+ Subkommandos und 11 Flag-Lücken.
  Zwei Worker-Lanes laufen dagegen: Agent-Token-Mutationen (`new`/`revoke`/`rotate`)
  und `auth set`/`auth rotate-passphrase`/`audit rotate-key`/`config validate`.
- **Offene, bewusste Lücke:** Windows-TTY-Approval fehlt (fail-closed „deny“,
  `ponytail:`-Kommentar nennt den Upgrade-Pfad `CONIN$`/`CONOUT$` + `SetConsoleMode`).
- Verbleibend: 13 von 35 MCP-Tools ohne Handler (davon 7 GUI-/Biometrie-abhängig),
  HTTP/OAuth/Broker, native Biometrie/Session, Swift-Bridge, Rest-CLI/TUI,
  Release-/Value-/Rollback-Gates. Go bleibt Produktion; kein Cutover/Release.

## Zwischenstand 2026-09-20 (nach `1d534410`)

- **`main` war rot**: CI-Lauf 35505824525 (`1d534410`) scheiterte in
  `Test (macos-latest)` und `Test (windows-latest)`, beide im Go-Testcode der
  Migration, nicht im Produktcode.
  - macOS: `entry_writer_crosslang_test.go:36: build Rust writer: context deadline
    exceeded` — der kalte Cargo-Build der Store-Beispieladapter lief in das
    2-Minuten-Limit des Adapter-Helfers. Alle vier Build-Aufrufe teilen jetzt
    `crosslangBuildTimeout` (15 min); die 2 Minuten bleiben für das Ausführen
    bereits gebauter Adapter.
  - Windows: `sessiongen` legte ein Vault-Verzeichnis `special-<&>-U+2028` an,
    das Windows ablehnt (`mkdir ... syntax is incorrect`). Der Generator entfernt
    dort jetzt `<` und `>` genau wie `fixture_path` im Rust-Differential und
    behält `&`/U+2028, weil darauf der JSON-Escaping-Vertrag beruht.
- Fixture `testdata/port/cli/session.json` wurde bewusst mit dem gepinnten
  Oracle `fca3f894` neu erzeugt; nur `generator_digest` ändert sich. Ein neuer
  Test bindet diesen Digest, weil kein Make- oder Workflow-Ziel `sessiongen`
  ausführt — die Datei konnte bisher unbemerkt veralten.
- Kein Cutover, kein Release; Go bleibt Produktion. Native CI für den neuen Head
  steht aus.

## Candidate and provenance

- **Integration candidate before this handover document:** `542175e09d40c2f06a0e1ab2cd0fb412fd8db50b`; it is based on `origin/main` `81210de2720ee000fa26adda4da4080daae01677`.
- The candidate reconciles the reviewed storage-recovery sequence from stale PR [#1020](https://github.com/danieljustus/symaira-vault/pull/1020) and the clean current-main search-index sequence from draft PR [#1025](https://github.com/danieljustus/symaira-vault/pull/1025). Neither source PR is itself claimed as merged by this document.
- The original local `47562eda7610db7d6f854f219023f6b97d90f503` is only a source reference for index-wire behavior. Its direct application conflicts with current main; the candidate uses the complete #1025 acceptance sequence instead.
- During reconstruction a separate checkpoint object (`43010ab28d4fb0448e0b2f3250390d6268dcaa55`) containing other parallel WIP was observed. Its local ref was subsequently absent from the original checkout; do not assume it remains reachable. It is not an input to this candidate and any recovered contents must be reconciled independently, not replayed blindly.
- Product contract PB-2026-09-09 revision 2 was used as an operational constraint: Vault remains standalone-first; no product, repository, module, Swift, release, or deployment migration is included. The local product-boundary commit `d3df9ee9de4ccecf4f6146993414a41f0d2d0e23` was not asserted to be on `main` and was not modified here.

## Integrated bounded scope

The candidate restores and tests the currently commissioned **RUST-005 storage slice**: persisted entry metadata, configured-recipient write behavior, rooted publication/deletion with fault paths, manifest sequencing, deterministic reopen handling, and encrypted search-index wire parity. Relevant public Go consumers remain `internal/vault/entry_readwrite.go`, `manifest.go`, `manifest_updater.go`, and `search.go`; the Rust implementation boundary is `crates/symvault-store` with test-only adapters under `crates/symvault-store/examples/`.

Data ownership remains the existing vault filesystem: encrypted entry files, manifest metadata, and encrypted search indexes. No productive vault was opened or migrated during verification; all contract tests create isolated temporary roots. There is no new public Rust CLI/MCP/HTTP entry point. The shipped Go CLI/service remains the executable reference and rollback implementation.

Native helpers and permissions remain outside this slice: `crates/symvault-platform`, macOS keychain/UI/clipboard/LaunchAgent behavior, Windows locking/reparse semantics, and the Swift `client/` bridge are not migrated or changed. This keeps the current boundary compatible with later Brain integration without enlarging MCP privileges or moving master keys.

## Verification at the candidate source

Executed on **macOS arm64**, Go `1.26.6`, Rust `1.98.0`, with `GOWORK=off`:

| Command | Result | Evidence scope |
| --- | --- | --- |
| `go test -v -timeout=15m -skip 'TestFlow|TestBinaryE2E|Integration' ./...` | PASS | Go CLI, MCP/error handling, filesystem and process-lifecycle suites; no productive vault paths used. |
| `go test ./internal/vault -run '^(TestEntryWriterGoRustLiveAcceptance|TestManifestSequenceGoRustDifferential|TestManifestSequenceJSONTransportControls|TestEncryptedIndexGoRustLiveAcceptance)$' -count=1 -timeout=20m -v` | PASS | Live Go↔Rust writer, manifest, transport-control, and encrypted-index contracts. |
| `go test ./cmd -run '^(TestCmdRun_BrokerWiring|TestCmdRun_WorkingDir)$' -count=1 -v` and `go test ./cmd/crud -run '^TestEditCommand_UpdatesEntry$' -count=1 -v` | PASS | Nested CLI/process output and safe temporary-filesystem behavior. |
| `cargo test -p symvault-store --all-targets --all-features --locked` | PASS | Rust store unit, audit, root-mutation, and adapter targets. |
| `cargo nextest run --workspace --all-features --locked` | PASS: 203 tests | Workspace implementation suite. |
| `make port-contract` | PASS | Frozen Go fixture generation, command/tree and core/crypto differential checks, bounded fuzz smoke. |
| `make rust-security` | PASS | `cargo audit` plus both workspace and fuzz `cargo deny` checks; duplicate-license warnings were non-fatal. |
| `make rust-fuzz-smoke rust-miri rust-features rust-coverage rust-version-contract` | PASS | Pinned fuzz smoke, Miri, feature combinations, coverage summary, and all 10 version differential cases. |
| `golangci-lint run --new-from-rev=origin/main` | PASS: 0 issues | No candidate-introduced Go lint finding. |
| `go run github.com/securego/gosec/v2/cmd/gosec@v2.22.0 -exclude-generated -exclude-dir=testdata ./...` | PASS: 0 issues | CI-pinned Go SAST version; resolved `google.golang.org/grpc` is `v1.83.2`. |
| [Rust storage differential #34369625689](https://github.com/danieljustus/symaira-vault/actions/runs/34369625689) | PASS | Native Ubuntu, macOS, and Windows Go↔Rust storage/publication and live writer/manifest/index checks for PR #1027 head `7ea1cbfb1d1d6350eb7dcbc30545d34dbbda506c`; the preceding source commit is `542175e09d40c2f06a0e1ab2cd0fb412fd8db50b`. |
| [Rust audit differential #34369681055](https://github.com/danieljustus/symaira-vault/actions/runs/34369681055) | PASS | Native Ubuntu, macOS, and Windows audit-differential workflow for the same PR head. |

The current local `golangci-lint run` and locally installed gosec `2.29.0` report pre-existing whole-repository findings outside this candidate. They are not treated as new migration regressions; CI uses pinned `gosec v2.22.0` and remains the authoritative protected gate.

## Deliberate non-claims and blockers

- `RUST-005` remains **in_progress** in `work-items.json`. The above proves bounded native Ubuntu/macOS/Windows storage behavior; it does not prove all read/list/index/legacy-migration paths, cross-process writer behavior, or full transactionality on every supported platform.
- Native Ubuntu, macOS, and Windows storage/audit evidence is recorded above. FreeBSD and iOS runtime evidence is still required for rows that claim those platforms; cross-compilation does not substitute for it.
- RUST-006 audit, RUST-007 platform/config/session, RUST-008 sync/import/export/intake, and all CLI/MCP/HTTP/FFI/distribution/cutover work remain at their ledger states. Do not promote their matrix rows from the presence of a compiled crate or a fixture projection.
- The existing Go fallback is mandatory. Reproducible rollback is: start from pinned `origin/main` `81210de2720ee000fa26adda4da4080daae01677`, build the Go CLI with Go 1.26.6, and operate a copy of a Rust-written test vault only after the future `DIST-005` compatibility gate passes. No Go deletion, release, tag, deployment, or productive-store migration is authorized by this checkpoint.

## Handover operating notes

- Work only from a clean, named candidate branch; retain the Go reference and use the checked-in fixture generators rather than copied behavior.
- Record each native CI run against its exact head SHA before changing matrix status. A configured workflow is not evidence of execution.
- Preserve any re-discovered parallel worktrees/branches and the checkpoint object above. Do not reset, clean, delete, or bulk-commit them.
- **Conclusion at this checkpoint:** `STABILER TEILSTAND, MIGRATION NOCH OFFEN`. The storage/index candidate has native Ubuntu/macOS/Windows evidence and is a bounded behavior-preserving module-move input; it is not release-, cutover-, or consolidation-ready while the listed RUST-005 and later-slice gaps remain.

## Continuation checkpoint: 2026-09-18, HEAD `f929e819`

The active integration branch is `codex/vault-rust-resume-20260917`; the pushed PR branch is `migration/rust-batch-20260916`, PR #1069 remains Draft. Agent profile edit, token listing, audit display, read-only `agent doctor`, signed pending share requests, share lifecycle persistence, and the grant-signing-key loader are connected. `agent doctor` checks the configured profile, skill path, YAML frontmatter, `managed_by: symaira` sentinel, and body SHA-256 drift without modifying files.

The prior general CI failure was reduced to a Clippy `write_literal` warning in the token-table heading. Commit `f929e819` fixes that warning; local workspace Clippy, three focused doctor tests, token/audit differential tests, and 22 sharing tests pass. New CI for `f929e819` must still be observed at the exact head before claiming native acceptance.

Next bounded work: implement the human TTY approval primitive and wire MCP `approve_share` only after safe terminal/timeout tests; then continue remaining agent token mutations and MCP/HTTP/Broker slices. Keep Go production and preserve rollback. Estimated total migration progress remains 50–55% by effort, not an acceptance percentage. All local build/test/cache/temp paths remain on the external NVMe.
