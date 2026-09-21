# Rust migration handover — 2026-09-09

## Zwischenstand 2026-09-21 (nach `a28b6a09`) — P0 gefixt, Squash-Pin behoben

- **Native CI beobachtet.** `0a123084` → Lauf `35539515206` grün;
  Merge `3232e31f` (PR #1089, Squash) → Lauf `35569092279` **rot**.
- **Squash-Merge hat die Pins zerstört** (eigener Fehler): die Fixtures waren auf
  Branch-Commits (`fd55bb73`, `c7309b0f`) eingefroren. Der Squash entfernte diese
  Objekte; danach schlug auf `main` jedes Gate fehl, das den Pin auflöst
  (`Rust storage differential`, `make port-fixtures-check` — „command-tree fixture
  is stale“), weil `git ls-tree <pin>` ins Leere greift. Ursache ist nicht der Fix,
  sondern die Pin-Wahl.
- **Behoben und wieder grün:** PR
  [#1090](https://github.com/danieljustus/symaira-vault/pull/1090), Squash-Merge
  `a28b6a09`. Alle 19 Pin-Stellen zeigen jetzt auf `3232e31f` — die Revision, die
  dauerhaft auf `main` erreichbar ist (`git merge-base --is-ancestor 3232e31f
  origin/main` ✓). Fixtures erneut eingefroren, weiterhin **provenance-only**.
  Kein Oracle-Quellcode in diesem Fix, deshalb bleibt der Pin inhaltlich korrekt.
- **Native CI für den Merge beobachtet:** `a28b6a09` → `CI` Lauf `35571433190`
  **success**, keine Fehler; `Rust storage differential` `35571433195` und
  `Rust pairing differential` `35571433199` success. Lokal auf `main` zusätzlich
  `port-fixtures-check`, `store-metadata-fixtures-check` (8 Vektoren),
  `cxfgen -check` (19 Cases) und `cargo test -p symvault-store -p symvault-mcp`
  (32 Suites ok) grün.
- **Regel für den nächsten Merge:** Ein Fixture-Pin darf nur eine Revision nennen,
  die von der Basis-Branch dauerhaft erreichbar ist, und das Re-Freeze muss **im
  selben PR** landen. Vor jedem Merge `git merge-base --is-ancestor <pin>
  origin/main` prüfen; schlägt das fehl, ist der Pin eine Zeitbombe. In
  `references/porting-pitfalls.md` festgehalten.
- Go bleibt Produktion; kein Cutover, kein Release. Kein Branch-/Tag-Ereignis.
- **Korrektur früherer Fehleinordnungen** (eigene Fehler, ausdrücklich richtiggestellt):
  - `rust-007-fixtures-check` ist **nicht** vorbestehend rot. Er ist auf `c60e3be5`
    (alte Basis) und auf `f034f061` (jetzt) grün — der ursprüngliche „`config/contract.json`
    is stale"-Befund war ein Fehlschluss aus einem `git stash`-Test, der nichts
    zurückgesetzt hat, weil die Arbeit bereits committet war. `rust-007-differential`
    (6 Fälle) ebenfalls grün, `config-profile-fixtures-check` 62 Cases PASS.
  - `auth_commands` (2 Fälle) ist **nicht** vorbestehend rot. Vollständiger Lauf:
    auf `c60e3be5` 3 passed/0 failed, auf `f034f061` 3 passed/0 failed, dreimal
    sequenziell reproduzierbar grün. Der frühere Fehlschlag war eine
    Parallel-Last-Erscheinung, kein Vertragsproblem und kein Baseline-Rot.
- **Bestätigt vorbestehend rot** ist nur `config-cli-differential`:
  auf `c60e3be5` reproduziert mit `os error 20` (Temp-Dir-Kollision in
  `agent_token_mutations_differential`, Mikrosekunden-Takt aus #1085; allein
  ausgeführt grün). Das ist die einzige rote Baseline, die ich behaupten darf.

## Zwischenstand 2026-09-20, Teil 4 (nach `c60e3be5`) — P0 im Oracle, Slice pausiert

**Der nächste geplante Slice (`migrate pseudonymize`) ist als Oracle unbrauchbar:
die Go-Produktion löscht dabei den ganzen Vault.** Gefunden bei der
Voruntersuchung des Slice, gemeldet als
[#1088](https://github.com/danieljustus/symaira-vault/issues/1088), Fix in
[PR #1089](https://github.com/danieljustus/symaira-vault/pull/1089).

Gemessen mit dem gepinnten Oracle-Build (`target/port/symvault-go`), isoliertes
`HOME`, Memory-Keyring, 2 Einträge:

- `migrate pseudonymize -y` meldet „Migrating 2 entries… / Migration complete.“
  und **Exit 0**, danach existiert **keine einzige Eintragsdatei** mehr:
  `find entries -name '*.age'` → 0, `list` leer, `get` → not found,
  `config.yaml` trägt `pseudonymize_paths: true`.
- Ursache: `cmd/admin/migrate.go` ruft `enablePseudonymizeConfig` **nach** der
  Schleife. `WriteEntry` lädt die Config selbst, `entryStoragePath()` liefert den
  HMAC-Pfad nur bei gesetztem Flag — also schreibt jede Iteration auf
  `entries/<plain>.age` zurück und das folgende `os.Remove` löscht sie.

Drei weitere Defekte derselben Stelle beim Fix gefunden und mitbehoben:
Pfadableitung aus dem Dateinamen (zweiter Lauf hasht den HMAC-Namen erneut),
`PrepareEntryForWrite(pseudonymize=false)` (logischer Pfad landet nie im
Ciphertext), und `ReadEntry`/`readEntryInner` ohne Fallback auf
`entries/<plain>.age` (Vault mit Flag und Plaintext-Namen liest sich als leer —
genau der Zustand nach einem fehlerhaften Lauf).

- Fixture-Pins vorgerückt. Der Fix berührt zwei Dateien, die Generatoren als
  gepinnte Oracle-Quelle binden und gegen den Working Tree vergleichen:
  `internal/vault/entry_readwrite.go` (manifestkeygen, storemetagen, 6
  MCP-Generatoren, `cxfgen` über den ganzen `internal/vault`-Closure) und
  `cmd/admin/migrate.go` (`portgen` bindet jede Nicht-Test-Datei unter `cmd/`).
  Betroffene Fixtures neu eingefroren — **alle nur Provenance geändert**, alle
  Vektoren/Cases byte-identisch: `store/metadata.json` (8), 
  `store/manifest-keys.json` (16), `mcp/tools-{delete-entry,generate-totp,
  get-value,list-entries,search-fetch,set-entry}.json`, `import/cxf.json` (19),
  `cli/command-tree.json` (135 Kommandos). Rust-Seite nachgezogen:
  `symvault-store/{src/metadata.rs,tests/manifest_keys.rs}` und die sechs
  `symvault-mcp/tests/tools_*.rs` (inkl. `source_hash`).
  `portgen`/`cxfgen` vergleichen gegen den Pin, konnten also nur eine Revision
  mit sauberem Tree nennen und wurden zusammen mit dem Re-Freeze vorgerückt.
  Geprüft und **unberührt**: `storegen`, `store004gen` (lesen gepinnte Blobs,
  nicht den Working Tree), `configclicasesgen`, `exportgen`, `import1passgen`,
  `importcsvgen`, `mcprendergen`, `sessiongen`, `gitio` (`internal/git`).
- **Vorbestehende, nicht durch diesen Fix verursachte rote Gates** (auf
  pristine `origin/main` bestätigt): `config-cli-differential`
  (Temp-Dir-Kollision in `agent_token_mutations_differential`, der
  Mikrosekunden-Takt aus #1085; allein ausgeführt grün).
  **Korrektur:** `rust-007-fixtures-check` wurde hier ursprünglich mit
  „`config/contract.json` is stale“ als vorbestehend rot geführt. Das war falsch
  und ist oben richtiggestellt: das Gate ist auf der alten wie der neuen Basis grün.
- **Slice-Entscheidung:** `migrate pseudonymize` nicht portieren, solange das
  Oracle den Defekt trägt. Byte-identische stdout/stderr-Fixture hätte die
  Datenlöschung als Vertrag eingefroren. #1089 ist inzwischen gemergt (`3232e31f`)
  — der Slice ist damit **wieder freigegeben**, die Voruntersuchung unten gilt
  weiter, und der Fix selbst muss noch verifiziert werden (die Akzeptanzpunkte
  unten nennen „zweiter Lauf ist ein No-op", was der Fix erst herstellt).
- Go bleibt Produktion; kein Cutover, kein Release.
- **Native CI für `0a123084` inzwischen beobachtet: grün** (Lauf `35539515206`).
  Der Merge-Lauf `35569092279` war rot, weil der Squash die Pins zerstörte; das ist
  oben behoben und mit `a28b6a09` (Lauf `35571433190`, success) belegt.

## Zwischenstand 2026-09-20, Teil 3 (nach `72c14890`)

**Gemessen: die macOS-Testflakes sind eine Uhr-Auflösung, kein Vertragsproblem.**

- `SystemTime::now().as_nanos()` liefert auf macOS Mikrosekunden-Schritte. Messung
  (Wegwerf-Test, 2026-09-20): 30 Samples → 9 verschiedene Werte, **alle** enden auf
  `000`; vier synchron per `Barrier` gestartete Threads bekamen 3 verschiedene
  Werte, zwei denselben. Tests **eines** Binaries benennen ihre Temp-Ordner so und
  landen beim Start im selben Verzeichnis.
- Folge: doppeltes `git init` in einem Ordner → `fatal: cannot copy
  '.../git-core/templates/info/exclude' … File exists`, Exit 128. Das traf am
  2026-09-20 dreimal `Rust native (macos-latest)` (`history_commands.rs:27` und
  `:89`), jeweils ohne Bezug zur geprüften Änderung: Issues #1082, #1085.
- **Behoben:** `crates/symvault-cli/tests/history_commands.rs` nutzt jetzt eine
  `tempfile::TempDir`-Wache plus nicht existierenden Wurzelpfad (PR #1084, Fixes
  #1082). **Offen:** dasselbe Muster in 21 weiteren Dateien unter
  `crates/symvault-cli/tests/` (Liste in #1085) — solange das offen ist, kann der
  macOS-Rust-Job jederzeit ohne Codebezug rot werden; ein Rerun hilft, ist aber
  kein Vertragssignal.
- **Nicht-Vertrag:** `Rust Miri` und `Rust native (macos-latest)` sind die
  langsamsten Jobs (~20 min bzw. ~6 min) und die einzigen, die in dieser Sitzung
  unabhängig von Änderungen rot wurden. Bewertung: natives Gate bleibt Pflicht,
  Flakes werden als Flakes behandelt und nicht als Evidenz.

**Nächster Slice: `symvault migrate pseudonymize`.** Voruntersuchung abgeschlossen,
Implementierung noch nicht begonnen:

- Der Rust-Store kann die Arbeit bereits: `Store::write_entry_at(..., pseudonymize)`,
  `Store::configured_entry_path`, `Store::delete_entry`, `symvault_crypto::pseudonymize_path`,
  Manifest-Pflege — alles vorhanden (`crates/symvault-store/src/lib.rs:1897-2141`).
  Zu portieren ist also die CLI-Schicht, nicht der Kern.
- Go-Oracle: `cmd/admin/migrate.go:46-153`. Vertragspunkte: Abbruch ohne `--yes` gibt
  `Canceled` auf stderr und Exit 0; leerer Vault gibt „No entries to migrate.
  Enabling pseudonymize_paths in config.“ und setzt den Config-Schalter trotzdem;
  sonst „Migrating N entries to pseudonymized paths...“, Fortschritt `\r`-Zeilen auf
  stderr, danach „Migration complete. All entries now use pseudonymized paths.“;
  jede Datei wird gelesen, mit `pseudonymize_paths` neu geschrieben und die
  Plaintext-Datei entfernt; `config.yaml` bekommt `vault.pseudonymize_paths: true`.
- Vorlage für die Rust-Seite: `crates/symvault-cli/src/migrate_kdf_commands.rs`
  (Mutation-Grenze) und die Verdrahtung in `main.rs` (`run_migrate_kdf`, um Zeile 3104).
- **Befund:** `crates/symvault-cli/tests/migrate_kdf_differential.rs` ist
  `#[ignore]` und braucht `SYMVAULT_GO_BINARY`; **kein** Makefile-/Workflow-Ziel setzt
  diese Variable (geprüft). Der Go↔Rust-Vergleich für `migrate kdf` läuft also nur
  manuell und ist kein Gate. Für `migrate pseudonymize` deshalb einen Fixture-Weg
  bauen, der ohne Umgebungsvariable läuft: Generator unter
  `scripts/rust-port/cmd/` (Muster `sessiongen`/`portgen`, Ziel
  `testdata/port/cli/migrate-pseudonymize.json`), Provenance-Digest-Test wie bei
  `sessiongen`, und ein nicht-ignorierter Contract-Test in
  `crates/symvault-cli/tests/`. Oracle-Binary bauen:
  `make port-contract`-Mechanik (`make`-Ziel baut `target/port/symvault-go` aus dem
  Checkout, `PORT_GO_BINARY`), dann den Generator dagegen laufen lassen.
- Akzeptanz für den Slice: (1) Fixture aus dem gepinnten Oracle mit Digest-Bindung,
  (2) Rust-CLI gibt byte-identischen stdout/stderr-Text wie das Fixture, (3) nach dem
  Lauf liegen alle Einträge unter HMAC-Pfaden und kein Plaintext-Name bleibt übrig,
  (4) `config.yaml` trägt `pseudonymize_paths: true`, (5) zweiter Lauf ist ein
  No-op mit der Leer-Vault-Meldung, (6) Abbruch ohne `--yes` lässt Vault und Config
  unverändert, (7) `cargo test -p symvault-cli` und `cargo fmt/clippy` grün.
- Kein Cutover, kein Release: Go bleibt Oracle und Produktion.

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

## Zwischenstand 2026-09-20, Teil 2 (nach `622ec619`)

- `main` war rot (`Test (macos-latest)` und `Test (windows-latest)`). Ursache und
  Fix in PR [#1078](https://github.com/danieljustus/symaira-vault/pull/1078),
  gemergt als `622ec619`: das 2-Minuten-Limit des Adapter-Helfers traf kalte
  Cargo-Builds, und `sessiongen` legte unter Windows einen unzulässigen
  Verzeichnisnamen an. Native Abnahme im Dispatch-Lauf 35507740116 auf dem
  PR-Head (beide Jobs grün). Die `main`-CI auf dem Merge-Commit `622ec619`
  (Lauf 35509590715) bestätigt `Test (windows-latest)` und
  `Test (macos-latest)` als erfolgreich; `Test (ubuntu-latest)` und `Rust Miri`
  liefen zum Zeitpunkt dieser Notiz noch.
- CLI-Oberfläche neu und reproduzierbar gemessen: `scripts/rust-port/cmd/cligap`
  vergleicht die Rust-CLI gegen den gepinnten Oracle-Baum
  (`testdata/port/cli/command-tree.json`, `a518124f`) und braucht dafür kein
  Oracle-Binary; Report in `target/resume-evidence/cli-gap-inventory.json`.
  Ergebnis bei `1d534410`: 134 Oracle-Pfade, 89 Rust-Pfade, **46 fehlen**,
  9 Flag-Lücken, **3 Alias-Lücken** (`get show`, `get cat`, `list ls`) und ein
  Rust-only Pfad (`mcp serve`, eine Re-Pin-Entscheidung).
  `docs/rust-port/cli-gap-inventory.md` ist damit ersetzt; `CLI-002`/`CLI-003`
  zitieren die Messung und bleiben beide `TODO`.
- Zwei delegierte Worker lieferten **keinen verwertbaren Beitrag**. Lane 1 schrieb
  vier CLI-Module mit erfundenen Store-/Session-APIs, ohne Fixture und ohne
  Differential (nicht kompilierbar); Lane 2 ein Werkzeug, das Hilfetexte als
  Kommandopfade zählte (Go-Pfade 1, Rust-Pfade 44136). Beides lag ungepusht als
  WIP auf den damaligen Worker-Branches (`subagent-sa-0-cebb4232` und
  `-sa-1-52b3faea`) und gilt ausdrücklich nicht als Fortschritt. Diese Branches
  wurden am 2026-09-20 entfernt; die Inhalte liegen als `git bundle` unter
  `…/recovery/symaira-vault-cleanup-20260920/` (Commits `a6f58fc6`, `df87dadf`).
  Lehre: Worker-Artefakte am Branch prüfen, nicht am Abschlussbericht.
- Kein Cutover, kein Release; Go bleibt Produktion.

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
