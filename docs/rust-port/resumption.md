# Rust migration handover — 2026-09-09

## Zwischenstand 2026-09-22, Teil 15 — Slice `import review` gemergt (30 → 28)

- **Basis:** `main` @ `a226a6f7`, Checkout sauber, kein fremder WIP, keine
  Rest-Worktrees. Toolchain: Go 1.27.1, Rust/Cargo 1.98.0.
- **cligap frisch auf `a226a6f7`** (`cargo build -p symvault-cli` + `go run
  ./scripts/rust-port/cmd/cligap`, Binary sha256 `67a4a00077d4`): Oracle-Pfade
  134, Rust-Pfade 99, **fehlend 30**, Flag-Lücken 9, Alias 0, Rust-only 1 —
  deckungsgleich mit Teil 14.
- **Slice gewählt: `import review list` + `import review promote` (30 → 28).**
  Begründung: rein offline (`cli.WithVault` + `ListEntries/GetEntry/WriteEntry/
  DeleteEntry`, alles bereits portiert), deterministisch (sortierte Import-IDs),
  volle Byte-Prüfbarkeit inkl. Vault-Seiteneffekte. Go-Referenz
  `cmd/admin/import.go` ~370–478.
- **Blocked-Rows (bewusst, mit Wand):** `approval` + `approval list/decide`
  (3 Pfade, loopback-HTTP gegen laufenden Server, kein HTTP-Client im
  Workspace — dieselbe Wand wie `update check/apply`); `dynamic`/`dynamic
  generate` (2, braucht PostgreSQL/AWS-Backends); `agent setup`
  (Netzwerk-Downloads); `device approval-pair` (Server-Roundtrip);
  `update check`/`update apply` (kein HTTP-Client, cosign). Offline-Teil
  `update info` + `update`-Hilfetext bleibt freier Kandidat für den Folge-Slice.
  `CLI-005` (doppelte `Error:`-Zeilen, Exit-Dialekt) weiter offen, absichtlich
  nicht mitgefixt.
- **Dispatch:** Worktree
  `/Volumes/1TB_NVMe_SN850X/Dev/Symaira_Dev/Repos/symaira-vault-wt-import-review`,
  Branch `feat/import-review` @ `a226a6f7`, ein Worker
  (`CLI-IMPORT-REVIEW-001`), Fixed-Field-Set aus `references/worker-dispatch.md`,
  required skills `go-rust-port-parity`, `code-editing`. Koordinator alleiniger
  Schreiber von Ledger, gemeinsamen Manifests und CI.
- **Geladene Skills dieser Sitzung (nicht erneut laden):** `go-to-rust-migration`
  (SKILL.md + `references/worker-dispatch.md`), `guard-repo`,
  `go-rust-port-parity` + `references/workflow.md`, `autonomous-coding-agents`,
  `parallel-repo-agents`, `code-editing`. `contract-matrix.md`,
  `differential-testing.md`, `rust-stack.md`, `references/porting-pitfalls.md`
  noch **nicht** geladen — nur bei Bedarf nachladen.
- Kein Cutover, kein Release; Go bleibt Produktion und Oracle.

## Zwischenstand 2026-09-21, Teil 14 (nach `f80ef938`) — `agent upgrade` gemergt (#1104), 31 → 30

- **PR [#1104](https://github.com/danieljustus/symaira-vault/pull/1104) squash-gemergt
  als `f80ef938`**: `agent upgrade <name> --tier <tier>` byte-identisch zur
  gepinnten Oracle (Exits/stdout/stderr plus Datei-Baeume nach
  Label-verankerter Random-Normalisierung). Alle Checks gruen
  (`Rust`, `Rust Miri`, `Rust native` macOS+Windows, `Rust port contract`,
  `Pairing differential`, `Test (ubuntu) — PR`, `govulncheck`, `osv-scanner`,
  `Vaultcore (macOS)`, `Process tree (Windows)`). Worktree/Branch danach
  entfernt, `main`-Checkout sauber.
- **cligap auf `main` (frisch gebaut):** Oracle-Pfade 134, Rust-Pfade 98 → 99,
  **fehlend 31 → 30**, Flag-Luecken 9, Alias 0, Rust-only 1.
- **Portiert (`agent_upgrade_commands.rs`, neu):** Tier-Validierung
  (`safe`-Alias, `--tier`-Pflicht), explizite Tier-Diff-Tabelle auf stderr,
  Biometrie-Gate (`--yes` braucht `--reason`; ohne `--no-biometric` nimmt der
  Port Go's Unavailable-Branch), interaktiver Confirm (piped stdin bricht ab,
  Exit 0), Profil-Save mit Tier, optional `--rotate-token` (Revoke-all +
  Create + Token-Datei), Skill-Refresh mit dem neuen Tier.
  Contract-Test `cli_agent_upgrade.rs` (11 Tests, TempDir, Throwaway
  HOME/USERPROFILE, restricted PATH).
- **Scope-Entscheidungen (sichtbar):** `apply_tier_preset_to_profile` in
  symvault-core jetzt `pub` (Upgrade legt das Preset ueber das geladene
  Profil, wie der Install-Writer); `map_scoped_token_error` /
  `write_agent_token_file` / `PINNED_TOOL_REGISTRY_HASH` sind `pub(crate)`;
  neuer Library-Einstieg `refresh_target_with_tier` (explizites Target, kein
  Lookup).
- **Drive-by-Parity-Fix in der Skill-Library:** Refresh-Fehlertexte sind auf
  Library-Ebene jetzt nackt (das `skill refresh`-Kommando setzt das
  `refresh skill: `-Praefix nur um `agentskill.Refresh`, Empty-Target-Fehler
  bleibt praefixlos) — entspricht Go `cmd/mcp/agent_skill.go`. Bestehende
  Skill-Tests weiter gruen.
- **Differential-Befunde (alle verifiziert):** 13/14 Faelle byte-identisch.
  (1) Auf einem TouchID-Mac zeigt Go einen echten TouchID-Prompt und folgt
  ihm — der Port nimmt den Unavailable-Branch (Warnung + Confirm bzw. Fehler
  mit `--yes`); auf Linux/Windows/allen CI-Runnern identisch, Contract-Tests
  nutzen ueberall `--no-biometric`. Kein Repo-Test deckt den Pfad ab (auf
  TouchID-Macs nicht deterministisch). (2) Go `TierPresets` kennt kein
  `"safe"` — der Loader wendet bei handgeschriebenem `tier: safe` kein Preset
  an (altes `canWrite: true`); `get_preset("safe") → None` repliziert den
  Miss. (3) Registry-Keys sind zufaellige ID-Suffixe (Sortierung variiert pro
  Lauf) — Normalisierung label-verankert statt positionsbasiert; Token-`prefix`
  und Tool-Registry-Hash flach normalisiert. (4) `vault/.lock`-Leftover ist
  Pre-existing (alle Store-Writes, flock-Stil; Go kennt keine Lock-Dateien) —
  separat als Issue [#1105](https://github.com/danieljustus/symaira-vault/issues/1105)
  angelegt, Differential ignoriert die Datei.
- **Gates auf dem Branch:** `cargo fmt --check`, `cargo clippy --workspace
  --all-targets --all-features --locked -- -D warnings` (0 Fehler),
  `cargo nextest run --workspace --all-features --locked` (**816 passed**,
  4 skipped — 805 + 11 neue), Doc-Tests.
- **Naechster Slice:** naechster Oracle-Pfad aus `cligap`-missing angreifen;
  `agent setup` (Netzwerk-Downloads), `update check/apply` (kein HTTP-Client,
  cosign) und `device approval-pair` (Server-Roundtrip) bleiben blockiert.
  CLI-005 (doppelte `Error:`-Zeilen) weiter offen, absichtlich nicht mitgefixt.

## Zwischenstand 2026-09-21, Teil 13 (nach `489a3a85`) — `agent install` gemergt (#1103), 32 → 31

- **PR [#1103](https://github.com/danieljustus/symaira-vault/pull/1103) squash-gemergt
  als `489a3a85`**: `agent install` byte-identisch zur gepinnten Oracle
  (Exits/stdout/stderr, Vault-`config.yaml` stdio+http, Agent-Dateien
  YAML/JSON/TOML nach Random-Normalisierung, alle Fehler inkl.
  CLI-005-Dopplung). Contract-Test `cli_agent_install.rs` (13 Tests) gegen 12
  gefrorene Oracle-Fixtures.
- **cligap auf `main` (frisch gebaut):** Oracle-Pfade 134, Rust-Pfade 97 → 98,
  **fehlend 32 → 31**, Flag-Luecken 9, Alias 0, Rust-only 1.
- **Windows-CI-Lehren (3 Fix-Runden, alle testseitig — der Port ist Go-treu):**
  (1) `run()` setzt zusaetzlich `USERPROFILE` aufs Throwaway-Home — Go
  `os.UserHomeDir` (vom Port-`expand_tilde` gespiegelt) ignoriert `HOME` auf
  Windows, sonst entkommt der Default-`~/.hermes/...`-Skill-Pfad ins echte
  Runner-Profil. (2) `normalize()` faltet `\` → `/` (kein Fixture enthaelt
  Backslash). (3) JSON escapt `\` als `\\` — escaped-Root zuerst ersetzen,
  danach alle `//`-Runs kollabieren außer `://` (URL-sicher).
  Verlauf: 4/13 → 11/13 → 12/13 → 13/13, danach 22/22 Checks gruen.
- **Scope-Entscheidungen (sichtbar in PR/Teil 12):** `getrandom` in
  CLI-`Cargo.toml`, `PINNED_TOOL_REGISTRY_HASH`-Konstante,
  `open_nofollow_kind`-Fix (macOS `/var`), Writer `autoUnseal`-zuerst.
- **Naechster Slice:** naechster Oracle-Pfad aus `cligap`-missing angreifen;
  `agent setup` (Netzwerk-Downloads), `update check/apply` (kein HTTP-Client,
  cosign) und `device approval-pair` (Server-Roundtrip) bleiben blockiert.
  CLI-005 (doppelte `Error:`-Zeilen) weiter offen, absichtlich nicht mitgefixt.

## Zwischenstand 2026-09-21, Teil 12 — `agent install` gebaut (32 → 31), PR offen

- **Gebaut in `feat/agent-install`** (Worktree
  `symaira-vault-wt-agent-install`): `crates/symvault-cli/src/agent_install_commands.rs`
  portiert `cmd/mcp/agent_install.go`, `cmd/mcp/mcp_install.go`
  (`buildServerConfig`, `stdioArgs`, `ResolveHTTPPort`) und
  `internal/mcp/install/*` (Detect-Tabelle, YAML/JSON/TOML-Injektoren,
  `BackupConfig`, `Install`), inklusive Token-Erzeugung im Registry-Store
  (`agent-install-*`-Display-Token plus zweites gescopetes `mcp-install-*`-Token
  fuer HTTP-Bearer), `health_check` per TCP+`GET /health`, Auto-Detect
  (`install_single → (InstallResult, Result<(), String>)` wie Go) und
  Skill-Install via `install_with_tier`/`profile_tier`-Template-Var. Kein
  `toml`-Crate: der TOML-Header/Array-Injektor ist handgerollt (quote-aware
  Klammertiefe). Dazu `AgentCommand::Install` plus Dispatch in `main.rs`.
- **Scope-Entscheidungen (sichtbar):** `getrandom = "=0.3.3"` neu in
  `crates/symvault-cli/Cargo.toml` (32-Byte-Secret-Paritaet);
  `PINNED_TOOL_REGISTRY_HASH` als Konstante (Go berechnet sha256 ueber die
  kompilierten MCP-Tools in `server.init()`, der Port hat kein Aequivalent —
  Upgrade-Pfad im Kommentar); `symvault-store/src/lib.rs`: `open_nofollow_kind`
  oeffnet nur noch die finale Komponente mit `NOFOLLOW` (macOS `/var` →
  `/private/var` scheiterte sonst mit ENOTDIR — echter Port-Bug, Go nutzt
  plain `os.Open`); `config.rs`-Writer: `autoUnseal` vor `requireApproval`.
- **cligap gemessen:** Oracle-Pfade 134, Rust-Pfade 97 → 98, **fehlend 32 → 31**,
  Flag-Luecken 9, Alias 0, Rust-only 1.
- **Differential-Befunde (alle verifiziert, keine offenen Diffs):** Vault-
  `config.yaml` stdio+http byte-gleich; Agent-Dateien (YAML/JSON/TOML) byte-
  gleich nach Random-Normalisierung; alle Exits stdout/stderr gleich.
  Geklaert und dokumentiert: (1) Oracle schreibt das **volle** 64-Hex-Bearer
  in die Agent-YAML (vermeintliches `first6...last4` war ein
  Terminal-Display-Artefakt — Lehre in `porting-pitfalls.md`); (2)
  `vaultDir` im gespeicherten Config ist der Resolver-Default bzw. `vDir` bei
  frischer Config, nie `--vault`-Flag-Magie; (3) Multi-Agent-Auto-Detect-
  Reihenfolge ist in Go map-zufaellig — der Port geht deterministisch in
  Definitionsreihenfolge (Single-Agent-Faelle byte-identisch); (4) Backup wird
  auch fuer leere Seeds geschrieben (0-Byte-`.backup` plus `Backup:`-Zeile);
  (5) builtin Default-Profile zaehlen als "already exists" ohne `--force`.
- **Repo-Test:** `crates/symvault-cli/tests/cli_agent_install.rs` (13 Tests,
  nicht ignoriert, ohne Umgebungsvariablen, `tempfile::TempDir`, restricted
  `PATH=/usr/bin:/bin` wie die Captures), 12 Fixtures unter
  `crates/symvault-cli/tests/fixtures/agent-install/` (Oracle-Bytes, frisch
  re-captured: `codex` braucht Empty-Seed statt `{}`).
- **Gates gruen:** `cargo fmt --all --check`, `cargo clippy --workspace
  --all-targets --all-features --locked -- -D warnings`,
  `cargo nextest run --workspace --all-features --locked` (805 passed,
  4 skipped), Doc-Tests. Session-Env-Lehre: `SYMVAULT_VAULT`-Leak im
  Terminal bricht `config_session_contract` — vor Gates `unset`ten.
- **Naechster Schritt:** committen, PR stellen, CI gruen abwarten, squash-mergen,
  Ledger-Teil-13 mit Merge-SHA.

## Zwischenstand 2026-09-21, Teil 11 (nach `e6e0dc0d`) — `agent skill*` gemergt, naechster Slice `agent install`

- **PR [#1102](https://github.com/danieljustus/symaira-vault/pull/1102) squash-gemergt
  als `e6e0dc0d`.** Alle Checks gruen im Lauf `35629952769` (`Rust`, `Rust Miri`,
  `Rust native` macOS+Windows, `Rust port contract`, `Pairing differential` und
  `Audit differential` auf drei Plattformen, `Test (ubuntu) — PR`, `govulncheck`,
  `osv-scanner`, `Process tree (Windows)`, `Flake vendorHash`, `Vaultcore (macOS)`).
  Worktree und Branch danach entfernt, `main`-Checkout sauber.
- **Stand der Luecken:** fehlende Oracle-Pfade **35 → 32**, Rust-Pfade 94 → 97,
  Flag-Luecken 9, Alias-Luecken 0, Rust-only 1 (Oracle 134).
- **Zwei CI-Funde wurden vor dem Merge behoben, beide echte Bugs im neuen Test,
  nicht Flakes:**
  1. `Rust native (windows-latest)` rot: die ueber `include_str!` gelesenen
     Fixtures waren im CRLF-Checkout konvertiert, der Renderer liefert LF.
     Fix: `.gitattributes` pinnt `crates/symvault-cli/tests/fixtures/**` auf
     `text eol=lf` **und** beide Loader normalisieren CRLF (`16919297`).
  2. `Rust native (macos-latest)` rot: der Byte-Vergleich nach einem *legitimen*
     Rewrite war zeitabhaengig, weil der Rewrite einen frischen
     `managed_installed_at`-Stempel setzt (`16:58:40` vs `16:58:41`). Fix: volle
     Byte-Gleichheit nur dort, wo **kein** Schreiben erwartet wird; sonst
     Vergleich ohne die Zeitstempel-Zeile (`b856b7dd`).
  Beide Lehren stehen jetzt in
  `symskills/library/go-to-rust-migration/references/porting-pitfalls.md`.
- **Naechster Slice spezifiziert:** `docs/rust-port/next-slice-agent-install.md`
  (`agent install`, optional `agent upgrade`; Ziel 32 → 31). Offline, setzt auf
  dem in Teil 10 gebauten Skill-Writer und dem portierten Token-Store auf;
  `agent setup` bleibt wegen Netzwerk-Downloads ausgeschlossen.
- **Verbleibende Blocker unveraendert:** `update check`/`apply` (kein HTTP-Client
  im Workspace), `device approval-pair` (kontaktiert den laufenden Server),
  `CLI-005` (Oracle druckt jeden Fehler doppelt — reproduziert, nicht behoben).

## Zwischenstand 2026-09-21, Teil 10 (nach `6649caf0`) — `agent skill*` gebaut

- **Gebaut in `feat/agent-skill-commands`** (Worktree
  `symaira-vault-wt-agent-skill`): `crates/symvault-cli/src/agent_skill_commands.rs`
  portiert `cmd/mcp/agent_skill.go` und `internal/agentskill`
  (`skill.go`, `install.go`, `manifest.go`), inklusive einer kleinen
  `text/template`-Teilmenge (`define`/`template "…" .`/`if eq`/`{{.Field}}`,
  Trim-Marker `{{-` und `-}}`), des Frontmatter-Schreibers, des `tar.gz`-Exports
  und von `refresh` (Sentinel-Pruefung, Body-Digest, `.bak`-Backup, 0750/0600,
  Traversal-Ablehnung). Dazu die sechs Template-Assets als byte-identische
  Kopien unter `crates/symvault-cli/assets/agent-skill/**`, eine `mod`-Zeile,
  `AgentCommand::Skill`/`AgentSkillCommand` und ein Dispatch-Arm in `main.rs`
  sowie `flate2`/`tar` in `crates/symvault-cli/Cargo.toml`.
- **Additiv wiederverwendet:** `agent_token_commands::display_rfc3339` ist jetzt
  `pub(crate)` und formatiert `InstalledAt` (Go nutzt dort `time.RFC3339`,
  Sekundenauflösung — der erste Versuch mit `to_rfc3339_nano` erzeugte 6–10
  Byte zu viel pro Skill-Datei und wurde im Differential gefunden).
- **cligap gemessen:** fehlende Oracle-Pfade **35 → 32**, Rust-Pfade 94 → 97,
  Alias-Luecken 0, Flag-Luecken 9, Rust-only 1 (Oracle 134).
- **Byte-Differential gegen die gepinnte Oracle: 18/19 Faelle identisch**
  in Exit-Code, stdout, stderr, Archiv-Inhalt (Mitglieder, Modi, mtime, uid,
  Nutzdaten) sowie den Bytes der geschriebenen und gesicherten Skill-Datei:
  alle fuenf Agenten, unbekannter Agent, 0/2 Argumente, `-o/--output`,
  Default-Dateiname, `--quiet`, `refresh` fuer fehlende/identische/geaenderte/
  unverwaltete/Traversal-Ziele und fehlende Config.
- **Bewusst normalisiert und benannt, nicht stillgelegt:** (1) `managed_version`,
  `managed_installed_at` und der Versionsstring in `INSTALL.md` sind build- bzw.
  zeitabhaengig (Sekundengenauigkeit und Quoting werden stattdessen im
  Repo-Test geprueft, und `managed_version` wird gegen die Version derselben
  Binary gehalten); (2) `managed_hash` deckt einen Body ab, der den Vault-Pfad
  enthaelt; (3) die Tar-Reihenfolge ist sortiert, weil die Oracle eine Go-Map
  iteriert; (4) die gzip-Stream-Bytes unterscheiden sich zwischen Go und Rust
  (Deflate-Implementierungen) — verglichen werden die extrahierten Inhalte.
- **Einzige verbleibende Abweichung:** `agent skill` ohne Subcommand druckt in
  der Oracle Cobras Hilfe und exitet 0; die Cobra-Hilfe ist ein dokumentiertes
  Nicht-Ziel dieses Ports (wie `symvault help`), also wird nur der Exit-Status
  angeglichen.
- **Repo-Test:** `crates/symvault-cli/tests/cli_agent_skill.rs` (12 Tests, nicht
  ignoriert, ohne Umgebungsvariablen, `tempfile::TempDir` statt Zeitstempel —
  Issue-#1085-Typ), Fixtures sind die Oracle-Ausgaben selbst unter
  `crates/symvault-cli/tests/fixtures/agent-skill/`. Negativprobe: falscher
  Output-Name fuer `codex` → Contract-Test rot, restauriert gruen.
- **Gates gruen:** `cargo fmt --all --check`, `cargo clippy -p symvault-cli
  --all-targets -- -D warnings`, `cargo test -p symvault-cli` (46 Suiten),
  `cargo test -p symvault-sync`.
- **Delegation-Wand:** der Worker `sa-0-eba56320` (`CLI-AGENT-SKILL-001`) lieferte
  wegen HTTP 429 (Codex-Abo-Limit, Reset in ~27 h) nichts; der Slice wurde wie
  schon beim Alias-/device-Slice vom Koordinator selbst gebaut.

## Zwischenstand 2026-09-21, Teil 9 (nach `6649caf0`) — `device approval-*` gemergt, naechster Slice gewaehlt

- **PR [#1101](https://github.com/danieljustus/symaira-vault/pull/1101) squash-gemergt
  als `6649caf0`.** Alle Checks gruen (`Rust`, `Rust Miri`, `Rust native` macOS+Windows,
  `Rust port contract`, `Pairing differential` auf drei Plattformen, `Test (ubuntu) — PR`,
  `Lint`, `govulncheck`, `osv-scanner`, `Flake vendorHash`). Worktree und Branch danach
  entfernt; `git status` im Haupt-Checkout sauber.
- **Stand der Luecken (cligap am integrierten `main`, Binary sha256 `8e21342d1835`):**
  Oracle-Pfade 134, Rust-Pfade 94, **fehlend 35**, Flag-Luecken 9, Alias-Luecken 0,
  Rust-only 1. Von 43 → 37 → 35 in zwei Slices.
- **Die 35 verbleibenden Pfade, gruppiert (aus `target/resume-evidence/cli-gap-inventory.json`):**
  `serve` 8 (inkl. `install`, `status`, `token create|list|revoke`, `uninstall`),
  `agent` 7 (`install`, `setup`, `skill`, `skill export`, `skill refresh`, `upgrade`),
  `update` 4 (`info`, `check`, `apply`, Root), `approval` 3 (`decide`, `list`, Root),
  `intake` 3 (`watch`, `watch disable`, Root), `broker`, `dynamic`, `dynamic generate`,
  `setup`, `startup-profile`, `ui`, `help`, `generate manpages`, `device approval-pair`,
  `import review list`, `import review promote`.
  Flag-Luecken: `import --quarantine`; `mcp --bind/--port/--tls-ca/--tls-cert/--tls-key`;
  `run --broker/--broker-passthrough/--broker-strict`.
- **Naechster Slice: `agent skill`, `agent skill export`, `agent skill refresh`** (35 → 32).
  Begruendung aus Evidenz: rein offline und deterministisch (Rendering eingebetteter
  Go-Templates + Hash-Vergleich, kein Netz, kein Daemon, keine Plattform), mit
  `internal/agentskill/skill_test.go` (993 Zeilen) als reicher Oracle-Fixture-Quelle.
  Die Abhaengigkeiten sind bereits im Workspace: `tar` und `flate2` liegen in `Cargo.lock`
  und werden von `crates/symvault-sync/src/archive.rs` benutzt; ein Template-Renderer
  existiert als `crates/symvault-sync/src/template.rs`. `expand_tilde` und
  Skill-Pfadauflösung sind in `crates/symvault-cli/src/agent_uninstall_commands.rs` schon
  portiert und sollen wiederverwendet werden.
  **Bewusste Grenze:** Go's `compress/gzip`-Strom ist nicht byte-vergleichbar; export
  vergleicht deshalb den **Archivinhalt** (Eintragsnamen, Modi, Nutzlast-Bytes) und nicht
  die gzip-Bytes — das wird im Test und im PR benannt, nicht verschwiegen.
  **Nicht in diesem Slice:** `agent install`, `agent setup`, `agent upgrade` (schreiben in
  `~/.symaira/bin` und mutieren damit die Maschine) und `serve`/`approval`/`broker`/`intake`
  (Dienste, TLS, Netz).

||||||| parent of 8c25ef94 (feat(cli): port `agent skill`, `agent skill export` and `agent skill refresh`)
## Zwischenstand 2026-09-21, Teil 8 (nach `09961118`) — `device approval-*` gebaut

- **Gebaut in `feat/device-approval-registry`** (Worktree
  `symaira-vault-wt-device-approval`): `crates/symvault-cli/src/device_approval.rs`
  portiert `internal/pairing/devicesession.go` (Register) und
  `cmd/device_approval.go` (`approval-list`, `approval-revoke`), plus zwei Zeilen
  Verdrahtung in `main.rs` und ein additives
  `GoTime::from_offset_datetime` in `crates/symvault-sync/src/pairing.rs`.
- **cligap gemessen:** fehlende Oracle-Pfade **37 → 35**, Rust-Pfade 92 → 94,
  Alias-Luecken 0, Rust-only 1.
- **Byte-Differential:** 12/12 Faelle identisch in Exit-Code, stdout, stderr **und**
  den Bytes der geschriebenen `device-sessions.json` (leerer Store, aktiv/revoked/expired,
  `--quiet`, `-y`, `--yes`, Abbruch `n`, `  Y  `, unbekannte ID, zwei/keine Argumente).
  Zwei Abweichungen sind dabei ausdruecklich normalisiert und benannt, nicht stillgelegt.
- **`CLI-005` erneut belegt und bewusst nicht behoben:** der Oracle-Root-Handler druckt
  jeden zurueckgegebenen Fehler **zweimal** (`Error: …` in zwei Zeilen) und formuliert
  „vault not initialized" anders; reproduziert auch bei `device revoke -y nope`, also
  querschnittlich und vorbestehend. Der Port druckt einmal. Die Fehlertexte selbst stimmen
  (`approval device "x" not found`, `accepts 1 arg(s), received N`, Exit 1).
- **Go-Map-Reihenfolge** der Liste ist kein Vertrag: der Contract-Test vergleicht Zeilen
  als Menge, die deterministische `BTreeMap`-Ordnung des Ports ist eine dokumentierte
  Abweichung.
- **Gates lokal:** `cargo fmt --all --check` 0, `cargo clippy -p symvault-cli --all-targets
  -- -D warnings` 0, `cargo test -p symvault-cli` exit 0 (45 Suiten), `cargo test -p
  symvault-sync` exit 0. Neuer Contract-Test `tests/cli_device_approval.rs` (8 Tests,
  `tempfile`-Wurzeln wegen #1085) plus 8 Unittests im Modul; Negativprobe (Meldung
  absichtlich gebrochen → 1 Test rot, restauriert → gruen).
- **Weiter offen:** `approval-pair` ruft den laufenden Server
  (`https://127.0.0.1:<port>`, Enroll-Secret) und rendert einen QR-Code — eigener
  Dependency-/Plattform-Entscheid. `Enroll`/`Validate`/`CleanupExpired` des Registers
  gehoeren auf den Server-Pfad (`internal/approval/enroll.go`, `internal/approval`), nicht
  zur CLI; `enroll` ist portiert und als ungenutzt markiert.

## Zwischenstand 2026-09-21, Teil 7 (nach `09961118`) — Alias-/Stub-Slice ist gemergt

- **PR [#1100](https://github.com/danieljustus/symaira-vault/pull/1100) squash-gemergt
  als `09961118`.** Alle Checks gruen, darunter `Rust`, `Rust Miri`,
  `Rust native (macos-latest)`, `Rust native (windows-latest)`,
  `Rust port contract`, `Pairing differential` auf allen drei Plattformen,
  `Test (ubuntu) — PR`, `Lint`, `govulncheck`, `osv-scanner`, `Flake vendorHash`.
  Lokal zusaetzlich `cargo test -p symvault-cli` (44 Suiten, exit 0), clippy und
  `cargo fmt --all --check`.
- **cligap gemessen vor/nach dem Slice:** fehlende Oracle-Pfade **43 → 37**,
  Alias-Luecken **3 → 0**, Rust-only unveraendert 1 (`mcp serve`).
- **Byte-Beleg:** 14/14 Stub-Aufrufe identisch in Exit-Code, stdout und stderr, mit
  isolierten HOME/XDG-Wurzeln; zusaetzlich Negativprobe (eine Meldung absichtlich
  gebrochen → 2 Tests rot, restauriert → gruen).
- **Flake-Beitrag vermieden:** der neue Test nutzt `tempfile::TempDir` statt
  `as_nanos()`-Namen. `vault_commands.rs` (von diesem Diff nicht beruehrt) blieb
  beim ersten Kaltstart einmal an der #1085-Kollision haengen und lief danach
  dreimal isoliert gruen — vorbestehend, keine Regression.
- **Worker-Lehre, erneut bestaetigt:** der delegierte Worker `sa-0-8a9ab152`
  (`deleg_1d28d938`) lieferte nichts. Hermes legte einen *eigenen* Worktree
  `.worktrees/subagent-sa-0-8a9ab152` an, der Bericht kam leer zurueck
  (`files_changed: []`, `branch: "main"`, `commit: 55f7023a` = Ledger-Commit),
  der Worktree war danach entfernt. Konsequenz fuer die naechste Karte: der
  absoluten Ziel-Worktree-Pfad gehoert explizit in den Prompt, und der Worker muss
  committen, sobald der erste Test gruen ist.
- **Naechster Slice, vermessen und spezifiziert:** `device approval-list` +
  `approval-revoke`, Vertrag und Acceptance in
  [`next-slice-device-approval.md`](next-slice-device-approval.md).
  `approval-pair` bleibt bewusst draussen (QR-Rendering, LAN-IPs).

## Zwischenstand 2026-09-21, Teil 6 (nach `55f7023a`) — Alias-/Stub-Slice gebaut (PR #1100)

- **Gebaut in `feat/cli-aliases-deprecated-stubs`** (Worktree
  `symaira-vault-wt-cli-aliases`, Commit `1664712f`, PR
  [#1100](https://github.com/danieljustus/symaira-vault/pull/1100)):
  (1) die drei Cobra-Aliase aus der Oracle-Baumdatei — `get` → `show`, `cat`;
  `list` → `ls` —, (2) sechs versteckte deprecated v4.0-Befehle byte-genau:
  `mcp token`, `mcp token create|list|revoke`, `mcp-config`,
  `mcp-token-rotate` (stdout leer, Exit 2, vier stderr-Zeilen).
- **Gemessen, nicht angenommen, zwei Oracle-Eigenheiten:**
  - `mcp token <unbekannt>` druckt die **Gruppen**-Meldung: Cobra hat keine
    `Args`-Schranke und fällt auf den Parent-`RunE` zurück. Deshalb ist das
    Rust-`Token` ein Catch-all mit Wort-Dispatch statt clap-Subkommandos.
  - `--quiet` unterdrückt **keine** der vier Zeilen (gleicher stderr mit und
    ohne `--quiet`).
- **Belege:** Differential gegen das gepinnte Oracle-Binary mit isolierten
  HOME/XDG-Wurzeln — **14/14** Aufrufe byte-identisch in Exit-Code, stdout und
  stderr (inkl. `--quiet`- und Argument-Varianten). `cligap`: fehlende
  Oracle-Pfade **43 → 37**, Alias-Lücken **3 → 0**, Rust-only 1 unverändert.
  Neuer, nicht ignorierter Contract-Test
  `crates/symvault-cli/tests/cli_alias_deprecated_stubs.rs` (4 Tests);
  Negativprobe: verfälschte Meldung → 2 Tests rot, restauriert grün.
  `cargo fmt --all --check` und `cargo clippy -p symvault-cli --all-targets`
  grün.
- **Bewusst nicht im Slice:** der vorbestehende Exit-Code-Dialekt bei „vault not
  initialized“ (Oracle Exit 3 + dreizeilige stderr, Rust Exit 1 + eine Zeile),
  identisch für Aliase **und** kanonische Befehle, bleibt `CLI-005` (`TODO`);
  `symvault help` bleibt dokumentierte Nicht-Zusage.
- **Worker-Ausfall, als Lehre notiert:** `deleg_1d28d938` (`sa-0-8a9ab152`)
  lieferte **nichts**. Hermes legte dem Worker einen *eigenen* Worktree
  `.worktrees/subagent-sa-0-8a9ab152` an; der Worker editierte dort, verlor die
  Orientierung (Ende in `/Users/daniel`), meldete `files_changed: []`,
  `branch: "main"` und `commit: 55f7023a` (mein Ledger-Commit) und der Worktree
  wurde beim Beenden entfernt — die Arbeit war weg, nichts war committet.
  Konsequenz: Wer in einem **vorgegebenen** Worktree dispatcht, muss dem Kind
  ausdrücklich sagen, dass es nicht in einen eigenen Worktree wechseln darf,
  und den ersten Commit verlangen, sobald ein Test grün ist (bestehende Regel,
  hier nicht eingehalten). Der Slice wurde danach vom Koordinator selbst im
  isolierten Worktree gebaut.
- **`main`-CI:** Rerun von Lauf `35610080000` (attempt 2) **success** → der
  Windows-Fehlschlag aus attempt 1 ist als Flake bestätigt
  ([#1099](https://github.com/danieljustus/symaira-vault/issues/1099),
  Kommentar am Issue).
- Kein Cutover, kein Release; Go bleibt Produktion und Oracle.

## Zwischenstand 2026-09-21, Teil 5 (nach `e30789d0`) — `migrate`-Slice integriert, Alias-/Stub-Slice ausgelagert

- **`migrate v4`/`migrate session` sind auf `main`.** PR #1098
  (`bdcdc782`) squash-gemergt als `e30789d0`; der PR war vorher vollständig
  grün (CI-Lauf `35608327679` success, `Rust pairing differential`
  `35608327529` success, alle 18 relevanten Jobs pass, `mergeStateStatus`
  CLEAN). Der Diff berührte **keine** Fixture und keinen Pin (nur
  `crates/symvault-cli/src/main.rs`, `crates/symvault-core/src/session.rs`,
  `crates/symvault-cli/tests/migrate_v4_differential.rs`, `resumption.md`) —
  es gab also nichts neu einzufrieren, und die Pin-Falle aus Teil „2026-09-21
  (nach `a28b6a09`)“ war hier nicht im Spiel. Native CI auf dem Merge-Commit:
  Lauf `35610080000` (`CI`) gestartet, `Rust pairing differential`
  `35610079785` success.
- **CLI-Lücke neu gemessen bei `e30789d0`** (`cargo build -p symvault-cli` +
  `go run ./scripts/rust-port/cmd/cligap`, Binary sha256 `18bfa533cd91`):
  **43 fehlende** Oracle-Pfade (134 Oracle, 92 Rust), 9 Flag-Lücken,
  **3 Alias-Lücken**, 1 Rust-only Pfad (`mcp serve`). Deckungsgleich mit Teil 4.
  Die 43 verteilen sich auf `agent` (6), `serve` (8), `mcp token*`/`mcp-config`/
  `mcp-token-rotate` (6), `update` (4), `approval` (3), `device approval-*` (3),
  `intake` (3), `import review` (2), `dynamic` (2), `broker`, `generate manpages`,
  `help`, `setup`, `startup-profile`, `ui` (je 1).
- **CLI-005-Beleg (neu, ohne Statuswechsel der Zeile).** Der gepinnte Oracle
  und die Rust-CLI unterscheiden sich in Exit-Code und stderr-Dialekt, wenn der
  Vault fehlt: Oracle `symvault list` → Exit **3**, stderr dreizeilig
  (`Error: …` doppelt plus `Run 'symvault init' for a quick start, or 'symvault
  setup' for the guided wizard.`); Rust → Exit **1**, eine `Error:`-Zeile.
  Bei den (noch) fehlenden Subkommandos trifft clap-Robustheit auf Cobra:
  `mcp token` → Oracle Exit **2** mit Deprecation-Warnung und `Try:`-Hinweis,
  Rust Exit **1** mit `unrecognized subcommand`. Beides bleibt unter `CLI-005`
  (`TODO`, „exit codes 0–10“); hier ist nur die Messung, keine neue Zusage.
- **Ausgelagerter Slice (koordiniert, nicht im Haupt-Checkout gebaut).**
  Worktree `/Volumes/1TB_NVMe_SN850X/Dev/Symaira_Dev/Repos/symaira-vault-wt-cli-aliases`,
  Branch `feat/cli-aliases-deprecated-stubs` auf `e30789d0`; ein Worker
  (`deleg_1d28d938`) baut: (1) die drei **Top-Level-Aliase** aus der
  Oracle-Baum-Datei — `get` → `show`, `cat`; `list` → `ls` (Cobra-Aliase wirken
  top-level, also `symvault show X` ≡ `symvault get X`; `symvault get show X`
  ist dagegen **kein** Vertrag, das Oracle lehnt es mit „accepts 1 arg(s),
  received 2“ ab), (2) die vier **deprecated, versteckten** `mcp token`-Stubs
  (`token`, `create`, `list`, `revoke`) byte-genau: stdout leer, Exit 2, vier
  stderr-Zeilen (Warnung, `Error:` doppelt, `Try:`-Hinweis); (3) neuen
  Fixture-Generator `scripts/rust-port/cmd/deprecstubgen` mit Provenance und
  Digest-Test plus einen nicht-ignorierten Rust-Contract-Test. Erwartung:
  Alias-Lücken 3 → 0, fehlende Pfade 43 → 39. Der Slice ist bewusst klein
  gewählt, weil er vollständig offline und byte-genau prüfbar ist.
- **Entscheidung (nicht portiert, begründet):** `symvault help` bleibt offen.
  Das Oracle-`help` ist Cobras eingebauter Hilfe-Befehl und gibt den
  **kompletten Go-Root-Hilfetext** aus (Exit 0, stdout). Byte-Parität würde das
  Nachbauen von Cobras Renderer verlangen; die Rust-CLI bietet stattdessen
  `--help`. Bleibt als Nicht-Zusage dokumentiert, kein stiller Skip.
- **Main-CI auf dem Merge-Commit war rot — nicht wegen des Merges.** Lauf
  `35610080000` (`e30789d0`, attempt 1) scheiterte **ausschließlich** in
  `Rust native (windows-latest)` (Job `106366704731`):
  `divergent_pull_matches_go_oracle_projection` bricht in
  `crates/symvault-sync/tests/git_io_gaps.rs:254` beim `GitRepository::init(&local)`
  mit `Io(Os { code: 5, kind: PermissionDenied })` ab; die anderen 4 Tests
  derselben Suite und alle übrigen Jobs des Laufs waren grün. Der Diff des
  Merges berührt `symvault-sync` nicht → kein Regress aus #1098. Erfasst als
  [#1099](https://github.com/danieljustus/symaira-vault/issues/1099); Rerun
  (attempt 2 desselben Laufs) gestartet, Ergebnis beim Schreiben offen. Die
  vorherigen `main`-Läufe (`71af9eb0`, `b1e1c69f`) waren alle grün, also ist
  das ein Flake-Kandidat und kein Dauerzustand.
- **Nächste Slices (geplant, noch nicht dispatcht).**
  - `update` (4 Pfade) ist **nicht** sofort baubar: der Rust-Workspace hat
    überhaupt keinen HTTP-Client (`Cargo.lock` enthält kein `reqwest`/`ureq`/
    `hyper`; `symvault-sync` spricht Git, nicht HTTP). Das Oracle nutzt
    stdlib `net/http` (`internal/update/checker.go`, `cosign.go`) plus
    cosign-Verifikation für `update apply`. Ohne neue Dependency ist nur
    `update info` (Install-Method-Erkennung aus dem Binary-Pfad) und der bare
    `update`-Hilfetext offline portierbar; `check`/`apply` sind bis zu einer
    bewussten HTTP-Transport- und Cosign-Entscheidung als `blocked` zu führen,
    nicht stillschweigend zu vereinfachen. Das ist die kleinste ehrliche
    Variante: Offline-Teil zuerst, Rest explizit blockiert.
  - `device approval-list`, `approval-pair`, `approval-revoke`
    (`cmd/device_approval.go`, ca. 300 Zeilen, dateibasiert, kein Netz) ist der
    nächste vollständig offline prüfbare Kandidat nach dem Alias-/Stub-Slice.
  - Danach der Rest der 43: `serve` (8), `agent` (6), `intake` (3),
    `approval` (3), `dynamic` (2), `import review` (2), `broker`, `ui`,
    `setup`, `startup-profile`, `generate manpages`, `help`.
- Geladene Skills dieser Sitzung: `go-to-rust-migration` (SKILL.md).
  `go-rust-port-parity` und `references/porting-pitfalls.md` wurden noch nicht
  geladen — bei der nächsten Invocation zuerst laden, nicht erneut inventarisieren.
- Kein Cutover, kein Release; Go bleibt Produktion und Oracle.

## Zwischenstand 2026-09-21, Teil 4 (nach `b1e1c69f`) — alle drei `migrate`-Subkommandos portiert

`migrate` ist in der Rust-CLI vollständig: `pseudonymize` (Teil 3), `v4` und
`session`. Die CLI-Lücke schrumpfte über beide Teile von 46 auf **43** fehlende
Oracle-Pfade; kein `migrate`-Pfad steht mehr in `missing_paths`.

- **`migrate v4`** (`crates/symvault-cli/src/main.rs`): weist Agent-Profilen ohne
  Tier-Feld ein Tier zu — `can_run_commands` → `admin`, `can_write` → `standard`,
  sonst `safe` — legt vorher eine Sicherung
  `config.yaml.v3-backup-<unix-stamp>` an und schreibt erst danach. Dry-Run
  schreibt nichts, ein zweiter Lauf meldet „All profiles already have tier
  fields." und legt keine weitere Sicherung an (idempotent).
- **`migrate session`**: aktualisiert eine zwischengespeicherte Passphrase vom
  Legacy-Klartextformat auf die verschlüsselte Form. Zwei neue
  `SessionManager`-Methoden in `crates/symvault-core/src/session.rs`:
  `has_legacy_plaintext_session` (fehlender Eintrag = „kein Legacy“, leerer
  Klartext zählt nicht) und `migrate_session` (Wrap-Key bei Bedarf, Klartext
  wird vor dem Serialisieren verworfen und per `zeroize` gelöscht,
  `max_lifetime_ns` wird auf 8 h defaulted, zweiter Lauf ist ein No-Op). Das
  Flag `--dry-run` erkennt den Legacy-Zustand und schreibt nichts.
- **Tests.** `crates/symvault-core/src/session.rs`: zwei Einheiten-Tests
  (Migration + Idempotenz + Defaulting; No-Op ohne Legacy-Eintrag) — 9/9
  Session-Tests grün. `crates/symvault-cli/tests/migrate_v4_differential.rs`
  vergleicht direkt gegen das gepinnte Go-Oracle (`SYMVAULT_GO_BINARY`).
- **Bewusste Abweichung, im Test dokumentiert:** das Oracle iteriert
  `cfg.Agents`, eine Go-Map, also ist die Reihenfolge der
  `  <name> → <tier>`-Zeilen nicht-deterministisch; Rust läuft über eine
  `BTreeMap` und ist sortiert. Byte-Parität ist dort ohne Nachbau der
  Map-Iteration nicht erreichbar, deshalb vergleicht der Test die **Menge** der
  Zuordnungen plus die stabilen Rahmenzeilen wörtlich. Verifiziert
  nicht-vakuos: ein absichtlich gebrochener `can_write`-Zweig macht den Test rot
  (`cli → safe` statt `cli → standard`), restauriert ist er grün; die
  Zuordnungsmenge wird explizit auf 7 Einträge geprüft.
- **End-to-End am Binary:** `migrate v4 --dry-run` schreibt nichts;
  der echte Lauf vergibt 7 Tiers und legt genau eine Sicherung an, die nachweislich
  die Vor-Migrations-Config ohne `tier:`-Zeilen enthält; der zweite Lauf ist ein
  No-Op. `migrate session` meldet ohne Legacy-Eintrag „No legacy plaintext
  session found. Nothing to migrate." — der Legacy-Pfad selbst ist
  cross-process nicht darstellbar, weil der Test-Keyring prozesslokal ist
  (gilt für Go genauso), und wird deshalb durch die Einheiten-Tests belegt.
- **Gate-Sweep** über alle 24 `port-contract`-Voraussetzungen: **23 PASS**;
  einziger FAIL ist weiterhin der macOS-Temp-Dir-Flake
  [#1085](https://github.com/danieljustus/symaira-vault/issues/1085), auf pristine
  `origin/main` identisch reproduziert.
- Kein Cutover, kein Release; Go bleibt Produktion.

## Zwischenstand 2026-09-21, Teil 3 (nach `71af9eb0`) — `migrate pseudonymize` portiert

Der nächste freigegebene Slice aus `RUST-009` ist gebaut: `symvault migrate
pseudonymize` existiert jetzt nativ in Rust und verhält sich wie das gefixte
Go-Oracle (`cmd/admin/migrate.go`, Order-Fix aus #1088).

- **Store-API** `Store::migrate_pseudonymize(&Identity) -> PseudonymizeSummary`
  (`crates/symvault-store/src/lib.rs`). Sie wandelt alle `entries/**/*.age` in
  HMAC-abgeleitete Pfade um. Der logische Pfad kommt aus dem Ciphertext
  (`entry.path`), nicht aus dem Dateinamen — nach der ersten Migration ist der
  Dateiname kein Identifikator mehr. Bereits abgeleitete Ziele werden
  übersprungen; würde man den abgeleiteten Namen erneut hashen, verwaiste der
  Eintrag. Die Klartextdatei wird erst entfernt, **nachdem** das Ziel bestätigt
  auf der Platte liegt; fehlt es, bricht die Migration mit Fehler ab, statt still
  zu löschen.
- **Die P0-Lehre ist jetzt strukturell abgesichert, nicht nur nachgeahmt.**
  `migrate_pseudonymize` **verweigert** die Arbeit mit `StoreError::Config`,
  solange `pseudonymize_paths` nicht gesetzt ist. Genau die umgekehrte
  Reihenfolge — Flag erst nach dem Rewrite-Loop setzen — hatte in Go jeden
  Eintrag auf seinen eigenen Klartextpfad geschrieben und dann gelöscht (#1088).
  Die CLI aktiviert das Flag deshalb **vor** dem ersten Schreibvorgang und öffnet
  den Store danach neu.
- **CLI** `crates/symvault-cli/src/main.rs`: Subkommando in der `MigrateCommand`-
  Enum, Dispatcher-Zweig und `run_migrate_pseudonymize` mit
  `-y/--yes`-Bestätigung; ohne `-y` fragt es interaktiv „Migrate all entries to
  pseudonymized paths. Make a backup first (y/N)" und bricht bei `n` mit
  „Canceled" ab — deckungsgleich mit `cli.ConfirmInteractive` im Oracle.
- **Tests** `crates/symvault-store/tests/pseudonymize_migration.rs` (3 Fälle,
  grün): Migration erhält jeden Eintrag und lässt keine klartextbenannte Datei
  zurück; zweiter Lauf ist ein No-Op (`migrated == 0`, Dateizahl unverändert);
  ohne Flag wird mit `StoreError::Config` verweigert und der Vault bleibt
  unberührt.
- **End-to-End am echten Binary** (`target/debug/symvault`, temporärer Vault):
  3 Einträge angelegt (`example.one`, `work/nested/two`, `deep/a/b/c/three`),
  migriert („Migrating 3 entries to pseudonymized paths..."), alle drei unter
  ihrem logischen Pfad lesbar, Dateizahl 3 vor und nach der Migration, zweiter
  Lauf schreibt 0 Einträge um, `list` liefert weiter alle drei. Abbruchpfad mit
  `n` verifiziert.
- **CLI-Lücke gemessen** (`scripts/rust-port/cmd/cligap`): 134 Oracle-Pfade,
  90 Rust-Pfade, **45 fehlen** (vorher 46), 9 Flag-Lücken, 3 Alias-Lücken,
  1 Rust-only Pfad. `migrate pseudonymize` ist nicht mehr in
  `missing_paths`. `CLI-002`/`CLI-003` bleiben `TODO`: Oberflächen-Erreichbarkeit
  ist keine Verhaltensparität und hebt keine Matrix-Zeile an.
- **Gate-Sweep** über alle 24 `port-contract`-Voraussetzungen: **23 PASS**. Der
  einzige FAIL ist der bekannte macOS-Temp-Dir-Flake
  [#1085](https://github.com/danieljustus/symaira-vault/issues/1085)
  (`config-cli-differential`, `Not a directory (os error 20)`) und **auf pristine
  `origin/main` identisch reproduziert** — kein Regress dieses Slices.
- Ein früherer `rust-007-fixtures-check`-FAIL war **selbstverschuldet**: ein
  exportiertes `SYMVAULT_VAULT` aus einem vorherigen E2E-Lauf erbte in
  `configgen` und backte den echten Vault-Pfad statt `/fixture/root/...` in die
  Fixture. Mit sauberer Umgebung grün; Fixtures unverändert. Lehre: nach
  E2E-Läufen `SYMVAULT_*` vollständig `unset`, bevor Fixture-Generatoren laufen.
- Kein Cutover, kein Release; Go bleibt Produktion.

## Zwischenstand 2026-09-21, Teil 2 (nach `c218771c`) — Dependency-Bumps blockieren die Pins nicht mehr

Der zuvor strukturell blockierte Dependabot-Bump ist gemergt. Zwei voneinander
unabhängige Kopplungen mussten dafür fallen — die zweite war beim ersten Anlauf
nicht sichtbar und ist der eigentliche Fund.

- **Kopplung 1 — `go.mod`/`go.sum` im erzwungenen Digest.** Der Bump ließ
  `TestManifestKeyProductionFixture` mit „production source differs from
  `3232e31f`: **go.mod**" scheitern: fünf Fixtures banden die
  Dependency-Manifeste in den *erzwungenen* Quellcode-Digest. Behoben in
  [#1094](https://github.com/danieljustus/symaira-vault/pull/1094) (`b5e5de32`):
  neuer `EnforcedSources`-Helfer, `go.mod`/`go.sum` bleiben als Provenance in
  `source_files` dokumentiert, gaten aber nicht mehr. Betroffen waren
  `mcprendergen`, `exportgen`, `manifestkeygen`, `configprofilegen` (blieb grün),
  `focus` und `mcpprompts`.
- **Kopplung 2 — Oracle-Harness parste `CombinedOutput` als JSON.** Nach dem
  Bump wurde `Rust port contract` rot, obwohl lokal alles grün war. Ursache ist
  **nicht** der Bump: `go run` schreibt Modul-Downloads und Build-Diagnostik nach
  stderr, und bei **kaltem Modul-Cache** landen diese Zeilen *vor* der
  JSON-Payload. Wer `CombinedOutput` an `json.Unmarshal` gibt, liest dann
  `go: downloading …` als Dokument und stirbt mit
  `invalid character 'g' looking for beginning of value`. Ein Bump erzwingt
  genau diesen kalten Pfad — deshalb sah es wie ein Bump-Regress aus.
  `syncgen`, `storegen` und `cxfgen` trennen die Ströme jetzt
  (`cmd.Output()` plus erfasstes `stderr` für die Fehlermeldung). Reproduziert
  wurde der Fehler absichtlich mit `GOMODCACHE=$(mktemp -d) go test ./...`.
- **Folge: drei Fixtures provenance-only neu eingefroren.** `syncgen`,
  `storegen` und `cxfgen` führen ihre **eigene** `main.go` in
  `generator_files`; jede Änderung an ihnen bewegt den `generator_digest`.
  Betroffen: `testdata/port/{sync/sync,import/cxf,store/store}.json` — je genau
  eine Zeile (`generator_digest`), Bodies und `source_digest` byte-identisch.
  Kein Full-Re-Freeze: der würde zusätzlich Eintrags-Zeitstempel und
  Encryption-Nonces umschreiben (#1015 bleibt dafür offen).
- **Gemessen auf `00f42edb` (PR [#1095](https://github.com/danieljustus/symaira-vault/pull/1095),
  Squash-Merge `c218771c`).** CI: 18/18 relevante Jobs grün, keine Failures —
  inklusive `Rust port contract` (pass, 7m5s), `Test (ubuntu) — PR` (pass, 5m6s),
  `Rust native (windows-latest)` (pass, 7m58s), `Flake vendorHash` (pass) und
  `Rust` (pass). Lokal mit kaltem Modul-Cache: 24 von 26 `port-contract`-Targets
  grün; `rust-gates-core` grün.
- **Vorbestehend rot bleibt ausschließlich** `config-cli-differential` (#1085,
  macOS-Temp-Dir-Kollision, `os error 20`, dreimal sequenziell reproduziert,
  auch mit kaltem Cache); der Job läuft in CI auf ubuntu und ist dort grün.
  `Rust native (windows-latest)` traf den bekannten #1071-Timeout in einer
  früheren Runde und war danach grün — `symvault-sync` ist von diesem Branch
  nicht berührt.
- **Issues geschlossen:** [#1058](https://github.com/danieljustus/symaira-vault/pull/1058)
  (durch #1095 ersetzt) und [#1093](https://github.com/danieljustus/symaira-vault/issues/1093).
  Pin `3232e31f` hat den Squash erneut überlebt (`merge-base --is-ancestor` ✓).
- **Regel für die Zukunft:** Wer einen Generator anfasst, der seine eigene
  Quelldatei in `generator_files` führt, muss die Fixture-Digests im **selben**
  PR nachziehen und den Re-Freeze provenance-only halten. Vor dem Editieren
  `generator_files` aller `testdata/port/**/*.json` gegen die eigene Diff-Liste
  prüfen. In `references/porting-pitfalls.md` festgehalten (zwei Einträge).
- Go bleibt Produktion; kein Cutover, kein Release. Nächster Slice unverändert
  `migrate pseudonymize` (RUST-009; in Rust noch nicht vorhanden).

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
