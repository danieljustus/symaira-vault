# Naechster Slice: `agent install` (+ pruefen: `agent upgrade`)

Status: **spezifiziert, nicht begonnen.** Stand nach Teil 11 (`agent skill*`,
PR #1102 gemergt als `e6e0dc0d`): 32 fehlende Oracle-Pfade.

## Ziel

`cligap`: `symvault agent install` von *fehlend* auf *vorhanden*;
Ziel 32 → 31. Falls `agent upgrade` im selben Slice sauber aufgeht, 32 → 30.

## Oracle-Referenz

- `cmd/mcp/agent_install.go` (495 Zeilen): `agentInstallRunE`,
  `agentInstallSingle`, `agentInstallAutoDetect`, `createAgentProfileConfig`,
  `buildInstallProfile`, `createAgentTokenInRegistry`, `installMCPConfig`,
  `installSkillPackage`, `resolveSkillPath`, `writeInstallOutput`.
- `cmd/mcp/agent_install_test.go` (219 Zeilen) als Verhaltens-Fixture-Quelle.
- `cmd/mcp/mcp_install.go` / `internal/install/**` fuer `installMCPConfig` und
  `install.AgentType` — vorher pruefen, welcher Teil schon in Rust liegt:
  `agent uninstall` ist portiert und muss denselben Config-Writer nutzen.
- `internal/agentskill` ist seit Teil 10 in Rust vorhanden
  (`crates/symvault-cli/src/agent_skill_commands.rs`); `installSkillPackage`
  und `resolveSkillPath` sollen darauf aufsetzen statt neu zu rendern.
- Token-Registry: `createAgentTokenInRegistry` nutzt den Store, der in
  `agent token new` bereits portiert ist — wiederverwenden, nicht duplizieren.

## Gemessene Ausgangslage

`grep -n "http\.\|net/http\|Download\|os/exec" cmd/mcp/agent_install.go` → leer.
Der Slice ist damit offline/deterministisch, sofern nicht `--http` einen
laufenden Server verlangt. Die Wirkung von `httpMode` zuerst im Oracle messen
und im Ledger festhalten; wenn sie einen Serverstart braucht, diesen Pfad als
`blocked` markieren statt zu raten.

## Risiken / Pitfalls vor dem Start

1. **Auto-Detect:** `agentInstallAutoDetect` kann ohne Argument mehrere Agenten
   finden. Pruefen, ob das ohne TTY deterministisch ist; sonst in den Tests
   explizite Agenten-Namen nutzen und den Auto-Detect-Pfad als `partial`
   markieren.
2. **Config-Writer:** `createAgentProfileConfig` veraendert die Vault-Config.
   Die Portierung aus `agent profile` / `agent uninstall` nutzen, sonst
   divergieren die Bytes (YAML-Reihenfolge, Kommentare, Rechte).
3. **Oracle nie mit echtem HOME** ausfuehren; throwaway `HOME`/`XDG`-Roots und
   Scratch-CWD. `agent setup` (Netzwerk-Downloads nach `~/.symaira/bin`) bleibt
   ausdruecklich **ausserhalb** dieses Slices.
4. **Fixtures:** Oracle-Ausgaben als Fixtures unter
   `crates/symvault-cli/tests/fixtures/**` ablegen; `.gitattributes` pinnt den
   Ordner auf LF (`text eol=lf`) und die Loader normalisieren CRLF.
5. **Tests:** `tempfile::TempDir` statt Zeitstempel-Namen (Issue #1085);
   Contract-Test `crates/symvault-cli/tests/cli_agent_install.rs`, non-ignored,
   ohne Umgebungsvariablen. Vergleiche nach einem *legitimen* Rewrite ignorieren
   den Installations-Zeitstempel (Lehre aus Teil 10).
6. **Test-Fixtures nicht nach CRLF konvertieren lassen** und Fehlerausgaben
   doppelt erwarten: die Oracle druckt jeden Fehler zweimal (CLI-005).

## Acceptance (aus dem Worktree-Root)

```sh
cargo fmt --all --check
cargo clippy -p symvault-cli --all-targets -- -D warnings
cargo test -p symvault-cli
GOTOOLCHAIN=go1.26.6 go build -ldflags "-s -w -X main.version=unreleased -X main.commit=none -X main.date=unknown" -o target/port/symvault-go .
GOTOOLCHAIN=go1.26.6 go run ./scripts/rust-port/cmd/cligap -binary target/debug/symvault
```

Plus ein Byte-Differential (Exit, stdout, stderr, geschriebene Dateien) fuer:
install mit explizitem Agenten, unbekannter Agent, `--skill-only`,
`--config-only`, `--dry-run`, `--force`, `--tier`, 0/2 Argumente, `--quiet`.
