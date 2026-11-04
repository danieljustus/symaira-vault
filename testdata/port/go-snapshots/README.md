# Frozen Go sources (provenance inputs)

Byte-exact copies of the Go files that Rust provenance tests hash
(`oracle.source_files`, `oracle.generator_files`, `go.mod`) or that a Rust unit
test asserts against (`internal/approval/local.go`,
`internal/mcp/serverbootstrap/http.go`,
`scripts/rust-port/cmd/{manifestkeygen,outputmodegen}/main.go`).

- Layout: `<repo-relative path>.txt` (so they never compile as Go).
- Source: `git show <MANIFEST.json commit>:<path>`; sha256 + size per file in
  `MANIFEST.json`, checked by `crates/symvault-cli/tests/go_snapshots_manifest.rs`.
- Why: the Rust build and tests must not need the Go tree (RUST-015). The
  fixture `source_digest`/`generator_digest` values are unchanged; the tests now
  hash these snapshots instead of the working tree.
- Do not edit by hand. Pinned files that are not Go sources (shell/Python
  scripts) are still read from their normal repo paths.

## Refreshed after the source commit

A snapshot whose Go source is edited by a later change is refreshed from that
change's working tree and its `MANIFEST.json` sha256/bytes are updated; the
`commit` field keeps naming the original freeze for every other file.

- `scripts/rust-port/cmd/outputmodegen/cases.go`: five `config set` integer
  cases (`010`, `017`, `0b11`, `0b101`, `1_000`; ADR 0034 item 4) added to the
  output-modes corpus, so the snapshot no longer equals
  `git show <commit>:scripts/rust-port/cmd/outputmodegen/cases.go`.
- `scripts/rust-port/cmd/outputmodegen/{cases,main}.go` (again): the generator
  records declared divergences (ADR 0034 items 3, 5, 8, 10): the new `read`,
  `declared` and `crash` case fields, the `remove` work file, the `files_after`
  and `declared_divergence` case fields and the `crashHeader` reduction of a Go
  panic. Thirteen cases were added to the corpus.
- `scripts/rust-port/cmd/outputmodegen/cases.go` (again): eighteen `get <query>`
  search-fallback scenarios (CLI-002/CLI-006: single and multiple hits, path and
  field matches, the lone `-`, no match, invalid paths, `--print` and `--length`)
  added to the output-modes corpus (90 cases, 549 -> 639).
- `scripts/rust-port/check_output_modes_cli.sh`: the frozen snapshot is the Go-era regeneration/check script as
  refreshed by the TMPDIR fix (local/nest2). It is a provenance input, not the live script: the Go-free
  `scripts/rust-port/check_output_modes_cli.sh` in the working tree is a different, shorter replay script. The
  snapshot's bytes are what `testdata/port/cli/output-modes.json` hashes into its `generator_digest`
  (`5b62dffb...`), so they stay as is and `MANIFEST.json` now records them (3755 bytes, sha256 `7a8a454900d2f7fe5c79cc076f97261fa516a422983c165d13e8ee4100ecc0a8`) instead of
  the pre-fix 3403-byte original.
