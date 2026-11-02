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
