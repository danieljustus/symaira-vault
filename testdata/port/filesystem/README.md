# Filesystem contract fixtures

Filesystem behavior is compared from fresh black-box sandboxes by the Go
harness in `scripts/rust-port/internal/diff`. The complete sandbox is covered,
including HOME, every XDG directory, TMPDIR, and the working tree. Each manifest
records relative path, entry type, permission bits, byte size, SHA-256 for
regular files, and symlink target. Timestamps and owners are deliberately
excluded because the public contract does not fix them.

Deterministic vault-layout fixtures will be generated here when STORE-001 starts.
The RUST-001 harness tests already prove that content, mode, type, and path drift
changes the manifest and fails comparison.
