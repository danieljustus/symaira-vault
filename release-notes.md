## What's changed

### Fixes
- #830 Stop reporting keychain faults as Touch ID failures — Touch ID setup no longer fails with `errSecDuplicateItem` when the login keychain is the default but missing from the search list; unrelated keychain statuses now map to dedicated, actionable errors.
- #832 Stop rewriting identical conflict copies on every command — git-sync writes a conflict copy only when it carries information (working-tree content diverges from the committed version and the copy on disk differs).
- #834 Treat only actual unmerged paths as sync conflicts after a failed pull — dirty files the remote never touched are no longer flagged or copied as conflicts.
- #835 Make `symvault sync --force` actually reset local changes — the force path now hard-resets to the fetched remote state, backing up discarded local content as recoverable conflict copies.
- #845 Scheme-aware MCP readiness poll with a loud deadline failure in server bootstrap tests.
- #833 Stop MCP server and wizard tests polluting the real vault directory (test isolation).

### Tests
- #838 Cover ForcePull's hard-reset failure branches
- #839 Make the hermetic guard test independent of stale source in gitignored local worktrees
- #844 Cover the git-sync pull path's error and guard branches
- #846 Cover orphaned conflict-file detection and `--fix` guard paths
- #847 Table-test Touch ID keychain status mapping

### CI & Docs
- #829 Shorten pull-request CI feedback
- #848 Record the 2026-08-22 golang/protobuf dependency re-evaluation
- Windows-safe permission-based doctor tests and shutdown race fixes for the token-migration path (7b75a01)

**Full Changelog**: https://github.com/danieljustus/symaira-vault/compare/v0.15.4...v0.15.5
