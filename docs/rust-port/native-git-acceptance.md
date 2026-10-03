# GIT-002/003 native acceptance, 2026-10-03

## Decision and scope

Accept GIT-002 (push/pull/authentication) and GIT-003 (reconciliation) as
`PASS`. Issue #1246's prerequisites #1073, #1099 and #1026 are closed and their
fixes are integrated. Keep RUST-008 `in_progress`: import/export, intake and
pairing have separate acceptance requirements. No release or Go removal is
implied by accepting these two rows.

Use compiled native test helpers on every supported platform. Shell-only SSH
fixtures previously excluded Windows from four productive transport tests;
native helpers exercise the same production Git path, quoted executable paths,
askpass environment, timeout and descendant cleanup there. They introduce no
production runtime dependency. Keep the old Go archive rejection as the named
`sync-windows-archive-exception-v1`; it does not establish archive parity.

## One executed revision on three platforms

The tested GitHub merge revision is
`c37d7d5e8c0bbf21494dbfa90f5d1fb3a460ee39`, tree
`eca05e279aed2da4d226d37ac5aa0af20e52cb4b`. Its verified parents are main
`bd020d11dc9fa4611075117b4ab3a587fd010ddd` and PR #1286 head
`af381b58c547ad9b5e88fe8b1f9336594dc31bf1`. The workflows are associated with
that PR head; all logs below check out the same merge revision. The subsequent
ordinary squash integration is `58698c6cd07b57f2dd025f61ad0e56b0887dc70f`.

| Native platform | Productive Rust Git tests | Reconciliation/winner tests | Actual Go Git observations |
| --- | --- | --- | --- |
| Linux | [CI job 111223726968](https://github.com/danieljustus/symaira-vault/actions/runs/37128982219/job/111223726968): all 11 named `git_io_gaps` tests passed | All 6 `version_winner_contract` tests and both reconciliation contract tests passed | [Observation job 111220077076](https://github.com/danieljustus/symaira-vault/actions/runs/37128982223/job/111220077076): 5 real Git I/O cases passed |
| Windows | [CI job 111223727202](https://github.com/danieljustus/symaira-vault/actions/runs/37128982219/job/111223727202): 11 passed, 0 failed/ignored | 6 winner tests passed, 0 failed/ignored; both reconciliation contract tests passed | [Observation job 111220076856](https://github.com/danieljustus/symaira-vault/actions/runs/37128982223/job/111220076856): 5 real Git I/O cases passed |
| macOS arm64 | [CI job 111223727199](https://github.com/danieljustus/symaira-vault/actions/runs/37128982219/job/111223727199): 11 passed, 0 failed/ignored | 6 winner tests passed, 0 failed/ignored; both reconciliation contract tests passed | [Observation job 111220077116](https://github.com/danieljustus/symaira-vault/actions/runs/37128982223/job/111220077116): 5 real Git I/O cases passed |

The two reconciliation tests are
`reconciliation_is_order_independent_and_lossless_on_conflict` and
`go_generated_git_reconcile_and_archive_cases_match_rust_projections`.
`git_lifecycle_matches_local_bare_remote_contract` also passed on all three
platforms. The surrounding contract binary has 16 tests on Unix and 12 on
Windows because four Unix archive/symlink permission tests are platform
specific; none of the Git or reconciliation tests is excluded on Windows.

The Go observation workflow additionally captured the six portable sync cases
twice and checked the genuine frozen corpus on every platform. Historical
archive failure and current backup roundtrip are asserted separately. All
inputs use disposable HOME/XDG roots and synthetic loopback/local repositories.

## Reproducibility and retained contracts

- `make git-io-differential`: source-bound Go transport capture plus all 11
  productive Rust Git tests.
- `make git-winner-differential`: genuine Go winner fixtures and all 6 Rust
  tests, including canonical JSON byte comparison.
- `cargo test -p symvault-sync --test contracts --all-features --locked`:
  real bare-remote lifecycle, frozen reconciliation projections and lossless
  conflict copies.
- `.github/workflows/rust-sync-observations.yml`: repeated actual captures,
  explicitly named archive contract and native Go Git I/O.

Transport source remains pinned to
`28fd35315cf4989821a96bb08279c999c693e8d9`; sync source remains pinned to
`caadd5ef95e8f19fabd3ae3d2c04caa296f2fd44`. Native execution supplements the
retained Go/Rust differential; it does not replace its provenance or silently
rewrite expected observations.
