# CI runtime of the Rust gates

Measured on run [35334218267](https://github.com/danieljustus/symaira-vault/actions/runs/35334218267)
(`pull_request`, head `d9bc4f0f`) from the job log timestamps. The `Rust` job was
the whole run's critical path at **2024 s (33.7 min)**; every other job in that
run finished within 7 minutes.

## Per-step split of the monolithic `make rust-gates` job

| Step | Duration |
| --- | --- |
| toolchain and tool installs | ~120 s |
| `rust-lint` (fmt + clippy) | 61 s |
| `rust-check` | 12 s |
| `rust-test` (nextest + doctests) | 123 s |
| `rust-security` (audit + deny) | 26 s |
| `rust-fuzz-smoke` | 75 s |
| **`rust-miri`** | **~1320 s (22 min)** |
| `rust-features` (cargo-hack) | 56 s |
| `rust-coverage` (llvm-cov) | 141 s |
| `rust-version-contract` | 39 s |

Miri is interpreter-bound: one `symvault-core` contract test alone ran for 586 s
inside the Miri pass. The measured reason Miri needs its own job is that no
amount of caching helps an interpreter, while every other step benefits from a
warm workspace build.

## Change

- `make rust-gates-core` is every staged gate except Miri; `make rust-gates`
  keeps its previous meaning (`rust-gates-core` + `rust-miri`).
- `ci.yml` runs `rust-gates-core` in the `Rust` job and `make rust-miri` in the
  new parallel `Rust Miri` job; `CI Success` requires both.

Expected wall clock: `max(≈12 min, ≈22 min, ≈7 min) ≈ 22 min` instead of 34 min,
without dropping or weakening a single gate. Reducing Miri itself (per-test
timings, and whether the crypto-heavy contract tests need interpreter coverage)
is tracked separately; that is the next wall-clock lever.
