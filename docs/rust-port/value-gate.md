# VALUE-001 value gate tool

`scripts/rust-port/valuegate.py` measures a Go release binary and a Rust release
binary on the same host and applies the VALUE-001 rule from
[`contract-matrix.md`](contract-matrix.md). It is Python 3 stdlib only: it needs
no Go toolchain, so it keeps working after the Go tooling is archived
(decision D6) and it never builds anything. Per decision D5, VALUE-001 is
**measured and reported, not blocking**.

## Rule

Thresholds come from `value_gate` in
[`baseline-20260905.json`](baseline-20260905.json) (fallback constants in the
tool are identical): a command **passes** iff

- binary size improves by >= 20% **or** the command's median peak RSS improves by
  >= 20% (improvement = `1 - rust/go`), **and**
- the command's p95 wall latency regresses by <= 10% (`rust_p95/go_p95 - 1`).

Both bounds are inclusive. The overall verdict passes only if every measured
command passes; every command is reported individually. Security and contract
parity (`security_and_contract_parity_required`) are evidenced by the other
contract rows, not by this tool.

## Running a real measurement

Inputs are **release** builds (stripped; debug builds are invalid comparisons):

```sh
# Rust: SYMVAULT_VERSION=dev cargo build --release -p symvault-cli --bin symvault --locked
# Go:   GOTOOLCHAIN=go1.26.6 make build   (stripped ldflags, ./symvault)
make value-gate GO_BIN=/path/to/symvault-go RUST_BIN=target/release/symvault
# or directly
python3 -B scripts/rust-port/valuegate.py measure --go GO --rust RUST --out out.json
python3 -B scripts/rust-port/valuegate.py check out.json [--report-only] [--json-out]
```

`make value-gate` writes `$(VALUE_GATE_OUT)` (default
`target/value-gate/value-gate.json`), then runs `check --report-only` (D5). Set
`VALUE_GATE_ENFORCE=1` to make a missed rule fail the target. Extra measure flags
go in `VALUE_GATE_FLAGS`. Copy the resulting JSON to
`docs/rust-port/value-gate-<date>.json` as the paired benchmark evidence for
VALUE-001. Run it on a quiet host, ideally once warm-cache and once after the
caches are cleared, and on macOS arm64 plus the CI sample.

`measure` options: `--runs N` (latency runs, default 100), `--rss-samples N`
(default 20), `--warmup N` (default 10, untimed), `--commands CMD...` (each a
quoted argument string; default `version`, `list`, `get vg/entry-1.password`,
`generate --length 32`), `--max-load` (default 4.0), `--allow-loaded`,
`--rss-method auto|time|wait4`.

## What is measured

- **Seed vault.** Per binary, a disposable HOME/XDG tree and vault are created
  in a temp directory (`SYMVAULT_VAULT`, `SYMVAULT_TEST_KEYRING=memory`,
  `SYMVAULT_PASSPHRASE` + `SYMVAULT_ALLOW_ENV_PASSPHRASE=1`, the same
  non-interactive convention as `data_safety_contract.py`), seeded by that
  binary's own `init --auth passphrase` and five `set` calls. Operator state is
  never touched. Commands should be read-only after seeding.
- **Size.** `os.stat` size of the binary plus a stripped check (ELF `.symtab`,
  Mach-O defined/debug symbols; `null` = undeterminable, e.g. scripts). A binary
  detected as not stripped marks the run invalid.
- **RSS.** Peak RSS per run, >= 20 samples per command per binary, via
  `/usr/bin/time -l` (macOS, bytes) / `-v` (Linux, KiB converted to bytes), or
  per-child `os.wait4` rusage when `/usr/bin/time` is unavailable. The median
  is compared; all samples are stored. A single sample is never enough (see
  the baseline note).
- **Latency.** Warmup, then >= 100 timed subprocess runs
  (`time.perf_counter_ns`, wall, stdout/stderr discarded); p50/p95 are
  nearest-rank. This includes process spawn and, for `version`, equals the
  startup measurement used in `value-signal-version-20260905.json`.
  `startup-profile` was not reused: it only re-executes the binary without
  arguments and cannot run paired commands over a seeded vault.
- **Host.** `uname`, CPU brand, logical CPUs, Python version, load average
  before and after.

## Validity

A measurement is `valid: false` (with `invalid_reasons`) and `check` exits 2 when:

- 1-min load average > `--max-load` (4.0) before or after. By default a loaded
  start is **refused** (exit 3, nothing written); `--allow-loaded` records the
  run but marks it invalid;
- fewer than 100 latency runs or 20 RSS samples;
- any command run failed, or RSS sampling failed;
- a binary is detected as not stripped.

A seed failure or non-executable input aborts with exit 2. Smoke runs with small
`--runs` are therefore always invalid and can never be mistaken for evidence.

## Measurement JSON (`schema_version` 1, `kind` `value-gate-measurement`)

```json
{
  "schema_version": 1, "kind": "value-gate-measurement", "created_utc": "...",
  "host": {"uname": "...", "system": "...", "machine": "...", "cpu": "...", "logical_cpus": 12, "python": "..."},
  "config": {"runs": 100, "rss_samples": 20, "warmup": 10, "rss_method": "time", "max_load": 4.0,
             "min_runs_for_valid": 100, "min_rss_samples_for_valid": 20},
  "load": {"before": [1m, 5m, 15m], "after": [1m, 5m, 15m]},
  "binaries": {"go": {"path": "...", "sha256": "...", "size_bytes": 0, "stripped": true, "stripped_detail": "..."},
               "rust": {...}},
  "seed": {"go": {"entries": 5, "auth": "passphrase", "steps": 6}, "rust": {...}},
  "commands": [{"name": "list", "argv": ["list"],
                "go":   {"latency_ms": {"runs_requested": 100, "n": 100, "failures": 0, "warmup": 10,
                                         "p50": 0.0, "p95": 0.0, "min": 0.0, "max": 0.0},
                         "rss_bytes": {"n": 20, "samples": [...], "median": 0, "max": 0, "error": null}},
                "rust": {...}}],
  "valid": true, "invalid_reasons": []
}
```

`check` exits 0 (rule met, or `--report-only`), 1 (rule not met), 2 (invalid or
unreadable input, wrong `kind`/`schema_version`, missing/zero/non-finite
values). Its verdict (`kind` `value-gate-verdict`, via `--json-out`) lists
thresholds, size result and one row per command with `rss_improvement`,
`p95_regression` and `pass`.

## Tests

`make value-gate-selftest` (`python3 -B scripts/rust-port/test_valuegate.py`)
drives the tool with fake shell-script binaries and synthetic JSON: pass, fail,
boundary, loaded host (refuse / allow / rising load), failing command, seed
failure, invalid input and stripped detection. The fakes validate the tool, not
Go or Rust.
