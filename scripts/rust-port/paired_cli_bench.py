#!/usr/bin/env python3
"""Measure a paired read command on disposable Go-created vault copies.

Both binaries must already be built. The Go binary must identify itself as
the frozen v0.22.1 oracle. Command output is captured and discarded; only
version labels and measurements are written to the JSON report.

Example:
    python3 scripts/rust-port/paired_cli_bench.py \\
        --go-binary target/port/symvault-go-release \\
        --rust-binary target/release/symvault > paired-benchmark.json
"""

from __future__ import annotations

import argparse
import json
import math
import os
import platform
import re
import shutil
import statistics
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

GO_RELEASE = "v0.22.1"
GO_REVISION = "caadd5e"
READ_ENTRY = "benchmark-entry-032"


class BenchmarkError(RuntimeError):
    pass


def percentile(values: list[float], percent: float) -> float:
    if not values or not 0 < percent <= 100:
        raise ValueError("percentile requires values and a percentile in (0, 100]")
    ordered = sorted(values)
    return ordered[math.ceil(percent / 100 * len(ordered)) - 1]


def parse_rss_bytes(stderr: str, system: str) -> tuple[int | None, str | None]:
    if system == "Linux":
        match = re.search(r"Maximum resident set size \(kbytes\):\s*(\d+)", stderr)
        return (int(match.group(1)) * 1024, "/usr/bin/time -v") if match else (None, None)
    if system in {"Darwin", "FreeBSD"}:
        match = re.search(r"^\s*(\d+)\s+maximum resident set size\s*$", stderr, re.I | re.M)
        return (int(match.group(1)), "/usr/bin/time -l") if match else (None, None)
    return None, None


def isolated_env(home: Path, temp_root: Path, vault: Path | None = None) -> dict[str, str]:
    # Only inherit executable lookup and OS loader necessities. This prevents
    # user credentials and unrelated CLI configuration from reaching either
    # measured process.
    env = {"PATH": os.environ.get("PATH", ""), "CI": "1", "NO_COLOR": "1", "LANG": "C", "TZ": "UTC"}
    for key in ("SYSTEMROOT", "WINDIR", "COMSPEC", "PATHEXT"):
        if key in os.environ:
            env[key] = os.environ[key]
    env.update(
        HOME=str(home),
        USERPROFILE=str(home),
        TMPDIR=str(temp_root),
        TMP=str(temp_root),
        TEMP=str(temp_root),
        XDG_CONFIG_HOME=str(home / "config"),
        XDG_DATA_HOME=str(home / "data"),
        XDG_CACHE_HOME=str(home / "cache"),
        SYMVAULT_PASSPHRASE="",
        SYMVAULT_ALLOW_ENV_PASSPHRASE="1",
        SYMVAULT_LOG_LEVEL="error",
        GIT_CONFIG_NOSYSTEM="1",
        GIT_TERMINAL_PROMPT="0",
    )
    if os.name == "nt":
        env["APPDATA"] = str(home / "AppData" / "Roaming")
        env["LOCALAPPDATA"] = str(home / "AppData" / "Local")
    if vault is not None:
        env["SYMVAULT_VAULT"] = str(vault)
        env["SYMVAULT_PASSPHRASE"] = os.environ.get("SYMVAULT_BENCH_INTERNAL_PASSPHRASE", "")
    return env


def run_captured(command: list[str], env: dict[str, str], label: str) -> bytes:
    try:
        result = subprocess.run(command, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    except OSError as exc:
        raise BenchmarkError(f"could not run {label} command") from exc
    if result.returncode != 0:
        raise BenchmarkError(f"{label} command failed with exit code {result.returncode}")
    return result.stdout


def safe_version(binary: Path, home: Path, temp_root: Path, label: str) -> str:
    output = run_captured([str(binary), "version"], isolated_env(home, temp_root), f"{label} version")
    first_line = output.decode("utf-8", "replace").strip().splitlines()
    if not first_line:
        raise BenchmarkError(f"{label} version command returned no label")
    return re.sub(r"[^A-Za-z0-9 .+()_:-]", "?", first_line[0][:128])


def rss_sample(binary: Path, args: list[str], env: dict[str, str], label: str) -> tuple[int | None, str | None]:
    system = platform.system()
    if system == "Linux":
        time_args = ["-v"]
    elif system in {"Darwin", "FreeBSD"}:
        time_args = ["-l"]
    else:
        return None, None
    time_binary = Path("/usr/bin/time")
    if not time_binary.is_file():
        return None, None
    try:
        result = subprocess.run(
            [str(time_binary), *time_args, str(binary), *args],
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
    except OSError:
        return None, None
    if result.returncode != 0:
        raise BenchmarkError(f"{label} RSS sample failed with exit code {result.returncode}")
    return parse_rss_bytes(result.stderr.decode("utf-8", "replace"), system)


def build_report(
    go_binary: Path,
    rust_binary: Path,
    runs: int,
    warmups: int,
    entries: int,
    include_rss: bool = True,
) -> dict[str, Any]:
    if runs < 1 or warmups < 0 or entries < 1:
        raise BenchmarkError("runs and entries must be positive; warmups cannot be negative")
    go_binary = go_binary.resolve(strict=True)
    rust_binary = rust_binary.resolve(strict=True)
    if not go_binary.is_file() or not rust_binary.is_file():
        raise BenchmarkError("both binary paths must be files")

    with tempfile.TemporaryDirectory(prefix="symvault-value-bench-") as temp_name:
        root = Path(temp_name)
        home = root / "home"
        home.mkdir()
        # The ephemeral passphrase exists only in this process environment and
        # its children. It is synthetic, never printed, and never serialized.
        passphrase = "value-bench-" + os.urandom(24).hex()
        os.environ["SYMVAULT_BENCH_INTERNAL_PASSPHRASE"] = passphrase
        try:
            go_version = safe_version(go_binary, home, root, "Go")
            rust_version = safe_version(rust_binary, home, root, "Rust")
            if GO_RELEASE not in go_version:
                raise BenchmarkError("Go binary did not report the frozen v0.22.1 release")

            template = root / "template-vault"
            go_env = isolated_env(home, root, template)
            run_captured([str(go_binary), "init", "--auth", "passphrase"], go_env, "Go vault init")
            for index in range(1, entries + 1):
                entry = f"benchmark-entry-{index:03d}"
                run_captured(
                    [
                        str(go_binary), "add", entry,
                        "--value", f"synthetic-value-{index:03d}",
                        "--username", f"fixture-user-{index:03d}",
                        "--url", "https://example.test/benchmark",
                        "--notes", "synthetic benchmark fixture",
                        "--force",
                    ],
                    go_env,
                    "Go fixture creation",
                )

            measured_entry = f"benchmark-entry-{entries:03d}"
            vaults: dict[str, Path] = {}
            for label in ("go", "rust"):
                vault = root / label / "vault"
                vault.parent.mkdir()
                shutil.copytree(template, vault)
                vaults[label] = vault

            binaries = {"go": go_binary, "rust": rust_binary}
            homes = {label: root / label / "home" for label in binaries}
            for side_home in homes.values():
                side_home.mkdir()
            command_args = ["get", measured_entry, "--output", "json"]

            def read_once(label: str) -> None:
                env = isolated_env(homes[label], root, vaults[label])
                run_captured([str(binaries[label]), *command_args], env, f"{label} read")

            for _ in range(warmups):
                read_once("go")
                read_once("rust")
            samples: dict[str, list[float]] = {"go": [], "rust": []}
            for index in range(runs):
                order = ("go", "rust") if index % 2 == 0 else ("rust", "go")
                for label in order:
                    start = time.perf_counter_ns()
                    read_once(label)
                    samples[label].append((time.perf_counter_ns() - start) / 1_000_000)

            rss: dict[str, tuple[int | None, str | None]] = {"go": (None, None), "rust": (None, None)}
            if include_rss:
                for label in binaries:
                    env = isolated_env(homes[label], root, vaults[label])
                    rss[label] = rss_sample(binaries[label], command_args, env, label)

            go_p95 = percentile(samples["go"], 95)
            rust_p95 = percentile(samples["rust"], 95)
            return {
                "schema_version": 1,
                "benchmark": "paired-cli-get",
                "oracle": {
                    "expected_release": GO_RELEASE,
                    "expected_source_revision": GO_REVISION,
                },
                "environment": {"os": platform.system(), "arch": platform.machine()},
                "fixture": {"entries": entries, "synthetic": True, "vault_copies": 2},
                "sampling": {
                    "operation": f"get {measured_entry} --output json",
                    "runs_per_binary": runs,
                    "warmups_per_binary": warmups,
                    "latency_method": "subprocess wall time via perf_counter_ns, including startup",
                    "p95_method": "nearest-rank",
                    "rss_samples_per_binary": 1 if include_rss else 0,
                    "rss_method": rss["go"][1] or rss["rust"][1],
                },
                "artifacts": {
                    "go": {"version": go_version, "binary_bytes": go_binary.stat().st_size},
                    "rust": {"version": rust_version, "binary_bytes": rust_binary.stat().st_size},
                },
                "measurements": {
                    label: {
                        "read_p50_ms": round(statistics.median(samples[label]), 3),
                        "read_p95_ms": round(percentile(samples[label], 95), 3),
                        "max_rss_bytes": rss[label][0],
                    }
                    for label in binaries
                },
                "comparison": {
                    "rust_binary_size_ratio": rust_binary.stat().st_size / go_binary.stat().st_size,
                    "rust_read_p95_ratio": rust_p95 / go_p95 if go_p95 else None,
                },
                "value_gate_claim": "not_evaluated_requires_native_macos_arm64_and_ci_samples",
            }
        finally:
            os.environ.pop("SYMVAULT_BENCH_INTERNAL_PASSPHRASE", None)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--go-binary", required=True, type=Path)
    parser.add_argument("--rust-binary", required=True, type=Path)
    parser.add_argument("--runs", type=int, default=120)
    parser.add_argument("--warmups", type=int, default=20)
    parser.add_argument("--entries", type=int, default=32)
    parser.add_argument("--no-rss", action="store_true", help="skip RSS where no supported time utility is available")
    args = parser.parse_args()
    try:
        report = build_report(
            args.go_binary, args.rust_binary, args.runs, args.warmups, args.entries, not args.no_rss
        )
    except (BenchmarkError, OSError, ValueError) as exc:
        print(f"paired_cli_bench: {exc}", file=sys.stderr)
        return 1
    json.dump(report, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
