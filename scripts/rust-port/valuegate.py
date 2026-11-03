#!/usr/bin/env python3
"""VALUE-001 value gate: paired Go/Rust release-binary measurement and check.

Go-free and stdlib-only. Two subcommands:

  measure --go BIN --rust BIN --out JSON [--runs N] [--commands ...]
      Seeds one disposable vault per binary (disposable HOME/XDG), then records
      binary size (+ stripped detection), peak RSS (repeated samples) and wall
      latency (warmup + N runs, p50/p95) for each command, with host info and
      load average before/after. A run on a loaded host is refused (exit 3) or,
      with --allow-loaded, written but marked invalid.

  check JSON [--report-only] [--json]
      Applies the VALUE-001 rule per command: pass iff (size improves >= 20% OR
      RSS improves >= 20%) AND p95 regresses <= 10%. Exit 0 pass, 1 rule not
      met, 2 invalid input/measurement.

Schema and procedure: docs/rust-port/value-gate.md. This tool never runs a
build; it measures binaries it is given. Debug builds are not valid inputs.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import platform
import re
import shlex
import shutil
import statistics
import struct
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

SCHEMA_VERSION = 1
KIND = "value-gate-measurement"
VERDICT_KIND = "value-gate-verdict"

ROOT = Path(__file__).resolve().parents[2]
BASELINE = ROOT / "docs" / "rust-port" / "baseline-20260905.json"

# Fallback thresholds; the baseline file's `value_gate` block is authoritative
# when present (see load_thresholds).
DEFAULT_THRESHOLDS = {
    "minimum_binary_or_rss_improvement": 0.2,
    "maximum_startup_or_command_p95_regression": 0.1,
}

# Tolerance so exact-boundary ratios (20.0% / 10.0%) are not lost to float error.
EPS = 1e-9
MIN_LATENCY_RUNS = 100
MIN_RSS_SAMPLES = 20
DEFAULT_MAX_LOAD = 4.0
SEED_PASSPHRASE = "value gate seed passphrase"
SEED_ENTRIES = 5
DEFAULT_COMMANDS = ["version", "list", "get vg/entry-1.password", "generate --length 32"]
TIME_BIN = "/usr/bin/time"
CMD_TIMEOUT = 120

EXIT_PASS, EXIT_FAIL, EXIT_INVALID, EXIT_LOADED = 0, 1, 2, 3


class ValueGateError(Exception):
    """Invalid input or an unusable measurement environment."""


# --------------------------------------------------------------------------
# small helpers


def utc_now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def percentile(sorted_values, pct):
    """Nearest-rank percentile of an ascending list."""
    if not sorted_values:
        raise ValueGateError("percentile of an empty sample set")
    rank = max(1, math.ceil(pct / 100.0 * len(sorted_values)))
    return sorted_values[min(rank, len(sorted_values)) - 1]


def get_loadavg():
    try:
        return list(os.getloadavg())
    except (OSError, AttributeError):
        return None


def load_thresholds(path=BASELINE):
    thresholds = dict(DEFAULT_THRESHOLDS)
    try:
        block = json.loads(Path(path).read_text()).get("value_gate", {})
    except (OSError, ValueError):
        return thresholds
    for key in thresholds:
        if isinstance(block.get(key), (int, float)):
            thresholds[key] = float(block[key])
    return thresholds


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


# --------------------------------------------------------------------------
# stripped detection (ELF .symtab / Mach-O defined non-debug symbols)

_MACHO_MAGICS = {0xFEEDFACF: "<", 0xFEEDFACE: "<"}


def detect_stripped(path):
    """Return (stripped: bool|None, detail). None means undeterminable."""
    try:
        with open(path, "rb") as fh:
            head = fh.read(64)
            if head[:4] == b"\x7fELF":
                return _elf_stripped(fh, head)
            if len(head) >= 4:
                magic = struct.unpack("<I", head[:4])[0]
                if magic in _MACHO_MAGICS:
                    return _macho_stripped(fh, head, is64=magic == 0xFEEDFACF)
    except OSError as exc:
        return None, f"unreadable: {exc}"
    return None, "not an ELF or thin little-endian Mach-O file"


def _elf_stripped(fh, head):
    is64 = head[4] == 2
    endian = "<" if head[5] == 1 else ">"
    if is64:
        shoff = struct.unpack_from(endian + "Q", head, 0x28)[0]
        shentsize, shnum = struct.unpack_from(endian + "HH", head, 0x3A)
        typ_off = 4
    else:
        shoff = struct.unpack_from(endian + "I", head, 0x20)[0]
        shentsize, shnum = struct.unpack_from(endian + "HH", head, 0x2E)
        typ_off = 4
    if not shoff or not shnum:
        return True, "elf: no section headers"
    fh.seek(shoff)
    table = fh.read(shentsize * shnum)
    for i in range(shnum):
        sh_type = struct.unpack_from(endian + "I", table, i * shentsize + typ_off)[0]
        if sh_type == 2:  # SHT_SYMTAB
            return False, "elf: .symtab present"
    return True, "elf: no .symtab"


def _macho_stripped(fh, head, is64):
    hdr = 32 if is64 else 28
    fh.seek(0)
    header = fh.read(hdr)
    ncmds = struct.unpack_from("<I", header, 16)[0]
    cmds = fh.read(struct.unpack_from("<I", header, 20)[0])
    off = 0
    for _ in range(ncmds):
        cmd, size = struct.unpack_from("<II", cmds, off)
        if cmd == 0x2:  # LC_SYMTAB
            symoff, nsyms = struct.unpack_from("<II", cmds, off + 8)
            entry = 16 if is64 else 12
            fh.seek(symoff)
            table = fh.read(entry * nsyms)
            defined = 0
            for i in range(nsyms):
                n_type = table[i * entry + 4]
                if n_type & 0xE0:  # N_STAB debug symbol
                    return False, "mach-o: debug (stab) symbols present"
                if n_type & 0x0E == 0x0E:  # N_SECT: defined in a section
                    defined += 1
            # A stripped executable keeps only __mh_execute_header (1 symbol).
            if defined > 1:
                return False, f"mach-o: {defined} defined symbols"
            return True, f"mach-o: {defined} defined symbol(s)"
        off += size
    return True, "mach-o: no LC_SYMTAB"


# --------------------------------------------------------------------------
# host + sandbox


def _cpu_brand():
    system = platform.system()
    try:
        if system == "Darwin":
            return subprocess.run(
                ["sysctl", "-n", "machdep.cpu.brand_string"],
                capture_output=True, text=True, timeout=10, check=False,
            ).stdout.strip() or None
        if system == "Linux":
            for line in Path("/proc/cpuinfo").read_text().splitlines():
                if line.lower().startswith("model name"):
                    return line.split(":", 1)[1].strip()
    except (OSError, subprocess.SubprocessError):
        pass
    return platform.processor() or None


def host_info():
    u = platform.uname()
    return {
        "uname": " ".join([u.system, u.release, u.machine]),
        "system": u.system,
        "machine": u.machine,
        "cpu": _cpu_brand(),
        "logical_cpus": os.cpu_count(),
        "python": platform.python_version(),
    }


class Sandbox:
    """Disposable HOME/XDG plus vault directory (never operator state)."""

    def __init__(self, base, name):
        self.base = Path(base, name)
        self.home = self.base / "home"
        self.vault = self.base / "vault"
        for sub in ("config", "data", "cache", "state"):
            (self.home / sub).mkdir(parents=True, exist_ok=True)
        self.vault.mkdir(parents=True, exist_ok=True)

    def env(self):
        return {
            "PATH": os.environ.get("PATH", ""),
            "HOME": str(self.home),
            "XDG_CONFIG_HOME": str(self.home / "config"),
            "XDG_DATA_HOME": str(self.home / "data"),
            "XDG_CACHE_HOME": str(self.home / "cache"),
            "XDG_STATE_HOME": str(self.home / "state"),
            "SYMVAULT_VAULT": str(self.vault),
            "SYMVAULT_TEST_KEYRING": "memory",
            "SYMVAULT_PASSPHRASE": SEED_PASSPHRASE,
            "SYMVAULT_ALLOW_ENV_PASSPHRASE": "1",
            "CI": "1",
        }

    def run(self, binary, args):
        return subprocess.run(
            [str(binary), *args], env=self.env(), stdin=subprocess.DEVNULL,
            capture_output=True, text=True, timeout=CMD_TIMEOUT, check=False,
        )


def seed_vault(sandbox, binary):
    """init + a few entries with a non-interactive passphrase; raises on failure."""
    steps = [["init", "--auth", "passphrase"]]
    for i in range(1, SEED_ENTRIES + 1):
        steps.append(["set", f"vg/entry-{i}.password", "--value", f"seed-value-{i}-correct-horse"])
    for args in steps:
        out = sandbox.run(binary, args)
        if out.returncode != 0:
            raise ValueGateError(
                f"seed step {' '.join(args[:2])!r} failed for {binary} "
                f"(exit {out.returncode}): {out.stderr.strip()[:200]}"
            )
    return {"entries": SEED_ENTRIES, "auth": "passphrase", "steps": len(steps)}


# --------------------------------------------------------------------------
# sampling


def detect_rss_method(requested="auto"):
    if requested in ("time", "wait4"):
        return requested
    if os.path.exists(TIME_BIN) and platform.system() in ("Darwin", "Linux"):
        return "time"
    return "wait4"


def _time_flag():
    return "-l" if platform.system() == "Darwin" else "-v"


_RSS_MAC = re.compile(r"^\s*(\d+)\s+maximum resident set size", re.M)
_RSS_LINUX = re.compile(r"Maximum resident set size \(kbytes\):\s*(\d+)")


def parse_time_rss(stderr, system=None):
    """Peak RSS bytes from /usr/bin/time -l (bytes, macOS) or -v (KiB, Linux)."""
    system = system or platform.system()
    if system == "Darwin":
        m = _RSS_MAC.search(stderr)
        return int(m.group(1)) if m else None
    m = _RSS_LINUX.search(stderr)
    return int(m.group(1)) * 1024 if m else None


def sample_rss(binary, args, env, method):
    """One peak-RSS sample in bytes; raises ValueGateError on command failure."""
    if method == "time":
        proc = subprocess.run(
            [TIME_BIN, _time_flag(), str(binary), *args], env=env,
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
            capture_output=False, stderr=subprocess.PIPE, text=True,
            timeout=CMD_TIMEOUT, check=False,
        )
        if proc.returncode != 0:
            raise ValueGateError(f"{binary} {' '.join(args)} exited {proc.returncode} during RSS sampling")
        rss = parse_time_rss(proc.stderr)
        if rss is None:
            raise ValueGateError("could not parse RSS from /usr/bin/time output")
        return rss
    # wait4: per-child rusage. ru_maxrss is bytes on macOS, KiB elsewhere.
    child = subprocess.Popen(
        [str(binary), *args], env=env, stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    _, status, usage = os.wait4(child.pid, 0)
    child.returncode = os.waitstatus_to_exitcode(status)
    if child.returncode != 0:
        raise ValueGateError(f"{binary} {' '.join(args)} exited {child.returncode} during RSS sampling")
    return int(usage.ru_maxrss) * (1 if platform.system() == "Darwin" else 1024)


def sample_latency_ms(binary, args, env):
    start = time.perf_counter_ns()
    proc = subprocess.run(
        [str(binary), *args], env=env, stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        timeout=CMD_TIMEOUT, check=False,
    )
    elapsed = (time.perf_counter_ns() - start) / 1e6
    return elapsed, proc.returncode


def measure_command(binary, args, env, runs, rss_samples, warmup, rss_method):
    for _ in range(warmup):
        sample_latency_ms(binary, args, env)
    latencies, failures = [], 0
    for _ in range(runs):
        ms, rc = sample_latency_ms(binary, args, env)
        if rc != 0:
            failures += 1
        else:
            latencies.append(ms)
    rss, rss_error = [], None
    for _ in range(rss_samples):
        try:
            rss.append(sample_rss(binary, args, env, rss_method))
        except ValueGateError as exc:
            rss_error = str(exc)
            break
    latencies.sort()
    out = {
        "latency_ms": {
            "runs_requested": runs, "n": len(latencies), "failures": failures, "warmup": warmup,
            "p50": percentile(latencies, 50) if latencies else None,
            "p95": percentile(latencies, 95) if latencies else None,
            "min": latencies[0] if latencies else None,
            "max": latencies[-1] if latencies else None,
        },
        "rss_bytes": {
            "n": len(rss), "samples": rss,
            "median": int(statistics.median(rss)) if rss else None,
            "max": max(rss) if rss else None,
            "error": rss_error,
        },
    }
    return out


# --------------------------------------------------------------------------
# measure


def parse_commands(items):
    commands = []
    for item in items:
        argv = shlex.split(item)
        if not argv:
            raise ValueGateError("empty --commands entry")
        commands.append({"name": " ".join(argv), "argv": argv})
    return commands


def binary_info(path):
    p = Path(path)
    if not p.is_file() or not os.access(p, os.X_OK):
        raise ValueGateError(f"not an executable file: {path}")
    stripped, detail = detect_stripped(p)
    return {
        "path": str(p.resolve()), "sha256": sha256_file(p), "size_bytes": p.stat().st_size,
        "stripped": stripped, "stripped_detail": detail,
    }


def run_measure(args):
    max_load = args.max_load
    load_before = get_loadavg()
    loaded_before = bool(load_before and load_before[0] > max_load)
    if load_before and loaded_before and not args.allow_loaded:
        print(
            f"refusing to measure: 1-min load average {load_before[0]:.2f} > {max_load} "
            "(use --allow-loaded to record an explicitly invalid run)", file=sys.stderr,
        )
        return EXIT_LOADED
    if args.runs < 1 or args.rss_samples < 1 or args.warmup < 0:
        raise ValueGateError("--runs/--rss-samples must be >= 1 and --warmup >= 0")

    commands = parse_commands(args.commands or DEFAULT_COMMANDS)
    rss_method = detect_rss_method(args.rss_method)
    infos = {"go": binary_info(args.go), "rust": binary_info(args.rust)}
    reasons = []
    for side, info in infos.items():
        if info["stripped"] is False:
            reasons.append(f"{side} binary is not stripped ({info['stripped_detail']})")
    if load_before and loaded_before:
        reasons.append(f"load average before measurement {load_before[0]:.2f} > {max_load}")
    if args.runs < MIN_LATENCY_RUNS:
        reasons.append(f"latency runs {args.runs} < {MIN_LATENCY_RUNS}")
    if args.rss_samples < MIN_RSS_SAMPLES:
        reasons.append(f"RSS samples {args.rss_samples} < {MIN_RSS_SAMPLES}")

    results = [{"name": c["name"], "argv": c["argv"]} for c in commands]
    seeds = {}
    with tempfile.TemporaryDirectory(prefix="valuegate-") as base:
        for side in ("go", "rust"):
            sandbox = Sandbox(base, side)
            seeds[side] = seed_vault(sandbox, infos[side]["path"])
            env = sandbox.env()
            for res, cmd in zip(results, commands):
                res[side] = measure_command(
                    infos[side]["path"], cmd["argv"], env,
                    args.runs, args.rss_samples, args.warmup, rss_method,
                )

    load_after = get_loadavg()
    if load_after and load_after[0] > max_load:
        reasons.append(f"load average after measurement {load_after[0]:.2f} > {max_load}")
    for res in results:
        for side in ("go", "rust"):
            lat, rss = res[side]["latency_ms"], res[side]["rss_bytes"]
            if lat["failures"]:
                reasons.append(f"{side} `{res['name']}` failed {lat['failures']}/{lat['runs_requested']} runs")
            if rss["error"]:
                reasons.append(f"{side} `{res['name']}` RSS sampling failed: {rss['error']}")

    doc = {
        "schema_version": SCHEMA_VERSION,
        "kind": KIND,
        "created_utc": utc_now(),
        "host": host_info(),
        "config": {
            "runs": args.runs, "rss_samples": args.rss_samples, "warmup": args.warmup,
            "rss_method": rss_method, "max_load": max_load,
            "min_runs_for_valid": MIN_LATENCY_RUNS, "min_rss_samples_for_valid": MIN_RSS_SAMPLES,
        },
        "load": {"before": load_before, "after": load_after},
        "binaries": infos,
        "seed": seeds,
        "commands": results,
        "valid": not reasons,
        "invalid_reasons": reasons,
    }
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n")
    print(f"wrote {out} (valid={doc['valid']})")
    for reason in reasons:
        print(f"  invalid: {reason}")
    return EXIT_PASS


# --------------------------------------------------------------------------
# check


def _require(cond, msg):
    if not cond:
        raise ValueGateError(msg)


def _num(value, label, positive=False):
    _require(isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value),
             f"{label} is not a finite number")
    _require(not positive or value > 0, f"{label} must be > 0")
    return float(value)


def evaluate(doc, thresholds):
    """Return the verdict dict; raises ValueGateError on invalid input."""
    _require(isinstance(doc, dict), "measurement is not a JSON object")
    _require(doc.get("kind") == KIND, f"kind must be {KIND!r}")
    _require(doc.get("schema_version") == SCHEMA_VERSION,
             f"unsupported schema_version {doc.get('schema_version')!r} (want {SCHEMA_VERSION})")
    _require(doc.get("valid") is True,
             "measurement is marked invalid: " + "; ".join(doc.get("invalid_reasons") or ["no reason recorded"]))
    bins = doc.get("binaries")
    _require(isinstance(bins, dict) and all(isinstance(bins.get(s), dict) for s in ("go", "rust")),
             "binaries.go and binaries.rust are required")
    go_size = _num(bins["go"].get("size_bytes"), "binaries.go.size_bytes", True)
    rust_size = _num(bins["rust"].get("size_bytes"), "binaries.rust.size_bytes", True)
    commands = doc.get("commands")
    _require(isinstance(commands, list) and commands, "commands must be a non-empty list")

    need_improve = thresholds["minimum_binary_or_rss_improvement"]
    max_regress = thresholds["maximum_startup_or_command_p95_regression"]
    size_improvement = 1.0 - rust_size / go_size
    size_ok = size_improvement >= need_improve - EPS

    rows = []
    for cmd in commands:
        _require(isinstance(cmd, dict) and isinstance(cmd.get("name"), str), "command entry without a name")
        name = cmd["name"]
        side = {}
        for s in ("go", "rust"):
            _require(isinstance(cmd.get(s), dict), f"`{name}`: missing {s} results")
            lat, rss = cmd[s].get("latency_ms"), cmd[s].get("rss_bytes")
            _require(isinstance(lat, dict) and isinstance(rss, dict), f"`{name}`: {s} results incomplete")
            _require(lat.get("failures") == 0, f"`{name}`: {s} had failed runs")
            _require(isinstance(lat.get("n"), int) and lat["n"] > 0, f"`{name}`: {s} has no latency samples")
            _require(isinstance(rss.get("n"), int) and rss["n"] > 0, f"`{name}`: {s} has no RSS samples")
            side[s] = (
                _num(lat.get("p95"), f"`{name}` {s} p95", True),
                _num(lat.get("p50"), f"`{name}` {s} p50", True),
                _num(rss.get("median"), f"`{name}` {s} median RSS", True),
            )
        rss_improvement = 1.0 - side["rust"][2] / side["go"][2]
        p95_regression = side["rust"][0] / side["go"][0] - 1.0
        rss_ok = rss_improvement >= need_improve - EPS
        p95_ok = p95_regression <= max_regress + EPS
        rows.append({
            "name": name,
            "size_improvement": size_improvement, "size_ok": size_ok,
            "rss_improvement": rss_improvement, "rss_ok": rss_ok,
            "p50_ms": {"go": side["go"][1], "rust": side["rust"][1]},
            "p95_ms": {"go": side["go"][0], "rust": side["rust"][0]},
            "p95_regression": p95_regression, "p95_ok": p95_ok,
            "pass": (size_ok or rss_ok) and p95_ok,
        })
    return {
        "schema_version": SCHEMA_VERSION,
        "kind": VERDICT_KIND,
        "thresholds": thresholds,
        "size": {"go_bytes": int(go_size), "rust_bytes": int(rust_size),
                 "improvement": size_improvement, "ok": size_ok},
        "commands": rows,
        "pass": all(r["pass"] for r in rows),
    }


def render_verdict(v):
    lines = [
        f"VALUE-001: need >={v['thresholds']['minimum_binary_or_rss_improvement']:.0%} size or RSS gain, "
        f"p95 regression <={v['thresholds']['maximum_startup_or_command_p95_regression']:.0%}",
        f"size: go {v['size']['go_bytes']} B, rust {v['size']['rust_bytes']} B, "
        f"improvement {v['size']['improvement']:+.1%} ({'ok' if v['size']['ok'] else 'below threshold'})",
    ]
    for r in v["commands"]:
        lines.append(
            f"  {'PASS' if r['pass'] else 'FAIL'}  {r['name']}: rss {r['rss_improvement']:+.1%} "
            f"({'ok' if r['rss_ok'] else 'below'}), p95 {r['p95_ms']['go']:.2f} -> {r['p95_ms']['rust']:.2f} ms "
            f"({r['p95_regression']:+.1%}, {'ok' if r['p95_ok'] else 'regressed'})"
        )
    lines.append("overall: " + ("PASS" if v["pass"] else "FAIL"))
    return "\n".join(lines)


def run_check(args):
    try:
        doc = json.loads(Path(args.json).read_text())
    except (OSError, ValueError) as exc:
        raise ValueGateError(f"cannot read measurement {args.json}: {exc}")
    verdict = evaluate(doc, load_thresholds(args.baseline))
    if args.json_out:
        print(json.dumps(verdict, indent=2, sort_keys=True))
    else:
        print(render_verdict(verdict))
    if verdict["pass"] or args.report_only:
        return EXIT_PASS
    return EXIT_FAIL


# --------------------------------------------------------------------------


def build_parser():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)
    m = sub.add_parser("measure", help="measure Go and Rust release binaries")
    m.add_argument("--go", required=True, help="Go release binary")
    m.add_argument("--rust", required=True, help="Rust release binary")
    m.add_argument("--out", required=True, help="output JSON path")
    m.add_argument("--runs", type=int, default=MIN_LATENCY_RUNS, help="latency runs per command (default 100)")
    m.add_argument("--rss-samples", type=int, default=MIN_RSS_SAMPLES, help="RSS samples per command (default 20)")
    m.add_argument("--warmup", type=int, default=10, help="untimed warmup runs per command (default 10)")
    m.add_argument("--commands", nargs="+", metavar="CMD",
                   help="read-only commands, each one quoted string (default: %s)" % "; ".join(DEFAULT_COMMANDS))
    m.add_argument("--max-load", type=float, default=DEFAULT_MAX_LOAD, help="1-min load above which a run is loaded")
    m.add_argument("--allow-loaded", action="store_true", help="measure anyway on a loaded host; result is marked invalid")
    m.add_argument("--rss-method", choices=("auto", "time", "wait4"), default="auto")
    c = sub.add_parser("check", help="apply the VALUE-001 rule to a measurement JSON")
    c.add_argument("json", help="measurement JSON from `measure`")
    c.add_argument("--report-only", action="store_true", help="exit 0 even if the rule is not met (decision D5)")
    c.add_argument("--json-out", action="store_true", help="print the verdict as JSON")
    c.add_argument("--baseline", default=str(BASELINE), help="baseline JSON holding the value_gate thresholds")
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    try:
        return run_measure(args) if args.cmd == "measure" else run_check(args)
    except ValueGateError as exc:
        print(f"valuegate: {exc}", file=sys.stderr)
        return EXIT_INVALID
    except subprocess.TimeoutExpired as exc:
        print(f"valuegate: command timed out: {exc}", file=sys.stderr)
        return EXIT_INVALID


if __name__ == "__main__":
    sys.exit(main())
