#!/usr/bin/env python3
"""Measure the Rust CLI's command surface against the frozen oracle command tree.

Python port of scripts/rust-port/cmd/cligap (Go), which only ever read the
committed testdata/port/cli/command-tree.json and probed the Rust binary; it never
needed a Go oracle binary. Surface reachability and flag presence only, never
behavioral parity. Same report schema and same walking rules as the Go tool.
"""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
LONG_FLAG = re.compile(r"--([a-zA-Z0-9][a-zA-Z0-9-]*)")
COMMAND_HEADINGS = {"Commands:", "Available Commands:", "Additional Commands:", "Essentials:", "Vault:",
                    "Sharing & Sync:", "Agents & MCP:", "Auth & Access:", "Administration:"}
OTHER_HEADINGS = {"Options:", "Flags:", "Global Flags:", "Arguments:", "Usage:", "Examples:", "Aliases:"}


def probe(binary, path):
    """`<binary> <path without the root name> --help`; (text, reachable)."""
    parts = path.split(" ")[1:]
    done = subprocess.run([str(binary), *parts, "--help"], capture_output=True, text=True, errors="replace")
    if done.returncode != 0:
        line = done.stderr.strip().split("\n", 1)[0]
        return (line or f"exit status {done.returncode}"), False
    return done.stdout, True


def flag_names(help_text):
    names, in_options = set(), False
    for line in help_text.split("\n"):
        trimmed = line.strip()
        if trimmed in {"Options:", "Flags:"}:
            in_options = True
            continue
        if trimmed in {"Commands:", "Available Commands:", "Arguments:"}:
            in_options = False
            continue
        if not in_options or not line.startswith(" "):
            continue
        names.update(LONG_FLAG.findall(line))
    return names


def subcommands(help_text):
    names, in_commands = [], False
    for line in help_text.split("\n"):
        trimmed = line.strip()
        if trimmed in COMMAND_HEADINGS:
            in_commands = True
            continue
        if trimmed in OTHER_HEADINGS:
            in_commands = False
            continue
        if not in_commands or not line.startswith("  ") or trimmed == "":
            continue
        name = trimmed.split()[0]
        if name in {"help", "completion"}:
            continue
        names.append(name)
    return names


def rust_walk_all(binary, depth):
    seen = set()

    def walk(args):
        path = " ".join(["symvault", *args])
        if path in seen:
            return
        seen.add(path)
        if len(args) > depth:
            return
        text, ok = probe(binary, path)
        if not ok:
            return
        for command in subcommands(text):
            walk([*args, command])

    walk([])
    return seen


def alias_path(path, alias):
    parts = path.split(" ")
    parts[-1] = alias
    return " ".join(parts)


def run(args):
    binary = Path(args.binary)
    if not binary.exists():
        raise SystemExit(f"FAIL rust binary {binary}: not found (build it first: cargo build -p symvault-cli)")
    oracle = json.loads(Path(args.tree).read_bytes())
    absolute = Path(os.path.abspath(binary))
    stat = absolute.stat()
    report = {"schema_version": 1, "tool": "scripts/rust-port/cligap.py",
              "generated_at": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
              "rust_binary": str(absolute), "rust_binary_sha256": hashlib.sha256(absolute.read_bytes()).hexdigest(),
              "rust_binary_modified": datetime.datetime.fromtimestamp(stat.st_mtime, datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
              "oracle_tree": args.tree, "oracle_commit": oracle["oracle"]["commit"], "oracle_release": oracle["oracle"]["release"],
              "depth": args.depth}
    scoped = [c for c in oracle["commands"] if c["path"] != "symvault" and c["path"].count(" ") <= args.depth]
    report["oracle_paths"] = len(scoped)
    oracle_paths = {c["path"] for c in scoped}
    missing, flag_gaps, alias_gaps = [], [], []
    for command in scoped:
        text, reachable = probe(absolute, command["path"])
        if not reachable:
            missing.append({"path": command["path"], "detail": text})
            continue
        for alias in command.get("aliases") or []:
            if not probe(absolute, alias_path(command["path"], alias))[1]:
                alias_gaps.append({"path": command["path"], "detail": alias})
        present = flag_names(text)
        for name in sorted(f["name"] for f in command.get("local_flags") or [] if f["name"] != "help" and f["name"] not in present):
            flag_gaps.append({"path": command["path"], "detail": "--" + name})
    walked = rust_walk_all(absolute, args.depth)
    report["rust_paths"] = len(walked)
    report["missing_paths"], report["flag_gaps"], report["alias_gaps"] = missing, flag_gaps, alias_gaps
    report["rust_only_paths"] = sorted(p for p in walked if p != "symvault" and p not in oracle_paths)
    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2) + "\n")
    print(f"WROTE {out}")
    print(f"probed {absolute} (sha256 {report['rust_binary_sha256'][:12]}, built {report['rust_binary_modified']})")
    print(f"oracle paths {report['oracle_paths']}, rust paths {report['rust_paths']}, missing {len(missing)}, "
          f"flag gaps {len(flag_gaps)}, alias gaps {len(alias_gaps)}, rust-only {len(report['rust_only_paths'])}")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", default=str(Path("target") / "debug" / "symvault"))
    parser.add_argument("--tree", default=str(Path("testdata") / "port" / "cli" / "command-tree.json"))
    parser.add_argument("--output", default=str(Path("target") / "resume-evidence" / "cli-gap-inventory.json"))
    parser.add_argument("--depth", type=int, default=3)
    run(parser.parse_args(argv))


if __name__ == "__main__":
    main()
