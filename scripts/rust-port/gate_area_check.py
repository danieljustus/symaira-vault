#!/usr/bin/env python3
"""Post-run assertions for the local gate's area process contracts.

The hosted area workflows follow each contract run with inline `python3 - <<PY`
receipt checks. The local gate (docs/rust-port/local-first.md) runs the same
contracts through Makefile targets and uses this script for the checks that are
independent of the workflow's fixed counts:

  receipt PATH [--parity A:B[:MIN] ...]   contract receipt: passed, clean tree
                                          before and after, candidate commit is
                                          HEAD, no recorded differences; each
                                          parity pair has equal, non-empty case
                                          name sets (at least MIN cases)
  gaps PATH [--prefix P ...]              cligap report: no missing path, flag gap
      [--no-missing-paths]                or alias gap at or under a prefix;
      [--min-paths ORACLE:RUST]           --no-missing-paths: none at all
  go-json PATH NAME...                    `go test -json` output: every NAME
                                          passed and none was skipped
  go-text-pass PATH NAME...               `go test -v` text: `--- PASS: NAME`
  log-ok PATH NAME...                     cargo test log: `test ...NAME ... ok`

Exit status 0 only when every assertion holds.
"""
import argparse
import json
import re
import subprocess
import sys
from pathlib import Path


def fail(message):
    print(f"gate_area_check: FAIL: {message}", file=sys.stderr)
    sys.exit(1)


def head():
    return subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()


def receipt(args):
    data = json.loads(Path(args.path).read_bytes())
    if data.get("passed") is not True:
        fail(f"{args.path}: passed is not true")
    for key in ("candidate_worktree_clean", "candidate_worktree_clean_at_end"):
        if key in data and data[key] is not True:
            fail(f"{args.path}: {key} is {data[key]!r}")
    if "candidate_commit" in data and data["candidate_commit"] != head():
        fail(f"{args.path}: candidate_commit {data['candidate_commit']} is not HEAD")
    if data.get("differences"):
        fail(f"{args.path}: undeclared differences recorded")
    for pair in args.parity or []:
        left, right, *minimum = pair.split(":")
        names = [{row["case"] for row in data[key]} for key in (left, right)]
        if not names[0] or names[0] != names[1]:
            fail(f"{args.path}: case sets of {left} and {right} differ: "
                 f"{sorted(names[0] ^ names[1])}")
        if minimum and len(names[0]) < int(minimum[0]):
            fail(f"{args.path}: {left} has {len(names[0])} cases, need {minimum[0]}")
    print(f"gate_area_check: ok {args.path}")


def gaps(args):
    data = json.loads(Path(args.path).read_bytes())
    if args.no_missing_paths and data.get("missing_paths"):
        fail("every Go help path must be reachable; missing_paths not empty")
    for kind in ["missing_paths", "flag_gaps", "alias_gaps"] if args.prefix else []:
        for gap in data.get(kind) or []:
            if any(gap["path"] == p or gap["path"].startswith(p + " ") for p in args.prefix):
                fail(f"{kind}: {gap['path']}")
    if args.min_paths:
        oracle, rust = (int(x) for x in args.min_paths.split(":"))
        if data["oracle_paths"] < oracle or data["rust_paths"] < rust:
            fail(f"paths oracle={data['oracle_paths']} rust={data['rust_paths']}")
    print(f"gate_area_check: ok {args.path}")


def go_json(args):
    rows = [json.loads(line) for line in Path(args.path).read_text().splitlines() if line.startswith("{")]
    passed = {row.get("Test") for row in rows if row.get("Action") == "pass"}
    skipped = {row.get("Test") for row in rows if row.get("Action") == "skip"}
    required = set(args.names)
    if not required <= passed:
        fail(f"required Go tests did not pass: {sorted(required - passed)}")
    if required & skipped:
        fail(f"required Go tests skipped: {sorted(required & skipped)}")
    if any(row.get("Action") == "fail" for row in rows):
        fail("go test -json reports a failing test")
    print(f"gate_area_check: ok {args.path} ({len(required)} required tests)")


def go_text_pass(args):
    text = Path(args.path).read_text()
    for name in args.names:
        if f"--- PASS: {name} " not in text:
            fail(f"{args.path}: no `--- PASS: {name}`")
    print(f"gate_area_check: ok {args.path} ({len(args.names)} required tests)")


def log_ok(args):
    text = Path(args.path).read_text()
    for name in args.names:
        if not re.search(r"test .*" + re.escape(name) + r" \.\.\. ok", text):
            fail(f"{args.path}: no `{name} ... ok`")
    print(f"gate_area_check: ok {args.path} ({len(args.names)} required tests)")


def main():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("receipt"); p.add_argument("path"); p.add_argument("--parity", action="append")
    p.set_defaults(run=receipt)
    p = sub.add_parser("gaps"); p.add_argument("path"); p.add_argument("--prefix", action="append")
    p.add_argument("--no-missing-paths", action="store_true"); p.add_argument("--min-paths")
    p.set_defaults(run=gaps)
    p = sub.add_parser("go-json"); p.add_argument("path"); p.add_argument("names", nargs="+")
    p.set_defaults(run=go_json)
    p = sub.add_parser("go-text-pass"); p.add_argument("path"); p.add_argument("names", nargs="+")
    p.set_defaults(run=go_text_pass)
    p = sub.add_parser("log-ok"); p.add_argument("path"); p.add_argument("names", nargs="+")
    p.set_defaults(run=log_ok)
    args = parser.parse_args()
    args.run(args)


if __name__ == "__main__":
    main()
