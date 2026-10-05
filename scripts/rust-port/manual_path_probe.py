#!/usr/bin/env python3
"""Diagnose path substitution against the real immutable Go CLI (no snapshots)."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess


PIN = "55da4ca13ead39d4000cf6f866ac8671ca86d8f2"
ROOT = Path(__file__).resolve().parents[2]


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(binary, directory, config):
    home = directory / "home"
    home.mkdir(parents=True, exist_ok=True)
    env = {key: value for key, value in os.environ.items()
           if not key.upper().startswith("SYMVAULT_")}
    env.update(HOME=str(home), USERPROFILE=str(home),
               XDG_CONFIG_HOME=str(config), XDG_DATA_HOME=str(home / "data"),
               XDG_CACHE_HOME=str(home / "cache"), SYMVAULT_TEST_KEYRING="memory",
               TZ="UTC", SOURCE_DATE_EPOCH="0")
    result = subprocess.run([str(binary), "generate", "manpages", "man"],
                            cwd=directory, env=env, capture_output=True, timeout=120)
    (directory / "stdout.bin").write_bytes(result.stdout)
    (directory / "stderr.bin").write_bytes(result.stderr)
    assert result.returncode == 0 and not result.stderr, (result.returncode, result.stderr)
    pages = {path.name: path.read_bytes() for path in (directory / "man").glob("*.1")}
    assert len(pages) == 119, len(pages)
    return pages


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--go", type=Path, required=True)
    parser.add_argument("--oracle-tree", type=Path, required=True)
    parser.add_argument("--rust", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output = args.output.resolve()
    # git archive snapshots have no Git directory: compare every production
    # byte with the immutable object instead of trusting a caller label.
    files = subprocess.check_output(["git", "ls-tree", "-r", "--name-only", PIN],
                                    cwd=ROOT, text=True).splitlines()
    files = sorted(path for path in files if path in {"go.mod", "go.sum"}
                   or (path.endswith(".go") and not path.endswith("_test.go")))
    digest = hashlib.sha256()
    for path in files:
        actual = (args.oracle_tree / path).read_bytes()
        expected = subprocess.check_output(["git", "show", f"{PIN}:{path}"], cwd=ROOT)
        assert actual == expected, path
        digest.update(path.encode() + b"\0" + actual + b"\0")
    args.output.mkdir(parents=True, exist_ok=False)
    cases = ["ordinary", "s__b0nk", "a_b_c", "a__b__c", "a`b`c", "a[b](c)d",
             "a![b](c)d", "a&amp;b", "a<b>c", "a*b*c", "a**b**c", "a\\_b_c"]
    if os.name == "nt":
        # Windows filename restrictions are not Markdown compatibility.
        cases = [case for case in cases if not any(char in case for char in '<>*\\')]
    observations = []
    baseline = json.loads((ROOT / "testdata/port/cli/artifacts.json").read_bytes())
    for index, case in enumerate(cases):
        directory = args.output / str(index)
        directory.mkdir()
        config = args.output / "config-roots" / case
        go_pages = run(args.go.resolve(), directory, config)
        page = go_pages["symvault-mcp.1"].decode("utf-8")
        start = page.index("(default: ") + len("(default: ")
        end = page.index("; existing installs", start)
        rendered = page[start:end]
        literal = str(config / "symaira-vault/config.yaml").replace("\\", "\\\\")
        observation = {"case": case, "config_path": str(config / "symaira-vault/config.yaml"),
                       "actual_go_roff": rendered, "literal_roff": literal,
                       "literal_substitution_matches_go": rendered == literal,
                       "manual_count": len(go_pages)}
        if args.rust:
            rust_dir = directory / "rust"
            rust_dir.mkdir()
            rust_pages = run(args.rust.resolve(), rust_dir, config)
            observation["go_rust_equal"] = go_pages == rust_pages
            observation["different_pages"] = sorted(name for name in go_pages
                                                     if go_pages[name] != rust_pages.get(name))
        normalized = page.replace(literal, "__CONFIG_PATH__")
        observation["current_normalizer_matches_golden"] = normalized == baseline["manpages"]["symvault-mcp.1"]
        observations.append(observation)
    report = {"oracle_commit": PIN, "oracle_source_files": files,
              "oracle_source_digest": digest.hexdigest(), "probe_sha256": sha256(Path(__file__)),
              "go_binary_sha256": sha256(args.go), "cases": observations}
    if args.rust:
        report["rust_binary_sha256"] = sha256(args.rust)
    (args.output / "report.json").write_bytes((json.dumps(report, indent=2) + "\n").encode())
    for observation in observations:
        print(json.dumps(observation))
    assert observations[0]["literal_substitution_matches_go"], "ordinary control must match"
    assert observations[1]["literal_substitution_matches_go"], "Unix single underscore control must match"
    assert not observations[3]["literal_substitution_matches_go"], "strong emphasis defect must reproduce"
    print("Confirmed ordinary/Unix underscore controls and Markdown path defects; not parity acceptance")


if __name__ == "__main__":
    main()
