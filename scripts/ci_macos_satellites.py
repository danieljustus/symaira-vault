#!/usr/bin/env python3
"""Select which HTTP-family macOS satellites a pull request can affect.

Used by .github/workflows/rust-http-macos.yml (select job, ubuntu-latest).

Fail-closed contract:
- Only ``pull_request`` events are filtered by changed files. Every other event
  (workflow_dispatch, anything unknown) selects all satellites, like the original
  per-workflow triggers did.
- Any error (git failure, unsupported glob syntax, truncated file list, bad
  arguments) selects all satellites. The workflow additionally treats missing
  outputs as "run".
- A satellite is selected when any changed file matches one of its patterns.
  Patterns are the satellite's original ``pull_request.paths`` (verbatim, from
  its workflow file at 895b1fe7) plus SHARED_INPUTS. SHARED_INPUTS adds the Rust
  inputs the family compiles and executes that the original lists omitted
  (crates/symvault-crypto, -gojson, -sync, third_party/argon2 via the path
  dependency chain, plus workspace manifests). The closure is computed from the
  workspace path dependencies; see scripts/test_ci_macos_satellites.py.

Usage:
  ci_macos_satellites.py select --event EVENT --base SHA --head SHA [--output FILE]
  ci_macos_satellites.py select --event EVENT --changed-file PATH ... [--output FILE]
"""
import argparse
import re
import subprocess
import sys

SATELLITES = {
    "head": [   '.github/workflows/rust-http-head.yml',
    'crates/symvault-cli/**',
    'crates/symvault-mcp/**',
    'crates/symvault-core/**',
    'crates/symvault-store/**',
    'crates/symvault-platform/**',
    'Cargo.lock',
    'internal/mcp/apitemplates/builtin/**',
    'scripts/rust-port/http_head_contract.py',
    'scripts/rust-port/http_oauth*',
    'scripts/rust-port/http_process*',
    'scripts/rust-port/mcp_process_contract.py',
    'scripts/rust-port/oracle_build.py',
    'scripts/rust-port/cmd/oraclebuild/**',
    'scripts/rust-port/internal/diff/**',
    'docs/adr/0021-http-head-responses-and-consent.md'],
    "origin": [   '.github/workflows/rust-http-origin.yml',
    'crates/symvault-cli/**',
    'crates/symvault-mcp/**',
    'crates/symvault-core/**',
    'crates/symvault-store/**',
    'crates/symvault-platform/**',
    'Cargo.lock',
    'internal/mcp/apitemplates/builtin/**',
    'scripts/rust-port/http_head_contract.py',
    'scripts/rust-port/http_origin_contract.py',
    'scripts/rust-port/http_oauth*',
    'scripts/rust-port/http_process*',
    'scripts/rust-port/mcp_process_contract.py',
    'docs/adr/0022-http-origin-authority-validation.md'],
    "oauth": [   '.github/workflows/rust-http-oauth.yml',
    'crates/symvault-cli/**',
    'crates/symvault-mcp/**',
    'crates/symvault-core/**',
    'crates/symvault-store/**',
    'crates/symvault-platform/**',
    'Cargo.lock',
    'internal/mcp/apitemplates/builtin/**',
    'scripts/rust-port/http_oauth*',
    'scripts/rust-port/http_process*',
    'scripts/rust-port/mcp_process_contract.py',
    'scripts/rust-port/oracle_build.py',
    'scripts/rust-port/test_oracle_build.py',
    'scripts/rust-port/cmd/oraclebuild/**',
    'scripts/rust-port/internal/diff/**',
    'docs/adr/0019-oauth-consent-binding-and-token-lifetimes.md'],
    "deadline": [   '.github/workflows/rust-http-read-deadlines.yml',
    'crates/symvault-cli/**',
    'crates/symvault-mcp/**',
    'crates/symvault-core/**',
    'crates/symvault-store/**',
    'crates/symvault-platform/**',
    'Cargo.lock',
    'internal/mcp/apitemplates/builtin/**',
    'scripts/rust-port/http_head_contract.py',
    'scripts/rust-port/http_framing_contract.py',
    'scripts/rust-port/http_slow_peer_contract.py',
    'scripts/rust-port/http_oauth*',
    'scripts/rust-port/http_process*',
    'scripts/rust-port/mcp_process_contract.py',
    'docs/adr/0024-absolute-http-input-read-deadlines.md'],
    "timeout": [   '.github/workflows/rust-http-timeouts.yml',
    'crates/symvault-cli/**',
    'crates/symvault-mcp/**',
    'crates/symvault-core/**',
    'crates/symvault-store/**',
    'crates/symvault-platform/**',
    'Cargo.lock',
    'internal/mcp/apitemplates/builtin/**',
    'scripts/rust-port/http_head_contract.py',
    'scripts/rust-port/http_framing_contract.py',
    'scripts/rust-port/http_slow_peer_contract.py',
    'scripts/rust-port/http_timeout_contract.py',
    'scripts/rust-port/http_oauth*',
    'scripts/rust-port/http_process*',
    'scripts/rust-port/mcp_process_contract.py',
    'docs/adr/0026-http-transport-timeout-options.md'],
    "write": [   '.github/workflows/rust-http-write.yml',
    'crates/symvault-cli/**',
    'crates/symvault-mcp/**',
    'crates/symvault-core/**',
    'crates/symvault-store/**',
    'crates/symvault-platform/**',
    'Cargo.lock',
    'internal/mcp/apitemplates/builtin/**',
    'scripts/rust-port/http_head_contract.py',
    'scripts/rust-port/http_framing_contract.py',
    'scripts/rust-port/http_slow_peer_contract.py',
    'scripts/rust-port/http_timeout_contract.py',
    'scripts/rust-port/http_tls_contract.py',
    'scripts/rust-port/http_tls_identity.go.txt',
    'scripts/rust-port/http_write_contract.py',
    'scripts/rust-port/http_write_mutation.py',
    'scripts/rust-port/test_http_write_contract.py',
    'scripts/rust-port/http_winsock_metadata.py',
    'scripts/rust-port/http_winsock_stop.cpp',
    'scripts/rust-port/http_oauth*',
    'scripts/rust-port/http_process*',
    'scripts/rust-port/mcp_process_contract.py',
    'scripts/rust-port/oracle_build.py',
    'scripts/rust-port/test_oracle_build.py',
    'scripts/rust-port/cmd/oraclebuild/**',
    'scripts/rust-port/internal/diff/**',
    'docs/adr/0027-absolute-http-write-deadlines.md'],
    "framing": [   '.github/workflows/rust-http-framing.yml',
    'crates/symvault-cli/**',
    'crates/symvault-mcp/**',
    'crates/symvault-core/**',
    'crates/symvault-store/**',
    'crates/symvault-platform/**',
    'Cargo.lock',
    'internal/mcp/apitemplates/builtin/**',
    'scripts/rust-port/http_head_contract.py',
    'scripts/rust-port/http_framing_contract.py',
    'scripts/rust-port/http_oauth*',
    'scripts/rust-port/http_process*',
    'scripts/rust-port/mcp_process_contract.py',
    'docs/adr/0023-bounded-chunked-request-framing.md'],
    "tls": [   '.github/workflows/rust-http-tls.yml',
    'crates/symvault-cli/**',
    'crates/symvault-mcp/**',
    'crates/symvault-core/**',
    'crates/symvault-store/**',
    'crates/symvault-platform/**',
    'Cargo.lock',
    'internal/mcp/apitemplates/builtin/**',
    'scripts/rust-port/http_head_contract.py',
    'scripts/rust-port/http_framing_contract.py',
    'scripts/rust-port/http_origin_contract.py',
    'scripts/rust-port/http_tls*',
    'scripts/rust-port/http_oauth*',
    'scripts/rust-port/http_process*',
    'scripts/rust-port/mcp_process_contract.py',
    'docs/adr/0025-live-tls-and-client-identity-proof.md'],
}

SHARED_INPUTS = [   'Cargo.toml',
    'Cargo.lock',
    'rust-toolchain.toml',
    '.gitattributes',
    'crates/**',
    'third_party/**',
    '.github/workflows/rust-http-macos.yml',
    'scripts/ci_macos_satellites.py',
    'scripts/test_ci_macos_satellites.py']

# GitHub truncates pull request file lists at 3000 entries; a truncated list
# cannot prove the absence of a relevant change.
MAX_CHANGED_FILES = 3000

ORDER = ["head", "origin", "oauth", "deadline", "timeout", "write", "framing", "tls"]


def glob_to_regex(pattern):
    """Translate a GitHub `paths` glob (`*`, `?`, `**`) to a full-match regex.

    Patterns using brackets, braces or negation are rejected so that the caller
    falls back to selecting every satellite instead of mis-matching them.
    """
    if any(ch in pattern for ch in "[]{}!"):
        raise ValueError(f"unsupported glob syntax: {pattern}")
    out = []
    i = 0
    while i < len(pattern):
        if pattern.startswith("**/", i):
            out.append("(?:.*/)?")
            i += 3
        elif pattern.startswith("**", i):
            out.append(".*")
            i += 2
        elif pattern[i] == "*":
            out.append("[^/]*")
            i += 1
        elif pattern[i] == "?":
            out.append("[^/]")
            i += 1
        else:
            out.append(re.escape(pattern[i]))
            i += 1
    return re.compile("^" + "".join(out) + "$")


def patterns_for(key):
    return list(SATELLITES[key]) + list(SHARED_INPUTS)


def select_all():
    return {key: True for key in ORDER}


def select(event, changed):
    """Return {satellite: bool}. Raises on any condition that cannot be decided."""
    if event != "pull_request":
        return select_all()
    if changed is None:
        raise ValueError("pull_request selection requires a changed-file list")
    if len(changed) >= MAX_CHANGED_FILES:
        raise ValueError("changed-file list may be truncated")
    result = {}
    for key in ORDER:
        regexes = [glob_to_regex(p) for p in patterns_for(key)]
        result[key] = any(rx.match(path) for path in changed for rx in regexes)
    return result


def changed_files_from_git(base, head):
    proc = subprocess.run(
        ["git", "diff", "--name-only", "--no-renames", f"{base}...{head}"],
        check=True, capture_output=True, text=True)
    return [line for line in proc.stdout.splitlines() if line]


def write_output(event, decisions, path):
    lines = [f"any={'true' if any(decisions.values()) else 'false'}"]
    lines += [f"{key}={'true' if decisions[key] else 'false'}" for key in ORDER]
    text = "\n".join(lines) + "\n"
    if path:
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(text)
    else:
        sys.stdout.write(text)


def main(argv=None):
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="cmd", required=True)
    sel = sub.add_parser("select")
    sel.add_argument("--event", required=True)
    sel.add_argument("--base")
    sel.add_argument("--head")
    sel.add_argument("--changed-file", action="append", default=None)
    sel.add_argument("--output")
    args = parser.parse_args(argv)
    try:
        if args.event != "pull_request":
            decisions = select(args.event, None)
        elif args.changed_file is not None:
            decisions = select("pull_request", args.changed_file)
        else:
            if not args.base or not args.head:
                raise ValueError("pull_request needs --base and --head")
            decisions = select("pull_request", changed_files_from_git(args.base, args.head))
    except Exception as exc:  # fail closed: every satellite runs
        print(f"selector fell back to all satellites: {exc}", file=sys.stderr)
        decisions = select_all()
    write_output(args.event, decisions, args.output)
    return 0


if __name__ == "__main__":
    sys.exit(main())
