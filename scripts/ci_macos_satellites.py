#!/usr/bin/env python3
"""Select which HTTP-family macOS satellites a pull request can affect.

Used by .github/workflows/rust-http-macos.yml (group "http") and
.github/workflows/rust-macos-satellites.yml (groups "mcp", "broker", "rest"); both select
jobs run on ubuntu-latest. Outputs: one key per satellite plus group_<name> per group.

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

# Consolidated PR macOS groups (.github/workflows/rust-macos-satellites.yml).
# Each entry is the satellite's original pull_request.paths verbatim at 895b1fe7
# (scripts/ci_macos_satellites_baseline.json). These satellites keep their original
# path coverage; the group workflow and this selector's own inputs select every group.
GROUP_WORKFLOW_INPUTS = [
    '.github/workflows/rust-macos-satellites.yml',
    'scripts/ci_macos_satellites.py',
    'scripts/test_ci_macos_satellites.py',
    'scripts/ci_macos_satellites_baseline.json',
]
GROUP_SATELLITES = {
    "mcp_process": [  # rust-mcp-process.yml
        ".github/workflows/rust-mcp-process.yml",
        "Makefile",
        "crates/**",
        "Cargo.toml",
        "Cargo.lock",
        ".gitattributes",
        "testdata/**",
        "third_party/**",
        "internal/mcp/apitemplates/builtin/**",
        "scripts/rust-port/mcp_process*",
        "scripts/rust-port/mcp_oracle.py",
        "scripts/rust-port/mcp_fixture_contract.py",
        "scripts/rust-port/test_mcp_oracle.py",
        "scripts/rust-port/cmd/mcpcallgen/**",
        "scripts/rust-port/cmd/http001initgen/**",
        "scripts/rust-port/cmd/execute_secret_*/*",
        "scripts/rust-port/internal/provenance/**",
        "scripts/rust-port/internal/oracletest/**",
        "go.mod",
        "go.sum",
        "scripts/rust-port/fixtures/mcp-anomaly/**",
        "internal/mcp/server/**",
        "docs/adr/0016-mcp-discovery-and-call-authorization.md",
    ],
    "mcp_http_process": [  # rust-mcp-http-process.yml
        ".github/workflows/rust-mcp-http-process.yml",
        "crates/**",
        "third_party/**",
        "Cargo.toml",
        "Cargo.lock",
        ".gitattributes",
        "internal/mcp/apitemplates/builtin/**",
        "scripts/rust-port/http_process*",
        "scripts/rust-port/test_http_process_contract.py",
        "testdata/**",
        "scripts/rust-port/mcp_process_contract.py",
        "scripts/rust-port/mcp_oracle.py",
        "docs/adr/0017-http-wire-contract-and-token-sessions.md",
    ],
    "mcp_http_shutdown": [  # mcp-http-shutdown.yml
        ".github/workflows/mcp-http-shutdown.yml",
        "internal/mcp/**",
        "internal/secureui/**",
        "internal/approval/**",
        "internal/policy/**",
        "internal/vault/**",
        "docs/adr/0009-http-shutdown-ownership.md",
    ],
    "broker_connect": [  # rust-broker-connect.yml
        ".github/workflows/rust-broker-connect.yml",
        "crates/symvault-mcp/**",
        "crates/symvault-platform/**",
        "Cargo.lock",
        "scripts/rust-port/connect_contract*",
        "docs/adr/0014-connect-socket-and-relay-ownership.md",
    ],
    "broker_egress": [  # rust-broker-egress.yml
        ".github/workflows/rust-broker-egress.yml",
        "crates/**",
        "Cargo.toml",
        "Cargo.lock",
        ".gitattributes",
        "testdata/**",
        "third_party/**",
        "internal/mcp/apitemplates/builtin/**",
        "scripts/rust-port/cmd/cligap/**",
        "scripts/rust-port/egress_contract*",
        "scripts/rust-port/http_tls_identity.go.txt",
        "docs/adr/0015-egress-broker-runtime-boundaries.md",
    ],
    "audit": [  # rust-audit.yml
        ".github/workflows/rust-audit.yml",
        ".github/workflows/ci.yml",
        "Cargo.toml",
        "Cargo.lock",
        "go.mod",
        "go.sum",
        "rust-toolchain.toml",
        "Makefile",
        "crates/symvault-store/Cargo.toml",
        "crates/symvault-store/src/audit.rs",
        "crates/symvault-store/tests/audit.rs",
        "crates/symvault-store/examples/audit-emit.rs",
        "internal/audit/**",
        "scripts/rust-port/cmd/auditverify/**",
        "testdata/port/audit/**",
        "docs/rust-port/contract-matrix.md",
        "docs/rust-port/work-items.json",
    ],
    "api_transport": [  # rust-api-transport.yml
        ".github/workflows/rust-api-transport.yml",
        "crates/**",
        "Cargo.toml",
        "Cargo.lock",
        ".cargo/**",
        "rust-toolchain.toml",
        ".gitattributes",
        "internal/mcp/apitemplates/builtin/**",
        "scripts/rust-port/api_transport*",
        "scripts/rust-port/test_api_transport_contract.py",
        "testdata/api-darwin-trust/**",
        "docs/adr/0018-api-dns-pinning-and-request-cancellation.md",
        "docs/adr/0028-owned-broker-dns-and-dial.md",
    ],
    "cli_artifacts": [  # rust-cli-artifacts.yml
        ".github/workflows/rust-cli-artifacts.yml",
        "crates/**",
        "Cargo.toml",
        "Cargo.lock",
        ".gitattributes",
        "**.go",
        "go.mod",
        "go.sum",
        "scripts/rust-port/cli_artifacts*",
        "scripts/rust-port/test_cli_artifacts_contract.py",
        "scripts/rust-port/manual_path*",
        "scripts/rust-port/cmd/portgen/**",
        "scripts/rust-port/cmd/cligap/**",
        "testdata/**",
        "third_party/**",
        "docs/adr/0011-cli-artifacts-and-completion-protocol.md",
    ],
    "intake_cli": [  # rust-intake-cli.yml
        ".github/workflows/rust-intake-cli.yml",
        "crates/symvault-cli/**",
        "crates/symvault-sync/**",
        "crates/symvault-store/**",
        "crates/symvault-platform/**",
        "Cargo.lock",
        "scripts/rust-port/intake_watch_contract.py",
        "internal/intake/**",
        "cmd/intake/**",
        "docs/adr/0010-intake-polling-and-quarantine.md",
    ],
    "serve_cli": [  # rust-serve-cli.yml
        ".github/workflows/rust-serve-cli.yml",
        "crates/**",
        "Cargo.toml",
        "Cargo.lock",
        ".gitattributes",
        "testdata/**",
        "third_party/**",
        "internal/mcp/apitemplates/builtin/**",
        "scripts/rust-port/serve_contract.py",
        "docs/adr/0013-deprecated-serve-and-locked-stdio.md",
    ],
    "kdf_policy": [  # kdf-resource-policy.yml
        ".github/workflows/kdf-resource-policy.yml",
        "internal/crypto/**",
        "internal/vault/**",
        "internal/config/**",
        "cmd/admin/migrate.go",
        "crates/symvault-crypto/**",
        "crates/symvault-cli/src/migrate_kdf_commands*",
        "crates/symvault-cli/src/main.rs",
        "crates/symvault-cli/tests/migrate_kdf_differential.rs",
        "scripts/rust-port/*kdf*",
        "scripts/rust-port/check_argon2_upstream.py",
        "testdata/port/crypto/kdf-policy-v1.json",
        "third_party/argon2/**",
        "Cargo.toml",
        "Cargo.lock",
        "Makefile",
    ],
    "vault_read_policy": [  # vault-read-resource-policy.yml
        ".github/workflows/vault-read-resource-policy.yml",
        "scripts/rust-port/cmd/entrypolicygen/**",
        "scripts/rust-port/refresh-read-policy-fixtures.py",
        "testdata/port/store/read-resource-policy.json",
        "cmd/**",
        "internal/cli/**",
        "internal/ui/**",
        "internal/secrets/**",
        "docs/adr/0008-vault-read-resource-policy.md",
        "crates/symvault-cli/tests/fixtures/import-review/**",
        "internal/vault/**",
        "internal/template/**",
        "internal/mcp/server/**",
        "crates/symvault-store/**",
        "crates/symvault-cli/src/**",
        "crates/symvault-mcp/src/**",
    ],
    "store_observations": [  # rust-store-observations.yml
        ".github/workflows/rust-store-observations.yml",
        "scripts/rust-port/cmd/storegen/**",
        "testdata/port/store/store.json",
        "docs/rust-port/store-normalization.md",
    ],
    "sync_observations": [  # rust-sync-observations.yml
        ".github/workflows/rust-sync-observations.yml",
        "scripts/rust-port/cmd/syncgen/**",
        "scripts/rust-port/cmd/gitio/**",
        "crates/symvault-sync/**",
        "testdata/port/sync/*.json",
        "docs/rust-port/windows-sync-oracle.md",
        "cmd/admin/backup*.go",
    ],
}

# GitHub truncates pull request file lists at 3000 entries; a truncated list
# cannot prove the absence of a relevant change.
MAX_CHANGED_FILES = 3000

ORDER = ["head", "origin", "oauth", "deadline", "timeout", "write", "framing", "tls"]

# "http" is rust-http-macos.yml (ORDER). The other groups are rust-macos-satellites.yml.
# A group job runs when any of its members is selected.
GROUPS = {
    "http": list(ORDER),
    "mcp": ["mcp_process", "mcp_http_process", "mcp_http_shutdown"],
    "broker": ["broker_connect", "broker_egress"],
    # cli_artifacts is last: it exports CLI_ARTIFACTS_BASH through $GITHUB_ENV.
    "rest": ["intake_cli", "serve_cli", "api_transport", "kdf_policy", "vault_read_policy",
             "store_observations", "sync_observations", "audit", "cli_artifacts"],
}
ALL_KEYS = list(ORDER) + list(GROUP_SATELLITES)
OUTPUT_KEYS = ALL_KEYS + ["group_" + name for name in GROUPS]
assert sorted(k for name, members in GROUPS.items() if name != "http" for k in members) == sorted(GROUP_SATELLITES)


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
    if key in SATELLITES:
        return list(SATELLITES[key]) + list(SHARED_INPUTS)
    return list(GROUP_SATELLITES[key]) + list(GROUP_WORKFLOW_INPUTS)


def select_all():
    return {key: True for key in OUTPUT_KEYS}


def select(event, changed):
    """Return {satellite or group_<name>: bool}. Raises on any undecidable condition."""
    if event != "pull_request":
        return select_all()
    if changed is None:
        raise ValueError("pull_request selection requires a changed-file list")
    if len(changed) >= MAX_CHANGED_FILES:
        raise ValueError("changed-file list may be truncated")
    result = {}
    for key in ALL_KEYS:
        regexes = [glob_to_regex(p) for p in patterns_for(key)]
        result[key] = any(rx.match(path) for path in changed for rx in regexes)
    for name, members in GROUPS.items():
        result["group_" + name] = any(result[k] for k in members)
    return result


def changed_files_from_git(base, head):
    proc = subprocess.run(
        ["git", "diff", "--name-only", "--no-renames", f"{base}...{head}"],
        check=True, capture_output=True, text=True)
    return [line for line in proc.stdout.splitlines() if line]


def write_output(event, decisions, path):
    lines = [f"any={'true' if any(decisions.values()) else 'false'}"]
    lines += [f"{key}={'true' if decisions[key] else 'false'}" for key in OUTPUT_KEYS]
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
