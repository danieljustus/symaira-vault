#!/usr/bin/env python3
"""Post-run assertions for the local gate's area process contracts.

The hosted area workflows follow each contract run with inline `python3 - <<PY`
receipt checks that assert exact case counts, declared-difference counts,
required case names and per-process invariants. This script ports those checks
one for one (Linux/Darwin values; the Windows-only branches are dropped), so a
shrunken, partial or malformed receipt cannot pass the local gate.

  receipt PATH [--profile NAME]      contract receipt. Always required, never
                                     defaulted: `passed` is true, clean tree
                                     before (and, unless the workflow did not
                                     assert it, after) the run, `candidate_commit`
                                     is HEAD, `native_os` is this host's OS. A
                                     missing key fails. --profile adds the
                                     workflow's own counts and names (PROFILES).
  profiles                           list the profile names.
  gaps PATH [--prefix P ...]         cligap report: no gap at a path that starts
      [--exact-path P ...]           with a prefix or equals an exact path;
      [--no-missing-paths]           --no-missing-paths: none at all;
      [--min-paths ORACLE:RUST]      --min-paths: at least that many paths.
  go-json PATH NAME...               `go test -json`: every NAME passed, none was
                                     skipped, nothing failed.
  go-text-pass PATH NAME...          `go test -v` text: `--- PASS: NAME`
  log-ok PATH NAME...                cargo test log: `test ...NAME ... ok`;
      [--exact-prefix P]             exactly `test P<NAME> ... ok`;
      [--contains TEXT ...]          the log contains each TEXT;
      [--sum-passed N]               the `test result: ok. N passed; 0 failed;
                                     0 ignored` lines add up to N;
      [--results-ok]                 at least one result line, none failing, none
                                     ignored, a non-zero total.

Exit status 0 only when every assertion holds; any missing key, wrong type or
wrong count is a failure (exit 1), never a crash that could be mistaken for one.
"""
import argparse
import hashlib
import json
import platform
import re
import subprocess
import sys
from pathlib import Path
from typing import NoReturn

HERE = Path(__file__).resolve().parent
RESULT = re.compile(r"test result: ok\. (\d+) passed; 0 failed; (\d+) ignored")


class Check(Exception):
    """An assertion about a receipt or log did not hold."""


def fail(message) -> NoReturn:
    print(f"gate_area_check: FAIL: {message}", file=sys.stderr)
    sys.exit(1)


def head():
    return subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()


def need(condition, what):
    if not condition:
        raise Check(what)


def eq(value, expected, what):
    need(value == expected, f"{what}: {value!r}, expected {expected!r}")


def size(sequence, expected, what):
    need(isinstance(sequence, (list, tuple, dict, set)), f"{what}: not a collection: {sequence!r}")
    need(len(sequence) == expected, f"{what}: {len(sequence)} entries, expected {expected}")


def at_least(value, minimum, what):
    need(isinstance(value, (int, float)) and not isinstance(value, bool) and value >= minimum,
         f"{what}: {value!r}, expected >= {minimum}")


def names(rows, key, what):
    need(isinstance(rows, list), f"{what}: not a list")
    return {row[key] for row in rows}


def flat(groups):
    return [row for group in groups for row in group]


def worktree_clean():
    status = subprocess.check_output(["git", "status", "--porcelain=v1", "--untracked-files=normal"])
    need(not status.strip(), "git status is not clean")


def processes_ok(processes, expected, what):
    size(processes, expected, what)
    need(all(p["output_capture_complete"] and not p["output_capture_errors"]
             and p["forced_cleanup_not_graceful_evidence"] for p in processes),
         f"{what}: output capture or forced-cleanup evidence incomplete")


def last_ping(rows, case, what):
    eq(rows[-1]["case"], case, f"{what} last case")
    eq(rows[-1]["response"]["status_line"], "HTTP/1.1 200 OK", f"{what} last status line")


def decisions(receipt, count, expected):
    size(receipt["declared_differences"], count, "declared_differences")
    eq({d["decision"] for d in receipt["declared_differences"]}, expected, "declared decisions")


def both(receipt):
    return [(name, receipt[name]) for name in ("go", "rust")]


# ---- HTTP contracts (rust-http-*.yml, rust-http-macos.yml) ----------------

def http_framing(r):
    decisions(r, 18, {"security-metadata-stays-in-headers", "framing-validation-before-dispatch",
                      "complete-chunk-frame-required", "one-request-length-required", "chunked-requires-http11"})
    for impl, o in both(r):
        size(o["rows"], 33, f"{impl} rows")
        size(names(o["rows"], "case", impl), 33, f"{impl} distinct cases")
        size(o["pipeline"]["responses"], 2, f"{impl} pipeline responses")
        processes_ok(o["processes"], 1, f"{impl} processes")
        last_ping(o["rows"], "recovery-ping", impl)


def http_head(r):
    for impl, o in both(r):
        size(o["rows"], 13, f"{impl} rows")
        size(o["authorization_heads"], 512, f"{impl} authorization heads")
        size(o["pipeline"]["responses"], 2, f"{impl} pipeline responses")
        processes_ok(o["processes"], 1, f"{impl} processes")
        eq(o["browser_control"]["status_line"], "HTTP/1.1 200 OK", f"{impl} browser control")


def http_origin(r):
    decisions(r, 69, {"serialized-http-origin-required", "loopback-host-required",
                      "valid-loopback-authority-required"})
    for impl, o in both(r):
        size(o["rows"], 202, f"{impl} rows")
        size(names(o["rows"], "case", impl), 202, f"{impl} distinct cases")
        processes_ok(o["processes"], 1, f"{impl} processes")
        last_ping(o["rows"], "recovery-ping", impl)


TERMINATIONS = {"actual-empty-eof-or-reset", "complete-go-json-error-before-write-deadline"}


def slow_peer(peer, what):
    need(peer["sender_joined"] and peer["peer_terminal_observed"] and not peer["forced_client_close"],
         f"{what}: peer not joined/observed or client closed by force")
    at_least(peer["sent_progress_bytes"], 4, f"{what} sent_progress_bytes")
    need(peer["termination"] in TERMINATIONS, f"{what}: termination {peer['termination']!r}")


def http_read_deadlines(r):
    need(not r["declared_differences"], "declared_differences must be empty")
    for impl, o in both(r):
        size(o["rows"], 3, f"{impl} rows")
        eq(names(o["rows"], "case", impl), {"initialize", "ping-before", "ping-after"}, f"{impl} row cases")
        size(o["slow_peers"], 2, f"{impl} slow peers")
        eq(names(o["slow_peers"], "case", impl), {"progressing-header", "progressing-body"}, f"{impl} slow peer cases")
        need(o["workers_joined"] and not o["control_errors"], f"{impl}: workers not joined or control errors")
        for peer in o["slow_peers"]:
            slow_peer(peer, f"{impl} {peer['case']}")
            need(peer["peer_terminal_kind"] in {"eof", "connection-reset"}, f"{impl}: peer_terminal_kind")
        size(o["idle_boundary"]["responses"], 2, f"{impl} idle responses")
        at_least(o["idle_boundary"]["idle_wait_seconds"], 6, f"{impl} idle_wait_seconds")
        processes_ok(o["processes"], 1, f"{impl} processes")


def http_timeouts(r):
    need(not r["declared_differences"], "declared_differences must be empty")
    profiles = {"positive", "zero", "negative"}
    eq(set(r["profiles"]), profiles, "profiles")
    for impl in ("go", "rust"):
        size(r["invalid_config"][impl], 2, f"{impl} invalid_config")
        for row in r["invalid_config"][impl]:
            expected = 6  # Rust ported Go ExitConfigError for mcp serve (c44e6c45)
            need(row["exit"] == row["expected_exit"] == expected, f"{impl} invalid_config exit {row['exit']!r}")
            need(not row["forced_cleanup"] and row["output_capture_complete"] and not row["output_capture_errors"],
                 f"{impl} invalid_config capture")
    for impl, o in both(r):
        eq(set(o), profiles, f"{impl} profiles")
        size(flat(p["rows"] for p in o.values()), 9, f"{impl} rows")
        size(flat(p["slow_peers"] for p in o.values()), 6, f"{impl} slow peers")
        for profile, p in o.items():
            what = f"{impl} {profile}"
            size(p["rows"], 3, f"{what} rows")
            processes_ok(p["processes"], 1, f"{what} processes")
            need(p["workers_joined"] and not p["control_errors"], f"{what}: workers/control errors")
            size(p["slow_peers"], 2, f"{what} slow peers")
            for peer in p["slow_peers"]:
                slow_peer(peer, what)
            at_least(p["idle_boundary"]["idle_wait_seconds"], 6, f"{what} idle_wait_seconds")
            size(p["idle_boundary"]["responses"], 2, f"{what} idle responses")
            last_ping(p["rows"], "ping-after", what)


# ADR 0034 item 20 (ratified): Rust negotiates no ALPN protocol; Go's plain-TLS listener selects `h2` for any offer
# containing it and `http/1.1` for an HTTP/1.1-only offer, its mTLS listener selects nothing. Written out here, not
# imported from the driver, so editing the driver cannot silently weaken the pin.
ALPN_OFFERS = [("h2-and-http11", ["h2", "http/1.1"]), ("http11-only", ["http/1.1"]), ("h2-only", ["h2"])]
ALPN_GO = {"tls": {"h2-and-http11": "h2", "http11-only": "http/1.1", "h2-only": "h2"},
           "mtls": {"h2-and-http11": None, "http11-only": None, "h2-only": None}}


def alpn_offers(rows, impl, profile, what):
    size(rows, 3, f"{what} alpn offers")
    for row, (case, offered) in zip(rows, ALPN_OFFERS):
        label = f"{what} alpn {case}"
        eq(row["case"], case, f"{label} case")
        eq(row["offered"], offered, f"{label} offered")
        expected = None if impl == "rust" else ALPN_GO["mtls" if profile.startswith("mtls") else "tls"][case]
        eq(row["selected"], expected, f"{label} negotiated protocol")
        eq(row["tls_version"], "TLSv1.2" if profile.endswith("12") else "TLSv1.3", f"{label} tls_version")
        if expected == "h2":
            eq(row["h2_settings_frame"], True, f"{label} h2 SETTINGS frame")
            eq(row["http1_status_line"], None, f"{label} http1_status_line")
        else:
            eq(row["h2_settings_frame"], None, f"{label} h2_settings_frame")
            eq(row["http1_status_line"], "HTTP/1.1 200 OK", f"{label} HTTP/1.1 status line")


def alpn_pin(r):
    expected = [{"profile": profile, "case": case, "go_selected": ALPN_GO["tls"][case], "rust_selected": None,
                 "decision": "alpn-http11-only"} for profile in ("tls12", "tls13") for case, _ in ALPN_OFFERS]
    eq(r["alpn_declared_differences"], expected, "alpn_declared_differences")


def http_tls(r):
    decisions(r, 20, {"https-discovery-on-tls", "secure-origin-matches-http-authority"})
    alpn_pin(r)
    profiles = {"tls12", "tls13", "mtls12", "mtls13"}
    for impl, o in both(r):
        eq(set(o), profiles, f"{impl} profiles")
        size(flat(p["rows"] for p in o.values()), 48, f"{impl} rows")
        size(flat(p["identity_controls"] for p in o.values()), 12, f"{impl} identity controls")
        size(flat(p["encrypted_peers"] for p in o.values()), 8, f"{impl} encrypted peers")
        for name, p in o.items():
            what = f"{impl} {name}"
            size(p["rows"], 12, f"{what} rows")
            size(names(p["rows"], "case", what), 12, f"{what} distinct cases")
            processes_ok(p["processes"], 1, f"{what} processes")
            need(p["control_workers_joined"] and not p["control_errors"], f"{what}: workers/control errors")
            need(all(c["rejected"] for c in p["identity_controls"]), f"{what}: identity control not rejected")
            alpn_offers(p["alpn_offers"], impl, name, what)
            size(p["encrypted_peers"], 2, f"{what} encrypted peers")
            for peer in p["encrypted_peers"]:
                need(peer["sender_joined"] and peer["peer_terminal_observed"] and not peer["forced_client_close"],
                     f"{what}: encrypted peer")
                need(4 <= peer["sent_record_bytes"] < peer["record_length"], f"{what}: sent_record_bytes")
                eq(peer["server_certificate_sha256"], r["server_certificate_sha256"], f"{what} certificate")
                eq(peer["tls_version"], "TLSv1.2" if name.endswith("12") else "TLSv1.3", f"{what} tls_version")
                need(peer["termination"] in TERMINATIONS, f"{what}: termination")
            last_ping(p["rows"], "recovery-ping", what)


def http_write(r):
    eq(r["scope"], "full", "scope")
    need(not r["declared_differences"], "declared_differences must be empty")
    profiles = {"tcp-five", "tcp-short", "tls12-short", "tls13-short", "tcp-output", "tls-output"}
    eq(set(r["profiles"]), profiles, "profiles")
    for impl, o in both(r):
        eq(set(o), profiles, f"{impl} profiles")
        size(flat(p["rows"] for p in o.values()), 18, f"{impl} rows")
        eq(sum(bool(p["handshake_peer"]) for p in o.values()), 2, f"{impl} handshake peers")
        eq(sum(bool(p["slow_output"]) for p in o.values()), 2, f"{impl} slow outputs")
        for profile, p in o.items():
            what = f"{impl} {profile}"
            size(p["rows"], 3, f"{what} rows")
            processes_ok(p["processes"], 1, f"{what} processes")
            body = p["late_body"]
            need(body["peer_terminal_observed"] and not body["forced_client_close"], f"{what}: late body peer")
            eq(body["sent_body_suffix_bytes"], 16, f"{what} body suffix")
            at_least(body["body_completed_seconds"], 2.4, f"{what} body_completed_seconds")
            if p["handshake_peer"]:
                peer = p["handshake_peer"]
                need(peer["sender_joined"] and peer["peer_terminal_observed"] and not peer["forced_client_close"],
                     f"{what}: handshake peer")
                need(9 <= peer["sent_hello_bytes"] < peer["client_hello_length"], f"{what}: sent_hello_bytes")
                need(.6 <= peer["elapsed_seconds"] <= 2, f"{what}: handshake elapsed_seconds")
            if p["slow_output"]:
                out = p["slow_output"]
                need(out["peer_terminal_observed"] and not out["forced_client_close"], f"{what}: slow output peer")
                at_least(out["slow_read_calls"], 4, f"{what} slow_read_calls")
                at_least(out["slow_received_bytes"], 4096, f"{what} slow_received_bytes")
                at_least(out["fast_drain_started_seconds"], 34, f"{what} fast_drain_started_seconds")
                at_least(out["declared_chunk_length"], 10 * 1024 * 1024, f"{what} declared_chunk_length")
                need(out["received_chunk_bytes"] < out["declared_chunk_length"], f"{what}: chunk fully received")
            last_ping(p["rows"], "ping-after", what)


OAUTH_DECISIONS = {"fresh-persisted-client", "bound-browser-consent", "fresh-single-use-code",
                   "fresh-scoped-token-pair", "single-use-browser-confirmation", "server-bound-consent-metadata",
                   "server-bound-consent-pkce", "server-side-consent-denial", "configured-positive-token-ttls",
                   "bounded-refresh-after-access-expiry", "bounded-refreshed-runtime-control"}
RESPONSE_KEYS = {"status_line", "headers", "body_base64", "wire_body_base64", "raw_base64"}


def http_oauth(r):
    size(r["semantic_controls"], 26, "semantic_controls")
    eq({x["decision"] for x in r["semantic_controls"]}, OAUTH_DECISIONS, "semantic decisions")
    for impl, o in both(r):
        size(o["rows"], 35, f"{impl} rows")
        size(o["ttl_rows"], 11, f"{impl} ttl_rows")
        rows = o["rows"] + o["ttl_rows"]
        size(names(rows, "case", impl), 46, f"{impl} distinct cases")
        need(all(RESPONSE_KEYS <= x["response"].keys() for x in rows), f"{impl}: response keys incomplete")
        processes_ok(o["processes"], 3, f"{impl} processes")
        eq(o["rows"][-1]["case"], "persisted-rotated-token-health", f"{impl} last row")
        eq(o["ttl_rows"][-1]["case"], "ttl-old-access-still-denied", f"{impl} last ttl row")


def http_process(r):
    sys.path.insert(0, str(HERE))
    from http_process_contract import EARLY_INVALID_ADMISSION_CASES, validate_stalled_observations
    worktree_clean()
    decisions(r, 4, {"token-session-isolation", "complete-json-body-required", "valid-utf8-required",
                     "metadata-fresh-marker-semantic-control"})
    for impl, rows in both(r):
        size(rows, 65, f"{impl} rows")
        cases = names(rows, "case", impl)
        size(cases, 65, f"{impl} distinct cases")
        need({"resource-discovery-head", "authorization-discovery-head", "oauth-authorize-invalid-head",
              "oauth-authorize-foreign-origin-head", "mcp-early-invalid-oversized-invalid-byte",
              "mcp-early-invalid-oversized-invalid-object"} <= cases, f"{impl}: required HEAD/early-invalid cases")
        need({"mcp-early-invalid-oversized-" + n for n, _, _ in EARLY_INVALID_ADMISSION_CASES} <= cases,
             f"{impl}: early-invalid admission cases")
        eq(rows[-1]["case"], "mcp-ping-after-stalled-clients", f"{impl} last case")
        need(all(RESPONSE_KEYS <= x["response"].keys() for x in rows), f"{impl}: response keys incomplete")
        eq(names(r[impl + "_startup_denials"], "case", impl),
           {"eof", "no", "blank", "not-affirmative", "unterminated-yes"}, f"{impl} startup denials")
        eq(names(r[impl + "_stalled_clients"], "case", impl),
           {"idle-before-request", "incomplete-request-body"}, f"{impl} stalled clients")
        need(r[impl + "_process"]["forced_cleanup_not_graceful_evidence"], f"{impl}: forced cleanup evidence")
    eq(r["go_startup_denials"], r["rust_startup_denials"], "startup denials go vs rust")
    try:
        validate_stalled_observations(r)
    except AssertionError as error:
        raise Check(f"validate_stalled_observations: {error}") from error


MCP_PROFILES = {"legacy", "tier-read-only", "tier-standard", "tier-admin", "admin-value-hidden",
                "admin-value-visible", "standard-command-override", "readonly-capability-overrides",
                "admin-command-disabled", "admin-tools-health-only", "admin-tools-self-only", "admin-api-explicit",
                "standard-no-value-capabilities", "builtin-default", "builtin-claude-code", "builtin-codex",
                "builtin-hermes", "builtin-openclaw", "builtin-opencode", "tier-read-only-real-child",
                "tier-standard-real-child", "tier-admin-real-child"}
MCP_HOSTILE = {"unterminated", "crlf", "blank-line", "null-frame", "nul-byte", "two-objects-one-line",
               "duplicate-envelope-id", "frame-exact-limit", "frame-over-limit", "unterminated-over-limit",
               "depth-10000", "depth-10001"}


def mcp_process(r):
    worktree_clean()
    eq(r["reference_contract"], "mcp-anomaly-ordered-v1", "reference_contract")
    eq(r["oracle_commit"], "24acdb08fcc7021262717aa803d72eb8d151c66a", "oracle_commit")
    eq(r["compiler"]["version"], "go1.26.6", "compiler version")
    eq(set(r["loaded_go_profiles"]), MCP_PROFILES, "loaded_go_profiles")
    eq(set(r["fixture_snapshots"]), MCP_PROFILES, "fixture_snapshots")
    for impl in ("go", "rust"):
        rows = r[impl]
        size(rows, 22, f"{impl} profiles")
        eq({row["case"] for row in rows}, MCP_PROFILES, f"{impl} profile cases")
        need(all(row["response_count"] == 22 and row["stdout_is_only_protocol"] for row in rows),
             f"{impl}: response_count or stdout_is_only_protocol")
        hostile = r[impl + "_hostile"]
        size(hostile, 12, f"{impl} hostile")
        eq({row["case"] for row in hostile}, MCP_HOSTILE, f"{impl} hostile cases")
        need(all(row["stdout_is_only_protocol"] for row in hostile), f"{impl}: hostile stdout")
    size(r["declared_differences"], 67, "declared_differences")
    eq(len([x for x in r["declared_differences"] if x["decision"] == "windows-headless-approval-denial"]), 0,
       "windows-headless-approval-denial rows")
    eq(sum(len(row["frames"]) for name in ("go", "rust", "go_hostile", "rust_hostile") for row in r[name]),
       1022, "total frames")


API_CASES = {"verified-dns-https", "wrong-hostname", "untrusted-root", "private-answer", "mixed-family-answer",
             "pending-headers-cancel", "progressing-body-deadline", "pending-dns-cancel"}


def api_transport(r):
    for impl, rows in both(r):
        size(rows, 8, f"{impl} rows")
        eq({row["case"] for row in rows}, API_CASES, f"{impl} cases")
        need(all(row["exit_code"] == 0 and row["seeded_files"] and row["dns"] for row in rows),
             f"{impl}: exit_code/seeded_files/dns")
    size(r["declared_differences"], 7, "declared_differences")


def cli_artifacts(r):
    eq(r["actual_counts"], {"help_pages": 140, "scripts": 8, "manuals": 119, "actual_cli_queries": 503},
       "actual_counts")
    observations = r["go_protocol_observations"]
    size(observations, 537, "go_protocol_observations")
    eq(sum(row["name"].startswith("parser/") for row in observations), 82, "parser/ observations")
    eq(sum("-quoted-" in row["name"] for row in observations), 18, "-quoted- observations")
    need({"bash", "zsh", "fish"} <= set(r["actual_shells"]), "native shells bash, zsh and fish are required")


# rust-intake-cli.yml: 26 required names, plus `terminate` off Windows.
INTAKE_CASES = {"missing-directory", "missing-argument", "disable-absent", "disable-present", "json-staging",
                "encrypted-batch", "encrypted-batch-repeat", "go-readback", "interrupt", "file-env", "file-text",
                "file-json", "extension-not-type", "attachment-empty", "attachment-png", "file-ocr",
                "file-byte-limit", "file-default-limits", "invalid-interval", "invalid-debounce",
                "file-no-argument", "file-unknown-flag", "file-count-limit", "file-bool-true",
                "ordinary-encrypted-file", "ordinary-encrypted-file-repeat", "terminate"}


def intake(r):
    for impl, rows in both(r):
        missing = INTAKE_CASES - names(rows, "case", impl)
        need(not missing, f"{impl}: missing intake cases {sorted(missing)}")


# rust-serve-cli.yml: 25 names, `service-helper-failure` off Windows, 4 more.
SERVE_CASES = {"bare-uninitialized", "quiet-uninitialized", "arbitrary-arguments", "stdio-agent-required",
               "empty-bind", "locked-http-rejected", "signed-port-accepted", "valued-bool", "tls-flags-reach-vault",
               "locked-stdio", "locked-unknown-agent", "locked-canonical", "locked-gui-metadata",
               "locked-without-opt-in", "unlocked-stdio", "unlocked-allow-locked", "unlocked-canonical",
               "unlocked-unknown-agent", "service-status-absent", "service-install", "service-status-running",
               "service-status-quiet", "service-uninstall", "service-status-removed", "canonical-service-status",
               "service-helper-failure", "service-default-config", "http-default-tls", "http-custom-tls",
               "http-client-ca"}


def serve(r):
    for impl, rows in both(r):
        eq(names(rows, "case", impl), SERVE_CASES, f"{impl} cases")


EGRESS_RUNTIME = {"tls-auth-bearer", "tls-auth-basic", "tls-auth-header", "tls-auth-query_param", "tls-auth-none",
                  "tls-all-substitution-surfaces", "method-denied", "endpoint-denied", "encoded-endpoint-allowed",
                  "encoded-endpoint-denied", "dot-segment-policy", "unmatched-forwarded", "unmatched-strict",
                  "passthrough-preserves-upstream-tls", "untrusted-upstream-tls", "template-port-binding",
                  "template-plaintext-binding", "connect-inner-authority-binding", "redirect-authority-binding"}
EGRESS_CLI = {"broker-missing-vault", "broker-boolean-forms", "run-broker-flags-reach-vault", "run-broker-disabled",
              "run-broker-public-env", "run-broker-strict-passthrough", "run-broker-child-error",
              "run-broker-timeout", "run-broker-explicit-env", "run-broker-launch-error", "standalone-broker",
              "standalone-broker-flags", "loopback-listener-policy", "concurrent-broker-ca-isolation"}


def egress(r):
    worktree_clean()
    for impl in ("go", "rust"):
        eq({row["case"] for row in r[impl]}, EGRESS_RUNTIME, f"{impl} runtime cases")
        eq({row["case"] for row in r[impl + "_cli"]}, EGRESS_CLI, f"{impl} cli cases")


def connect(r):
    for impl, rows in both(r):
        eq({row["case"] for row in rows}, {"ordinary", "delayed", "fragmented-binary"}, f"{impl} cases")


def signal(r):
    worktree_clean()
    eq(r["expect_mismatch"], False, "expect_mismatch")
    for impl, rows in both(r):
        size(rows, 41, f"{impl} signal observations")
    # Go-only armed-clipboard observations (the Rust leg would need the real pasteboard):
    # 3 stdio `mcp` (SIGINT/SIGTERM/SIGHUP) + 4 `ui` (SIGINT/SIGTERM/SIGHUP/SIGQUIT) + 6 HTTP
    # `mcp` (armed SIGINT/SIGTERM/SIGHUP, idle SIGHUP, armed and idle SIGHUP inherited as SIG_IGN).
    size(r["go_only"], 13, "go-only clipboard observations")


def http_drain(r):
    """MCP-003/HTTP-004/CLI-007: Go/Rust graceful drain of `mcp` over HTTP (http_drain_contract.py)."""
    sys.path.insert(0, str(HERE))
    from http_drain_contract import GO_EXPECTED, RUNS
    worktree_clean()
    eq(r["expect_mismatch"], False, "expect_mismatch")
    eq(r["mismatch"], "", "mismatch")
    eq(r["drain_seconds"], 5.0, "drain_seconds")
    for impl, rows in both(r):
        size(rows, 15, f"{impl} drain observations")
        eq([(x["case"], x["signal"]) for x in rows], list(RUNS), f"{impl} drain runs")
        for x in rows:
            name = f"{impl} {x['case']}/{x['signal']}"
            need(x["exit_code"] == 0 and x["stdout"] == "", f"{name}: exit status or stdout")
            need(x["in_window"] is True and x["listener_closed"] is True, f"{name}: exit window or open listener")
            eq(x["runtime_records"], [], f"{name} runtime records")
            eq(x["outcome"], GO_EXPECTED[x["case"]][0], f"{name} peer outcome")


# ---- HTTP-001 / HTTP-002 process contracts (no hosted workflow step) --------
# The counts below are pinned here and cross-checked against the driver's own
# tables (imported, never copied), so neither can drift on its own.

def driver_calls(what, function, *arguments):
    """Run a driver's pure comparison/policy function; its AssertionError is a failed check."""
    try:
        return function(*arguments)
    except AssertionError as error:
        raise Check(f"{what}: {error}") from error


ROW_KEYS = {"case", "request_sha256", "request_base64", "raw_base64", "reset", "responses"}
CALL_KEYS = {"case", "raw_base64", "reset", "responses"}
RESPONSE_FIELDS = ("status_line", "code", "interim", "headers", "headers_without_date", "body_base64", "truncated")


def wire_rows(rows, what, keys=ROW_KEYS):
    """Structure of raw-transcript rows (http_replay_contract.exchange): every field the evidence needs is present."""
    for x in rows:
        need(keys <= x.keys(), f"{what} {x.get('case')!r}: incomplete row")
        need(x["reset"] != "timeout", f"{what} {x['case']!r}: the server left the connection open")
        need(isinstance(x["responses"], list), f"{what} {x['case']!r}: responses is not a list")
        for response in x["responses"]:
            if "code" not in response:   # a stream cut before a complete head
                need(response.get("truncated") is True and "partial_base64" in response,
                     f"{what} {x['case']!r}: malformed partial response")
                continue
            need(all(key in response for key in RESPONSE_FIELDS), f"{what} {x['case']!r}: incomplete response")
            eq(response["headers_without_date"], sorted([k, v] for k, v in response["headers"] if k != "date"),
               f"{what} {x['case']!r} headers_without_date")


def driver_sha(receipt, name):
    eq(receipt["driver_sha256"], hashlib.sha256((HERE / name).read_bytes()).hexdigest(),
       f"driver_sha256 ({name} changed after the receipt was written)")


REPLAY_TOKENS = dict.fromkeys(("full", "health", "metadata", "other", "expired", "revoked"), "placeholder")


def http_replay(r):
    """HTTP-001: SSE negotiation, replay, envelope, route and framing corpus (http_replay_contract.py)."""
    sys.path.insert(0, str(HERE))
    import http_replay_contract as driver
    driver_sha(r, "http_replay_contract.py")
    eq(r["oracle_commit"], driver.ORACLE, "oracle_commit")
    need(isinstance(r["port"], int), "port")
    names = [name for name, *_ in driver.cases(r["port"], REPLAY_TOKENS)]
    eq(len(names), 276, "driver case count")
    eq(len(driver.DECLARED), 71, "driver declared count")
    eq(sorted(driver.INTERIM_ONLY), ["expect-100", "expect-100-chunked"], "driver interim-only cases")
    eq(len(driver.HEALTH_CASES) - 1, 8, "driver health clock cases (route-head-health is compared separately)")
    for impl, o in both(r):
        eq([x["case"] for x in o["rows"]], names, f"{impl} case inventory and order")
        wire_rows(o["rows"], impl)
        processes_ok(o["processes"], 1, f"{impl} processes")
    identical, declared, semantic, interim_only = driver_calls("replay comparison", driver.compare,
                                                                r["go"]["rows"], r["rust"]["rows"], r["port"])
    eq(len(identical), 194, "identical cases")
    eq(len(declared), 71, "declared cases")
    eq(len(semantic), 8, "semantic (health clock) cases")
    eq(len(interim_only), 2, "final-identical (Go-only interim 100 Continue) cases")
    eq(len(identical) + len(declared) + len(semantic) + len(interim_only) + 1, len(names),
       "identical + declared + semantic + interim-only + route-head-health")
    eq({d["case"]: d["decision"] for d in r["declared_differences"]},
       {case: label for case, (label, _, _) in driver.DECLARED.items()}, "declared_differences")
    size(r["declared_differences"], 71, "declared_differences")
    eq([x["case"] for x in r["interim_only_cases"]], sorted(driver.INTERIM_ONLY), "interim_only_cases")
    eq((r["identical_cases"], r["semantic_cases"]), (194, 8), "receipt identical/semantic counts")


def http_token(r):
    """HTTP-002: bearer-token state, clock and storage matrix (http_token_contract.py)."""
    sys.path.insert(0, str(HERE))
    import http_token_contract as driver
    driver_sha(r, "http_token_contract.py")
    eq(r["oracle_commit"], driver.ORACLE, "oracle_commit")
    need(isinstance(r["port"], int), "port")
    raws, body = driver.token_registry()
    names = [name for name, _ in driver.token_cases(r["port"], raws)]
    scenarios = driver.startup_scenarios(raws, body)
    eq((len(names), len(scenarios)), (180, 70), "driver token-state and startup/storage counts")
    for impl, o in both(r):
        eq([x["case"] for x in o["rows"]], names, f"{impl} token-state case inventory and order")
        wire_rows(o["rows"], impl)
        need(isinstance(o["process"]["exit"], int) and o["process"]["disposal"] == "killed"
             and all(isinstance(o["process"][k], str) for k in ("stdout", "stderr")), f"{impl}: process record")
    driver_calls("token-state comparison", driver.check_token_rows, r["go"]["rows"], r["rust"]["rows"])
    eq(r["token_cases"], 180, "token_cases")
    size(r["startup"], 70, "startup/storage scenarios")
    eq([x["case"] for x in r["startup"]], [s[0] for s in scenarios], "startup scenario inventory and order")
    for scenario, x in zip(scenarios, r["startup"], strict=True):
        for impl in ("go", "rust"):
            need(isinstance(x[impl]["stderr_utf8"], str), f"{scenario[0]} {impl}: stderr_utf8")
            wire_rows(x[impl]["responses"], f"{scenario[0]} {impl}", CALL_KEYS)
        driver_calls(f"startup {scenario[0]}", driver.check_startup, scenario, x["go"], x["rust"])
    eq(set(r["dynamic"]), {"go", "rust"}, "dynamic implementations")
    driver_calls("dynamic scenario", driver.check_dynamic, r["dynamic"]["go"], r["dynamic"]["rust"])
    reload_steps = r["duplicate_reload"]
    eq(set(reload_steps), {"go", "rust"}, "duplicate_reload implementations")
    size(reload_steps["go"], 21, "go duplicate-key reload steps")
    driver_calls("duplicate-key reload", driver.check_duplicate_reload, reload_steps["go"], reload_steps["rust"])
    stale = r["stale_revocation"]
    eq(set(stale), {"go", "rust"}, "stale_revocation implementations")
    for impl in ("go", "rust"):
        size(stale[impl], 2, f"{impl} stale-revocation scenarios")
        eq([x["mode"] for x in stale[impl]], ["corrupt", "delete"], f"{impl} stale-revocation modes")
    driver_calls("stale revocation", driver.check_stale_revocation, stale["go"], stale["rust"])


def toolhash(r):
    """TOOLHASH-001: registry hash stamp, drift refusal and audit rows (toolhash_process_contract.py)."""
    sys.path.insert(0, str(HERE))
    import toolhash_process_contract as driver
    driver_sha(r, "toolhash_process_contract.py")
    recorded = json.loads(driver.FIXTURE.read_bytes())["registry"]["hash"]
    eq(r["recorded_go_hash"], recorded, "recorded Go registry hash")
    eq(r["issue"], {impl: {"new": recorded, "rotate": recorded} for impl in ("go", "rust")}, "CLI issuance hashes")
    expected = [(scenario, token) for scenario, _, _, who in driver.SCENARIOS for token in who]
    eq(len(expected), 14, "driver HTTP outcome count")
    eq(sorted((h["scenario"], h["token"]) for h in r["http"]), sorted(expected), "HTTP outcomes")
    outcomes = {}
    for h in r["http"]:
        eq(h["go"], h["rust"], f"{h['scenario']}/{h['token']} go vs rust")
        eq(h["go"][0], "HTTP/1.1 200 OK", f"{h['scenario']}/{h['token']} status line")
        outcomes[h["scenario"], h["token"]] = json.loads(h["go"][1])
    for token in ("go_current", "go_legacy_empty", "go_cli_issued", "rust_cli_issued"):
        need(not outcomes["search", token]["result"]["isError"], f"search with {token} must be accepted")
    for scenario, token in (("search", "go_stale"), ("policy-denied-path", "go_stale"), ("health", "go_stale")):
        result = outcomes[scenario, token]["result"]
        need(result["isError"] and result["content"][0]["text"] == driver.DRIFT_TEXT,
             f"{scenario} with {token} must be refused with the drift text")
    scoped = outcomes["out-of-scope-tool", driver.STALE_SCOPED]["result"]
    need(scoped["isError"] and "tool registry has changed" not in scoped["content"][0]["text"],
         "scope denial must precede the drift refusal")
    need(not outcomes["policy-allowed-path", "go_current"]["result"]["isError"], "allowed path with a current token")
    denied = outcomes["policy-denied-path", "go_current"]
    need("error" in denied and "result" not in denied, "entry policy denies the path for a current token")
    need(not outcomes["health", "rust_cli_issued"]["result"]["isError"], "health with a Rust-issued token")
    audit = r["audit"]
    eq(set(audit), {"go", "rust"}, "audit implementations")
    size(audit["go"], driver.EXPECTED_AUDIT_ROWS, "go audit rows")
    eq(driver.EXPECTED_AUDIT_ROWS, 8, "driver audit row count")
    eq(audit["go"], audit["rust"], "go vs rust audit rows")
    need({"tool_denied", "tool_registry_drift"} <= {dict(row)["action"] for row in audit["go"]},
         "audit rows lack the denial and drift actions")
    for row in audit["go"]:
        fields = dict(row)
        eq((fields["sess_id"], fields["req_id"]), ("<sess>", "<req>"), "masked audit ids")


# name -> (checker, workflow asserts candidate_worktree_clean_at_end,
#          workflow asserts an empty `differences`)
PROFILES = {
    "http-framing": (http_framing, True, True),
    "http-head": (http_head, True, True),
    "http-origin": (http_origin, True, True),
    "http-read-deadlines": (http_read_deadlines, True, True),
    "http-timeouts": (http_timeouts, True, True),
    "http-tls": (http_tls, True, True),
    "http-write": (http_write, True, True),
    "http-oauth": (http_oauth, True, True),
    "http-process": (http_process, True, True),
    "mcp-process": (mcp_process, True, True),
    "api-transport": (api_transport, True, False),
    "cli-artifacts": (cli_artifacts, False, False),
    "intake": (intake, False, False),
    "serve": (serve, False, False),
    "egress": (egress, True, False),
    "connect": (connect, False, False),
    "signal": (signal, False, False),
    "http-drain": (http_drain, True, False),
    "http-replay": (http_replay, True, False),
    "http-token": (http_token, True, False),
    "toolhash": (toolhash, True, False),
}


def receipt(args):
    try:
        data = json.loads(Path(args.path).read_bytes())
    except (OSError, ValueError) as error:
        fail(f"{args.path}: unreadable receipt: {error}")
    if not isinstance(data, dict):
        fail(f"{args.path}: receipt is not an object")
    checker, at_end, differences = PROFILES[args.profile] if args.profile else (None, True, False)
    try:
        eq(data["passed"], True, "passed")
        eq(data["candidate_worktree_clean"], True, "candidate_worktree_clean")
        if at_end:
            eq(data["candidate_worktree_clean_at_end"], True, "candidate_worktree_clean_at_end")
        eq(data["candidate_commit"], head(), "candidate_commit is not HEAD")
        eq(data["native_os"], platform.system(), "native_os")
        if differences:
            need(not data["differences"], "undeclared differences recorded")
        if checker:
            checker(data)
    except Check as error:
        fail(f"{args.path}: {error}")
    except (KeyError, IndexError, TypeError, AttributeError, ValueError) as error:
        fail(f"{args.path}: malformed receipt ({type(error).__name__}: {error})")
    print(f"gate_area_check: ok {args.path}" + (f" [{args.profile}]" if args.profile else ""))


def gaps(args):
    try:
        data = json.loads(Path(args.path).read_bytes())
        if args.no_missing_paths:
            need(not data["missing_paths"], "every Go help path must be reachable; missing_paths not empty")
        if args.prefix or args.exact_path:
            for kind in ("missing_paths", "flag_gaps", "alias_gaps"):
                need(kind in data, f"report has no {kind}")
                for gap in data[kind] or []:
                    path = gap["path"]
                    if any(path.startswith(p) for p in args.prefix or []) or path in (args.exact_path or []):
                        raise Check(f"{kind}: {path}")
        if args.min_paths:
            oracle, rust = (int(x) for x in args.min_paths.split(":"))
            at_least(data["oracle_paths"], oracle, "oracle_paths")
            at_least(data["rust_paths"], rust, "rust_paths")
    except Check as error:
        fail(f"{args.path}: {error}")
    except (OSError, KeyError, TypeError, ValueError) as error:
        fail(f"{args.path}: malformed report ({type(error).__name__}: {error})")
    print(f"gate_area_check: ok {args.path}")


def read_text(path):
    try:
        return Path(path).read_text()
    except OSError as error:
        fail(f"{path}: unreadable: {error}")


def go_json(args):
    rows = []
    for line in read_text(args.path).splitlines():
        if line.startswith("{"):
            try:
                rows.append(json.loads(line))
            except ValueError:
                fail(f"{args.path}: malformed go test -json line")
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
    text = read_text(args.path)
    for name in args.names:
        if f"--- PASS: {name} " not in text:
            fail(f"{args.path}: no `--- PASS: {name}`")
    print(f"gate_area_check: ok {args.path} ({len(args.names)} required tests)")


def contains(text, needle):
    """`needle` occurs in `text` and is not the tail/head of a longer number.

    A count such as "10 passed" must not match "110 passed", nor "2 passed" match
    "12 passed": a needle starting (ending) with a digit may not be preceded
    (followed) by one.
    """
    pattern = re.escape(needle)
    if needle[:1].isdigit():
        pattern = r"(?<!\d)" + pattern
    if needle[-1:].isdigit():
        pattern += r"(?!\d)"
    return re.search(pattern, text) is not None


def log_ok(args):
    text = read_text(args.path)
    for name in args.names:
        if args.exact_prefix is not None:
            found = f"test {args.exact_prefix}{name} ... ok" in text
        else:
            found = re.search(r"test .*" + re.escape(name) + r" \.\.\. ok", text)
        if not found:
            fail(f"{args.path}: no `{name} ... ok`")
    for needle in args.contains or []:
        if not contains(text, needle):
            fail(f"{args.path}: does not contain {needle!r}")
    results = RESULT.findall(text)
    if args.results_ok or args.sum_passed is not None:
        if not results:
            fail(f"{args.path}: no `test result: ok` line")
        if any(int(ignored) != 0 for _, ignored in results):
            fail(f"{args.path}: ignored tests in a required run")
        total = sum(int(n) for n, _ in results)
        if total == 0:
            fail(f"{args.path}: zero tests ran")
        if args.sum_passed is not None and total != args.sum_passed:
            fail(f"{args.path}: {total} tests passed, expected {args.sum_passed}")
    if re.search(r"^test result: FAILED", text, re.M):
        fail(f"{args.path}: a test result line says FAILED")
    print(f"gate_area_check: ok {args.path} ({len(args.names)} required tests)")


def list_profiles(_):
    print("\n".join(sorted(PROFILES)))


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("receipt"); p.add_argument("path"); p.add_argument("--profile", choices=sorted(PROFILES))
    p.set_defaults(run=receipt)
    p = sub.add_parser("profiles"); p.set_defaults(run=list_profiles)
    p = sub.add_parser("gaps"); p.add_argument("path"); p.add_argument("--prefix", action="append")
    p.add_argument("--exact-path", action="append")
    p.add_argument("--no-missing-paths", action="store_true"); p.add_argument("--min-paths")
    p.set_defaults(run=gaps)
    p = sub.add_parser("go-json"); p.add_argument("path"); p.add_argument("names", nargs="+")
    p.set_defaults(run=go_json)
    p = sub.add_parser("go-text-pass"); p.add_argument("path"); p.add_argument("names", nargs="+")
    p.set_defaults(run=go_text_pass)
    p = sub.add_parser("log-ok"); p.add_argument("path"); p.add_argument("names", nargs="*")
    p.add_argument("--exact-prefix"); p.add_argument("--contains", action="append")
    p.add_argument("--sum-passed", type=int); p.add_argument("--results-ok", action="store_true")
    p.set_defaults(run=log_ok)
    # Names may follow options (`log-ok LOG --exact-prefix X name1 name2`):
    # argparse before 3.13 consumes the empty positional list first and rejects
    # the trailing names (the Linux gate container ships python 3.12 as python3).
    args, extra = parser.parse_known_args()
    if extra:
        if hasattr(args, "names") and not any(item.startswith("-") for item in extra):
            args.names = list(args.names) + extra
        else:
            parser.error("unrecognized arguments: " + " ".join(extra))
    args.run(args)


if __name__ == "__main__":
    main()
