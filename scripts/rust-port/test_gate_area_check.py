#!/usr/bin/env python3
"""Negative controls for gate_area_check.py.

Every receipt profile is fed a synthetic receipt shaped like the hosted
workflow's expectations (it must pass), and then, one at a time: every key
removed, every list truncated to one row or emptied, wrong counts and wrong
names. Each of those must exit 1. The synthetic receipts are algorithm unit
state only, never native process observations.
"""
import argparse
import contextlib
import copy
import hashlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import gate_area_check as g
import http_token_contract as token_driver
import test_http_replay_contract as replay_cases
import toolhash_process_contract as toolhash_driver
from http_process_contract import EARLY_INVALID_ADMISSION_CASES

HEAD = "0123456789abcdef0123456789abcdef01234567"
OK_LINE = "HTTP/1.1 200 OK"


def response(status=OK_LINE):
    return {"status_line": status, "headers": {}, "body_base64": "", "wire_body_base64": "", "raw_base64": ""}


def row(case, **extra):
    return {"case": case, "response": response(), **extra}


def procs(count=1):
    return [{"output_capture_complete": True, "output_capture_errors": [], "forced_cleanup_not_graceful_evidence": True}
            for _ in range(count)]


def base(**extra):
    return {"passed": True, "candidate_worktree_clean": True, "candidate_worktree_clean_at_end": True,
            "candidate_commit": HEAD, "native_os": "Linux", "differences": [], "declared_differences": [], **extra}


def decl(count, decisions):
    return [{"decision": sorted(decisions)[i % len(decisions)]} for i in range(count)]


def cases(prefix, count):
    return [row(f"{prefix}-{i}") for i in range(count)]


def peer(**extra):
    return {"sender_joined": True, "peer_terminal_observed": True, "forced_client_close": False,
            "sent_progress_bytes": 8, "termination": "actual-empty-eof-or-reset",
            "peer_terminal_kind": "eof", **extra}


def per_impl(make):
    return {"go": make("go"), "rust": make("rust")}


# ---- good receipts -------------------------------------------------------

def good_framing():
    def make(_):
        rows = cases("f", 32) + [row("recovery-ping")]
        return {"rows": rows, "pipeline": {"responses": [1, 2]}, "processes": procs()}
    return base(declared_differences=decl(18, {"security-metadata-stays-in-headers", "framing-validation-before-dispatch",
                               "complete-chunk-frame-required", "one-request-length-required",
                               "chunked-requires-http11"}),
                **per_impl(make))


def good_head():
    return base(**per_impl(lambda _: {"rows": cases("h", 13), "authorization_heads": list(range(512)),
                                      "pipeline": {"responses": [1, 2]}, "processes": procs(),
                                      "browser_control": {"status_line": OK_LINE}}))


def good_origin():
    def make(_):
        return {"rows": cases("o", 201) + [row("recovery-ping")], "processes": procs()}
    return base(declared_differences=decl(69, {"serialized-http-origin-required", "loopback-host-required",
                                               "valid-loopback-authority-required"}), **per_impl(make))


def good_deadlines():
    def make(_):
        return {"rows": [row("initialize"), row("ping-before"), row("ping-after")],
                "slow_peers": [peer(case="progressing-header"), peer(case="progressing-body", peer_terminal_kind="connection-reset")],
                "workers_joined": True, "control_errors": [],
                "idle_boundary": {"responses": [1, 2], "idle_wait_seconds": 6.5}, "processes": procs()}
    return base(**per_impl(make))


def good_timeouts():
    profiles = ("positive", "zero", "negative")

    def make(_):
        return {name: {"rows": [row("a"), row("b"), row("ping-after")], "processes": procs(),
                       "workers_joined": True, "control_errors": [],
                       "slow_peers": [peer(case="x"), peer(case="y")],
                       "idle_boundary": {"idle_wait_seconds": 7, "responses": [1, 2]}} for name in profiles}
    invalid = {impl: [{"exit": code, "expected_exit": code, "forced_cleanup": False, "output_capture_complete": True,
                       "output_capture_errors": []} for _ in range(2)] for impl, code in (("go", 6), ("rust", 1))}
    return base(profiles=list(profiles), invalid_config=invalid, **per_impl(make))


def good_tls():
    profiles = ("tls12", "tls13", "mtls12", "mtls13")
    digest = "ab" * 32

    def make(_):
        out = {}
        for name in profiles:
            version = "TLSv1.2" if name.endswith("12") else "TLSv1.3"
            out[name] = {"rows": cases("t", 11) + [row("recovery-ping")], "processes": procs(),
                         "control_workers_joined": True, "control_errors": [],
                         "identity_controls": [{"rejected": True} for _ in range(3)],
                         "encrypted_peers": [peer(sent_record_bytes=8, record_length=64, server_certificate_sha256=digest,
                                                  tls_version=version) for _ in range(2)]}
        return out
    return base(server_certificate_sha256=digest, declared_differences=decl(20, {"https-discovery-on-tls",
                "secure-origin-matches-http-authority"}), **per_impl(make))


def good_write():
    profiles = ("tcp-five", "tcp-short", "tls12-short", "tls13-short", "tcp-output", "tls-output")

    def make(_):
        out = {}
        for name in profiles:
            slow = name.endswith("-output")
            out[name] = {"rows": [row("a"), row("b"), row("ping-after")], "processes": procs(),
                         "late_body": {"peer_terminal_observed": True, "forced_client_close": False,
                                       "sent_body_suffix_bytes": 16, "body_completed_seconds": 3},
                         "handshake_peer": ({"sender_joined": True, "peer_terminal_observed": True,
                                             "forced_client_close": False, "sent_hello_bytes": 10,
                                             "client_hello_length": 200, "elapsed_seconds": 1} if name in ("tls12-short", "tls13-short") else None),
                         "slow_output": ({"peer_terminal_observed": True, "forced_client_close": False,
                                          "slow_read_calls": 5, "slow_received_bytes": 5000,
                                          "fast_drain_started_seconds": 35, "declared_chunk_length": 11 * 1024 * 1024,
                                          "received_chunk_bytes": 1024} if slow else None)}
        return out
    return base(scope="full", profiles=list(profiles), **per_impl(make))


def good_oauth():
    decisions = sorted(g.OAUTH_DECISIONS)

    def make(_):
        rows = cases("r", 34) + [row("persisted-rotated-token-health")]
        ttl = cases("ttl", 10) + [row("ttl-old-access-still-denied")]
        return {"rows": rows, "ttl_rows": ttl, "processes": procs(3)}
    return base(semantic_controls=[{"decision": decisions[i % len(decisions)]} for i in range(26)], **per_impl(make))


def good_http_process():
    extra = ["resource-discovery-head", "authorization-discovery-head", "oauth-authorize-invalid-head",
             "oauth-authorize-foreign-origin-head", "mcp-early-invalid-oversized-invalid-byte",
             "mcp-early-invalid-oversized-invalid-object"] + ["mcp-early-invalid-oversized-" + n
                                                              for n, _, _ in EARLY_INVALID_ADMISSION_CASES]
    extra = list(dict.fromkeys(extra))
    receipt = base(declared_differences=decl(4, {"token-session-isolation", "complete-json-body-required",
                                                 "valid-utf8-required", "metadata-fresh-marker-semantic-control"}))
    for impl in ("go", "rust"):
        rows = [row(name) for name in extra] + cases("p", 64 - len(extra)) + [row("mcp-ping-after-stalled-clients")]
        receipt[impl] = rows
        receipt[impl + "_startup_denials"] = [{"case": c} for c in ("eof", "no", "blank", "not-affirmative", "unterminated-yes")]
        receipt[impl + "_stalled_clients"] = [
            {"case": "idle-before-request", "request_sha256": "a" * 64, "received_base64": "", "peer_eof": True,
             "passed": True, "elapsed_seconds": 5.0, "response_class": "silent-eof"},
            {"case": "incomplete-request-body", "request_sha256": "b" * 64, "received_base64": "", "peer_eof": True,
             "passed": True, "elapsed_seconds": 10.0, "response_class": "silent-eof"}]
        receipt[impl + "_process"] = {"forced_cleanup_not_graceful_evidence": True}
    return receipt


def good_mcp_process():
    def make_hostile(_):
        return [{"case": name, "stdout_is_only_protocol": True, "frames": [0]} for name in sorted(g.MCP_HOSTILE)]

    def make(_):
        return [{"case": name, "response_count": 22, "stdout_is_only_protocol": True, "frames": [0]}
                for name in sorted(g.MCP_PROFILES)]
    receipt = base(reference_contract="mcp-anomaly-ordered-v1", oracle_commit="24acdb08fcc7021262717aa803d72eb8d151c66a",
                   compiler={"version": "go1.26.6"}, loaded_go_profiles=sorted(g.MCP_PROFILES),
                   fixture_snapshots={name: 1 for name in g.MCP_PROFILES},
                   declared_differences=[{"decision": "other"} for _ in range(67)])
    for impl in ("go", "rust"):
        receipt[impl] = make(impl)
        receipt[impl + "_hostile"] = make_hostile(impl)
    # 2 x 22 profile rows and 2 x 12 hostile rows carry one frame each; the first
    # row carries the rest, so that the total is exactly 1022.
    receipt["go"][0]["frames"] = [0] * (1022 - 67)
    return receipt


def good_api():
    def make(_):
        return [{"case": name, "exit_code": 0, "seeded_files": ["a"], "dns": {"x": 1}} for name in sorted(g.API_CASES)]
    return base(declared_differences=[{"decision": "d"} for _ in range(7)], **per_impl(make))


def good_cli_artifacts():
    observations = ([{"name": f"parser/{i}"} for i in range(82)] + [{"name": f"case-quoted-{i}"} for i in range(18)]
                    + [{"name": f"other-{i}"} for i in range(537 - 100)])
    return base(actual_counts={"help_pages": 140, "scripts": 8, "manuals": 119, "actual_cli_queries": 503},
                go_protocol_observations=observations, actual_shells={"bash": 1, "zsh": 1, "fish": 1})


def good_intake():
    return base(**per_impl(lambda _: [{"case": c} for c in sorted(g.INTAKE_CASES)]))


def good_serve():
    return base(**per_impl(lambda _: [{"case": c} for c in sorted(g.SERVE_CASES)]))


def good_egress():
    receipt = base()
    for impl in ("go", "rust"):
        receipt[impl] = [{"case": c} for c in sorted(g.EGRESS_RUNTIME)]
        receipt[impl + "_cli"] = [{"case": c} for c in sorted(g.EGRESS_CLI)]
    return receipt


def good_connect():
    return base(**per_impl(lambda _: [{"case": c} for c in ("ordinary", "delayed", "fragmented-binary")]))


def good_signal():
    return base(expect_mismatch=False, **per_impl(lambda _: [{"n": i} for i in range(33)]))


def good_http_drain():
    from http_drain_contract import GO_EXPECTED, RUNS

    def make(_):
        return [{"case": case, "signal": name, "exit_code": 0, "stdout": "", "in_window": True,
                 "listener_closed": True, "runtime_records": [], "outcome": GO_EXPECTED[case][0]}
                for case, name in RUNS]
    return base(expect_mismatch=False, mismatch="", drain_seconds=5.0, **per_impl(make))


def driver_sha(name):
    return hashlib.sha256((Path(__file__).resolve().parent / name).read_bytes()).hexdigest()


def good_http_replay():
    # The self-consistent Go/Rust corpus of test_http_replay_contract.py (every
    # declared, interim-only, health-clock and identical class present).
    go, rust = replay_cases.synthetic()
    identical, declared, semantic, interim_only = replay_cases.replay.compare(go, rust, replay_cases.PORT)
    assert (len(identical), len(declared), len(semantic), len(interim_only)) == (194, 71, 8, 2)
    return base(port=replay_cases.PORT, driver_sha256=driver_sha("http_replay_contract.py"), oracle_commit=token_driver.ORACLE,
                go={"rows": go, "processes": procs()}, rust={"rows": rust, "processes": procs()},
                declared_differences=[{"case": d["case"], "decision": d["decision"]} for d in declared],
                identical_cases=194, semantic_cases=8, interim_only_cases=[{"case": d["case"]} for d in interim_only])


def call_record(code):
    return {"case": "call", "raw_base64": "", "reset": None, "elapsed_seconds": 0.0,
            "responses": [{"status_line": OK_LINE, "code": code, "interim": False, "headers": [],
                           "headers_without_date": [], "body_base64": "", "truncated": False}]}


def startup_record(scenario):
    name, _, graceful, state, first = scenario
    listening = state == "listening"
    codes = [first if first is not None else 200] + [200] * 4
    if name in ("legacy-only", "legacy-only-sigint"):
        codes = [401, 401, 200, 200, 403]
    after = {}
    if name.startswith("legacy-only") or name.startswith("registry-missing"):
        after = {"mcp-tokens.json": {"version": 2, "entries": [["legacy (auto-migrated, unscoped)", "legacy"]]}}
    return {"state": state, "exit": None if listening else 1, "disposal": ("graceful" if graceful else "killed") if listening else "exited",
            "before": {}, "after": after, "stderr_has_legacy_warning": False, "stderr_utf8": "",
            "responses": [call_record(code) for code in codes] if listening else []}


def good_http_token():
    raws, body = token_driver.token_registry()
    rows = replay_cases.TokenContract("test_matrix_passes_and_mutations_fail").rows()
    process = {"disposal": "killed", "exit": -9, "stdout": "", "stderr": ""}
    startup = []
    for scenario in token_driver.startup_scenarios(raws, body):
        record = startup_record(scenario)
        startup.append({"case": scenario[0], "go": record, "rust": copy.deepcopy(record)})
    dynamic = {"live_before_expiry": 200, "live_expiry_epoch": 100.0, "live_detected_epoch": 101.0, "added_latency": 2.1,
               "revoke_latency": 2.2, "recovered_latency": 2.0, "after_corruption": 200}
    steps = [[f"step-{i}", 200 if i % 2 else 401] for i in range(21)]
    stale = [{"mode": mode, "revoked_token_status": 401, "other_token_status": 200} for mode in ("corrupt", "delete")]
    return base(port=4242, driver_sha256=driver_sha("http_token_contract.py"), oracle_commit=token_driver.ORACLE, token_cases=180, startup=startup,
                go={"rows": rows, "process": dict(process)}, rust={"rows": copy.deepcopy(rows), "process": dict(process)},
                dynamic={"go": dict(dynamic), "rust": dict(dynamic)}, duplicate_reload={"go": steps, "rust": copy.deepcopy(steps)},
                stale_revocation={"go": stale, "rust": copy.deepcopy(stale)})


def frame(result=None, error=None):
    out = {"jsonrpc": "2.0", "id": 2}
    out.update({"result": result} if error is None else {"error": error})
    return OK_LINE, json.dumps(out)


def tool_result(text="ok", is_error=False):
    return {"isError": is_error, "content": [{"type": "text", "text": text}]}


def good_toolhash():
    recorded = json.loads(toolhash_driver.FIXTURE.read_bytes())["registry"]["hash"]
    drift = tool_result(toolhash_driver.DRIFT_TEXT, True)
    http = []
    for scenario, _, _, who in toolhash_driver.SCENARIOS:
        for token in who:
            if token == "go_stale":
                outcome = frame(drift)
            elif scenario == "out-of-scope-tool":
                outcome = frame(tool_result("tool not permitted for this token", True))
            elif (scenario, token) == ("policy-denied-path", "go_current"):
                outcome = frame(error={"code": -32602, "message": "denied by entry policy"})
            else:
                outcome = frame(tool_result())
            http.append({"scenario": scenario, "token": token, "go": list(outcome), "rust": list(outcome)})
    actions = ["tool_call", "tool_call", "tool_denied", "tool_denied", "tool_registry_drift", "tool_registry_drift",
               "tool_registry_drift", "tool_call"]
    audit = [[["action", action], ["sess_id", "<sess>"], ["req_id", "<req>"], ["token_id", "tok-1"]] for action in actions]
    return base(driver_sha256=driver_sha("toolhash_process_contract.py"), recorded_go_hash=recorded,
                issue={impl: {"new": recorded, "rotate": recorded} for impl in ("go", "rust")}, http=http,
                audit={"go": audit, "rust": copy.deepcopy(audit)})



def _replay_row(receipt, case, side="rust"):
    return next(x for x in receipt[side]["rows"] if x["case"] == case)


def _toolhash_outcome(receipt, scenario, token, result):
    """Both servers return the same (wrong) outcome: only the hand-written expectation can catch it."""
    for h in receipt["http"]:
        if (h["scenario"], h["token"]) == (scenario, token):
            h["go"] = h["rust"] = list(frame(result))


GOOD = {
    "http-framing": good_framing, "http-head": good_head, "http-origin": good_origin,
    "http-read-deadlines": good_deadlines, "http-timeouts": good_timeouts, "http-tls": good_tls,
    "http-write": good_write, "http-oauth": good_oauth, "http-process": good_http_process,
    "mcp-process": good_mcp_process, "api-transport": good_api, "cli-artifacts": good_cli_artifacts,
    "intake": good_intake, "serve": good_serve, "egress": good_egress, "connect": good_connect,
    "signal": good_signal, "http-drain": good_http_drain,
    "http-replay": good_http_replay, "http-token": good_http_token, "toolhash": good_toolhash,
}

# Keys a profile does not read (the workflow did not assert them either).
UNREAD = {
    "http-head": {"declared_differences"}, "http-process": set(), "api-transport": {"differences"},
    "cli-artifacts": {"differences", "declared_differences", "candidate_worktree_clean_at_end"},
    "intake": {"differences", "declared_differences", "candidate_worktree_clean_at_end"},
    "serve": {"differences", "declared_differences", "candidate_worktree_clean_at_end"},
    "connect": {"differences", "declared_differences", "candidate_worktree_clean_at_end"},
    "egress": {"differences", "declared_differences"},
    "signal": {"differences", "declared_differences", "candidate_worktree_clean_at_end"},
}
ALWAYS_UNREAD = {"differences", "declared_differences"}


def run_check(profile, receipt):
    """Run `gate_area_check.py receipt` in-process; return its exit status."""
    with tempfile.TemporaryDirectory() as raw:
        path = Path(raw) / "receipt.json"
        path.write_text(json.dumps(receipt) if not isinstance(receipt, str) else receipt)
        args = argparse.Namespace(path=str(path), profile=profile)
        with mock.patch.object(g, "head", return_value=HEAD), \
                mock.patch.object(g, "worktree_clean", return_value=None), \
                mock.patch.object(g.platform, "system", return_value="Linux"), \
                contextlib.redirect_stderr(io.StringIO()), contextlib.redirect_stdout(io.StringIO()):
            try:
                g.receipt(args)
            except SystemExit as exit_:
                return exit_.code
            return 0


def walk(node, path=()):
    """Yield (path, container-node) for every dict and list in the receipt."""
    yield path, node
    if isinstance(node, dict):
        for key, value in node.items():
            yield from walk(value, path + (key,))
    elif isinstance(node, list):
        if node:  # the last element: the checks read the final row of every list
            yield from walk(node[-1], path + (len(node) - 1,))


def at(root, path):
    for part in path:
        root = root[part]
    return root


class ReceiptProfiles(unittest.TestCase):
    def test_good_receipts_pass(self):
        for profile, build in GOOD.items():
            with self.subTest(profile=profile):
                self.assertEqual(run_check(profile, build()), 0)

    def test_every_profile_has_a_good_receipt(self):
        self.assertEqual(set(GOOD), set(g.PROFILES))

    def test_every_removed_key_fails(self):
        survivors = []
        for profile, build in GOOD.items():
            good = build()
            unread = UNREAD.get(profile, set()) | ALWAYS_UNREAD
            for path, node in walk(good):
                if not isinstance(node, dict):
                    continue
                for key in list(node):
                    if not path and key in unread:
                        continue
                    mutant = copy.deepcopy(good)
                    del at(mutant, path)[key]
                    if run_check(profile, mutant) == 0:
                        survivors.append((profile, path + (key,)))
        # Fields the hosted workflow does not assert either (evidence only, or
        # placeholders of these synthetic receipts), so the port does not either.
        evidence = {"headers", "body_base64", "wire_body_base64", "raw_base64"}
        unread = {("http-head", "case"), ("http-head", "status_line"), ("http-head", "response"),
                  ("http-read-deadlines", "status_line"), ("http-read-deadlines", "response"),
                  ("http-timeouts", "case"), ("http-timeouts", "peer_terminal_kind"),
                  ("http-tls", "sent_progress_bytes"), ("http-tls", "peer_terminal_kind"),
                  ("api-transport", "decision"), ("signal", "n")}
        survivors = [s for s in survivors if s[1][-1] not in evidence and (s[0], s[1][-1]) not in unread]
        self.assertEqual(survivors, [], "removing these keys must fail the check")

    def test_every_shrunken_list_fails(self):
        survivors = []
        for profile, build in GOOD.items():
            good = build()
            for path, node in walk(good):
                if not isinstance(node, list) or not node:
                    continue
                for label, shrunk in (("one row", node[:1]), ("empty", [])):
                    if label == "one row" and len(node) == 1:
                        continue
                    mutant = copy.deepcopy(good)
                    if not path:
                        continue
                    at(mutant, path[:-1])[path[-1]] = shrunk
                    if run_check(profile, mutant) == 0:
                        survivors.append((profile, path, label))
        # `frames` lists are only counted in total; declared_differences is
        # empty or counted per profile and tested separately below.
        self.assertEqual(survivors, [])

    def test_wrong_header_values_fail(self):
        for profile, build in GOOD.items():
            for key, bad in (("passed", False), ("candidate_worktree_clean", False), ("candidate_commit", "deadbeef"),
                             ("native_os", "Darwin")):
                with self.subTest(profile=profile, key=key):
                    mutant = build()
                    mutant[key] = bad
                    self.assertEqual(run_check(profile, mutant), 1)

    def test_wrong_workflow_counts_fail(self):
        def grow(receipt, *path):
            at(receipt, path).append(copy.deepcopy(at(receipt, path)[-1]))
        mutations = [
            ("http-framing", lambda r: r["declared_differences"].pop()),
            ("http-framing", lambda r: grow(r, "go", "rows")),
            ("http-origin", lambda r: r["declared_differences"].pop()),
            ("http-origin", lambda r: grow(r, "rust", "rows")),
            ("http-head", lambda r: r["go"]["authorization_heads"].pop()),
            ("http-read-deadlines", lambda r: r["go"]["idle_boundary"].update(idle_wait_seconds=5.9)),
            ("http-read-deadlines", lambda r: r["declared_differences"].append({"decision": "x"})),
            ("http-timeouts", lambda r: r["invalid_config"]["go"][0].update(exit=1, expected_exit=1)),
            ("http-timeouts", lambda r: r["profiles"].append("extra")),
            ("http-tls", lambda r: r["declared_differences"].append({"decision": "https-discovery-on-tls"})),
            ("http-tls", lambda r: r["go"]["tls12"]["identity_controls"][0].update(rejected=False)),
            ("http-tls", lambda r: r["rust"]["mtls13"]["encrypted_peers"][0].update(tls_version="TLSv1.2")),
            ("http-write", lambda r: r.update(scope="tls-output-probe-only")),
            ("http-write", lambda r: r["declared_differences"].append({"decision": "windows"})),
            ("http-write", lambda r: r["rust"]["tcp-output"]["slow_output"].update(received_chunk_bytes=11 * 1024 * 1024)),
            ("http-write", lambda r: r["rust"]["tcp-five"]["late_body"].update(sent_body_suffix_bytes=15)),
            ("http-oauth", lambda r: r["semantic_controls"].pop()),
            ("http-oauth", lambda r: r["go"]["processes"].pop()),
            ("http-oauth", lambda r: r["go"]["rows"][-1].update(case="other")),
            ("http-process", lambda r: r["declared_differences"].pop()),
            ("http-process", lambda r: r["go"].pop(0)),
            ("http-process", lambda r: r["rust_stalled_clients"][0].update(elapsed_seconds=1.0)),
            ("mcp-process", lambda r: r["declared_differences"].pop()),
            ("mcp-process", lambda r: r.update(oracle_commit="0" * 40)),
            ("mcp-process", lambda r: r["compiler"].update(version="go1.26.10")),
            ("mcp-process", lambda r: r["go"][0]["frames"].pop()),
            ("api-transport", lambda r: r["declared_differences"].pop()),
            ("api-transport", lambda r: r["go"][0].update(exit_code=1)),
            ("cli-artifacts", lambda r: r["actual_counts"].update(manuals=118)),
            ("cli-artifacts", lambda r: r["go_protocol_observations"].pop()),
            ("cli-artifacts", lambda r: r["actual_shells"].pop("fish")),
            ("intake", lambda r: r["rust"].pop(0)),
            ("serve", lambda r: r["go"].append({"case": "unexpected-extra"})),
            ("egress", lambda r: r["go_cli"].pop()),
            ("connect", lambda r: r["rust"].pop()),
            ("signal", lambda r: r.update(expect_mismatch=True)),
            ("signal", lambda r: r["rust"].pop()),
            ("http-drain", lambda r: r.update(expect_mismatch=True)),
            ("http-drain", lambda r: r.update(mismatch="x")),
            ("http-drain", lambda r: r.update(drain_seconds=1.0)),
            ("http-drain", lambda r: r["rust"].pop()),
            ("http-drain", lambda r: r["go"].append(copy.deepcopy(r["go"][-1]))),
            ("http-drain", lambda r: r["rust"][0].update(exit_code=1)),
            ("http-drain", lambda r: r["rust"][3].update(outcome="force-closed-empty")),
            ("http-drain", lambda r: r["rust"][3].update(in_window=False)),
            ("http-drain", lambda r: r["rust"][3].update(runtime_records=[".runtime-port"])),
            ("http-drain", lambda r: r["rust"][3].update(stdout="x")),
            ("http-drain", lambda r: r["go"].reverse()),
            ("http-replay", lambda r: r["declared_differences"].pop()),
            ("http-replay", lambda r: r["rust"]["rows"].pop()),
            ("http-replay", lambda r: r["go"]["rows"].reverse()),
            ("http-replay", lambda r: r.update(identical_cases=193)),
            ("http-replay", lambda r: r.update(semantic_cases=7)),
            ("http-replay", lambda r: r["interim_only_cases"].pop()),
            ("http-replay", lambda r: r.update(driver_sha256="0" * 64)),
            ("http-replay", lambda r: r.update(oracle_commit="0" * 40)),
            ("http-replay", lambda r: r.update(port="4242")),
            ("http-replay", lambda r: r["go"]["processes"].pop()),
            ("http-replay", lambda r: r["rust"]["processes"][0].update(output_capture_complete=False)),
            ("http-replay", lambda r: r["rust"]["rows"][5].update(reset="timeout")),
            ("http-replay", lambda r: r["declared_differences"][0].update(decision="other")),
            ("http-replay", lambda r: _replay_row(r, "method-GET")["responses"][0].update(code=500, status_line="HTTP/1.1 500 X")),
            ("http-replay", lambda r: _replay_row(r, "line-empty").update(responses=copy.deepcopy(_replay_row(r, "line-empty", "go")["responses"]))),
            ("http-token", lambda r: r["startup"].pop()),
            ("http-token", lambda r: r["startup"].reverse()),
            ("http-token", lambda r: r.update(token_cases=179)),
            ("http-token", lambda r: r.update(driver_sha256="1" * 64)),
            ("http-token", lambda r: r.update(oracle_commit="1" * 40)),
            ("http-token", lambda r: r["go"]["rows"].pop()),
            ("http-token", lambda r: r["rust"]["rows"][5]["responses"][0].update(code=500, status_line="HTTP/1.1 500 X")),
            ("http-token", lambda r: r["rust"]["process"].update(disposal="graceful")),
            ("http-token", lambda r: r["startup"][0]["rust"].update(state="exited")),
            ("http-token", lambda r: r["startup"][2]["rust"].update(after={"mcp-tokens.json": "unparseable"})),
            ("http-token", lambda r: r["dynamic"]["rust"].update(after_corruption=401)),
            ("http-token", lambda r: r["dynamic"]["go"].update(revoke_latency=9.0)),
            ("http-token", lambda r: r["duplicate_reload"]["rust"].pop()),
            ("http-token", lambda r: r["duplicate_reload"]["rust"][3].__setitem__(1, 999)),
            ("http-token", lambda r: [x.pop() for x in (r["duplicate_reload"]["go"], r["duplicate_reload"]["rust"])]),
            ("http-token", lambda r: r["stale_revocation"]["rust"][0].update(revoked_token_status=200)),
            ("http-token", lambda r: r["stale_revocation"]["go"].reverse()),
            ("toolhash", lambda r: r["http"].pop()),
            ("toolhash", lambda r: r["http"][3]["rust"].__setitem__(1, "{}")),
            ("toolhash", lambda r: r["audit"]["rust"].pop()),
            ("toolhash", lambda r: r["audit"]["go"].pop()),
            ("toolhash", lambda r: [row.pop(1) for row in r["audit"]["rust"]]),
            ("toolhash", lambda r: r["issue"]["rust"].update(new="")),
            ("toolhash", lambda r: r.update(recorded_go_hash="0" * 64)),
            ("toolhash", lambda r: r.update(driver_sha256="2" * 64)),
            ("toolhash", lambda r: _toolhash_outcome(r, "search", "go_stale", tool_result())),
            ("toolhash", lambda r: _toolhash_outcome(r, "policy-denied-path", "go_stale", tool_result("denied", True))),
            ("toolhash", lambda r: _toolhash_outcome(r, "search", "rust_cli_issued", tool_result("refused", True))),
            ("toolhash", lambda r: _toolhash_outcome(r, "out-of-scope-tool", toolhash_driver.STALE_SCOPED, tool_result(toolhash_driver.DRIFT_TEXT, True))),
            ("toolhash", lambda r: [row.__setitem__(0, ["action", "tool_call"]) for row in r["audit"]["go"] + r["audit"]["rust"]]),
        ]
        for profile, mutate in mutations:
            with self.subTest(profile=profile, mutation=mutate.__code__.co_firstlineno):
                mutant = GOOD[profile]()
                mutate(mutant)
                self.assertEqual(run_check(profile, mutant), 1)

    def test_one_row_receipt_fails(self):
        for profile, build in GOOD.items():
            receipt = build()
            for path, node in list(walk(receipt)):
                if isinstance(node, list) and len(node) > 1 and path and path[-1] in (
                        "rows", "go", "rust", "go_protocol_observations", "ttl_rows"):
                    at(receipt, path[:-1])[path[-1]] = node[:1]
            with self.subTest(profile=profile):
                self.assertEqual(run_check(profile, receipt), 1)

    def test_malformed_receipts_fail_closed(self):
        for profile in GOOD:
            for text in ("", "[]", "null", "{}", '{"passed": true}', "not json"):
                with self.subTest(profile=profile, text=text):
                    self.assertEqual(run_check(profile, text), 1)

    def test_basic_receipt_without_profile_requires_every_header(self):
        self.assertEqual(run_check(None, base()), 0)
        for key in ("passed", "candidate_worktree_clean", "candidate_worktree_clean_at_end", "candidate_commit",
                    "native_os"):
            mutant = base()
            del mutant[key]
            with self.subTest(missing=key):
                self.assertEqual(run_check(None, mutant), 1)


class CommandLine(unittest.TestCase):
    """The real script, as the Makefile runs it: exit status and stderr."""

    def invoke(self, receipt, *argv):
        import platform
        import subprocess
        head = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
        receipt = dict(receipt, candidate_commit=head, native_os=platform.system())
        with tempfile.TemporaryDirectory() as raw:
            path = Path(raw) / "receipt.json"
            path.write_text(json.dumps(receipt))
            return subprocess.run([sys.executable, "-B", str(Path(g.__file__)), "receipt", str(path), *argv],
                                  capture_output=True, text=True)

    def test_exit_status_of_the_real_script(self):
        good = good_connect()
        done = self.invoke(good, "--profile", "connect")
        self.assertEqual((done.returncode, done.stderr), (0, ""))
        one_row = dict(good, go=good["go"][:1])
        done = self.invoke(one_row, "--profile", "connect")
        self.assertEqual(done.returncode, 1)
        self.assertIn("FAIL", done.stderr)
        missing = {k: v for k, v in good.items() if k != "rust"}
        self.assertEqual(self.invoke(missing, "--profile", "connect").returncode, 1)
        self.assertEqual(self.invoke(dict(good, passed=False), "--profile", "connect").returncode, 1)
        stale = self.invoke(good, "--profile", "connect")
        self.assertEqual(stale.returncode, 0)


class Reports(unittest.TestCase):
    def run_main(self, *argv):
        with mock.patch.object(sys, "argv", ["gate_area_check.py", *argv]), \
                contextlib.redirect_stderr(io.StringIO()), contextlib.redirect_stdout(io.StringIO()):
            try:
                g.main()
            except SystemExit as exit_:
                return exit_.code
            return 0

    def write(self, directory, name, content):
        path = Path(directory) / name
        path.write_text(content if isinstance(content, str) else json.dumps(content))
        return str(path)

    def test_gaps(self):
        report = {"oracle_paths": 134, "rust_paths": 100, "missing_paths": [], "flag_gaps": [], "alias_gaps": None}
        with tempfile.TemporaryDirectory() as d:
            ok = self.write(d, "ok.json", report)
            self.assertEqual(self.run_main("gaps", ok, "--prefix", "symvault serve", "--min-paths", "134:100",
                                           "--no-missing-paths"), 0)
            for label, mutant in {
                "zero oracle paths": dict(report, oracle_paths=0),
                "zero rust paths": dict(report, rust_paths=0),
                "short oracle paths": dict(report, oracle_paths=133),
                "missing path": dict(report, missing_paths=[{"path": "symvault serve"}]),
                "flag gap under prefix": dict(report, flag_gaps=[{"path": "symvault serve http"}]),
                "no oracle_paths key": {k: v for k, v in report.items() if k != "oracle_paths"},
                "no flag_gaps key": {k: v for k, v in report.items() if k != "flag_gaps"},
            }.items():
                with self.subTest(label):
                    path = self.write(d, "bad.json", mutant)
                    self.assertEqual(self.run_main("gaps", path, "--prefix", "symvault serve",
                                                   "--min-paths", "134:100", "--no-missing-paths"), 1)
            exact = self.write(d, "exact.json", dict(report, alias_gaps=[{"path": "symvault run"}]))
            self.assertEqual(self.run_main("gaps", exact, "--exact-path", "symvault broker",
                                           "--exact-path", "symvault run"), 1)
            sub = self.write(d, "sub.json", dict(report, alias_gaps=[{"path": "symvault run extra"}]))
            self.assertEqual(self.run_main("gaps", sub, "--exact-path", "symvault broker",
                                           "--exact-path", "symvault run"), 0)
            self.assertEqual(self.run_main("gaps", self.write(d, "garbage.json", "{"), "--min-paths", "1:1"), 1)

    def test_go_json(self):
        rows = [{"Action": "pass", "Test": "TestA"}, {"Action": "pass", "Test": "TestB"}]
        text = "\n".join(json.dumps(r) for r in rows)
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(self.run_main("go-json", self.write(d, "a", text), "TestA", "TestB"), 0)
            self.assertEqual(self.run_main("go-json", self.write(d, "b", text), "TestA", "TestC"), 1)
            skipped = text + "\n" + json.dumps({"Action": "skip", "Test": "TestA"})
            self.assertEqual(self.run_main("go-json", self.write(d, "c", skipped), "TestA"), 1)
            failed = text + "\n" + json.dumps({"Action": "fail", "Test": "TestZ"})
            self.assertEqual(self.run_main("go-json", self.write(d, "d", failed), "TestA"), 1)
            self.assertEqual(self.run_main("go-json", self.write(d, "e", ""), "TestA"), 1)
            self.assertEqual(self.run_main("go-json", str(Path(d) / "absent"), "TestA"), 1)

    def test_log_ok_totals_and_names(self):
        log = ("test migrate_kdf_commands::tests::one ... ok\ntest migrate_kdf_commands::tests::two ... ok\n"
               "test result: ok. 9 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out\n")
        with tempfile.TemporaryDirectory() as d:
            path = self.write(d, "log", log)
            args = ["log-ok", path, "one", "two", "--exact-prefix", "migrate_kdf_commands::tests::",
                    "--contains", "9 passed; 0 failed; 0 ignored", "--sum-passed", "9"]
            self.assertEqual(self.run_main(*args), 0)
            self.assertEqual(self.run_main(*args[:-1], "8"), 1)
            self.assertEqual(self.run_main("log-ok", path, "three", "--exact-prefix",
                                           "migrate_kdf_commands::tests::"), 1)
            self.assertEqual(self.run_main("log-ok", path, "one", "--exact-prefix", "other::"), 1)
            # names after the options (python < 3.13 argparse rejects this without the fix)
            self.assertEqual(self.run_main("log-ok", path, "--exact-prefix", "migrate_kdf_commands::tests::",
                                           "--contains", "9 passed; 0 failed; 0 ignored", "one", "two"), 0)
            self.assertEqual(self.run_main("log-ok", path, "--exact-prefix", "migrate_kdf_commands::tests::",
                                           "one", "three"), 1)
            self.assertEqual(self.run_main("log-ok", path, "one", "--bogus-option"), 2)
            ignored = self.write(d, "ign", log.replace("0 ignored", "1 ignored"))
            self.assertEqual(self.run_main("log-ok", ignored, "--sum-passed", "9"), 1)
            self.assertEqual(self.run_main("log-ok", self.write(d, "none", "nothing ran\n"), "--results-ok"), 1)
            zero = self.write(d, "zero", "test result: ok. 0 passed; 0 failed; 0 ignored;\n")
            self.assertEqual(self.run_main("log-ok", zero, "--results-ok"), 1)
            failed = self.write(d, "failed", log + "test result: FAILED. 1 passed; 1 failed; 0 ignored\n")
            self.assertEqual(self.run_main("log-ok", failed, "one"), 1)

    def test_contains_counts_are_digit_bounded(self):
        for text, needle, expected in [
            ("test result: ok. 110 passed; 0 failed; 0 ignored;", "10 passed; 0 failed; 0 ignored", 1),
            ("test result: ok. 12 passed; 0 failed; 0 ignored;", "2 passed; 0 failed; 0 ignored", 1),
            ("test result: ok. 10 passed; 0 failed; 0 ignored;", "10 passed; 0 failed; 0 ignored", 0),
            ("test result: ok. 2 passed; 0 failed; 0 ignored;", "test result: ok. 2 passed; 0 failed; 0 ignored;", 0),
            ("test result: ok. 12 passed; 0 failed; 0 ignored;", "test result: ok. 2 passed; 0 failed; 0 ignored;", 1),
            ("4 passed; 0 failed; 0 ignored", "4 passed; 0 failed; 0 ignored", 0),
            ("14 passed; 0 failed; 0 ignored", "4 passed; 0 failed; 0 ignored", 1),
            ("10 passed; 0 failed; 0 ignored; 0 measured", "10 passed; 0 failed; 0 ignored", 0),
            ("10 passed; 0 failed; 0 ignored 1", "10 passed; 0 failed; 0 ignored 1", 0),
            ("10 passed; 0 failed; 0 ignored 10", "10 passed; 0 failed; 0 ignored 1", 1),
        ]:
            with tempfile.TemporaryDirectory() as d:
                path = self.write(d, "log", text + "\n")
                self.assertEqual(self.run_main("log-ok", path, "--contains", needle), expected, (text, needle))

    def test_go_text_pass(self):
        with tempfile.TemporaryDirectory() as d:
            path = self.write(d, "t", "--- PASS: TestX (0.00s)\n")
            self.assertEqual(self.run_main("go-text-pass", path, "TestX"), 0)
            self.assertEqual(self.run_main("go-text-pass", path, "TestY"), 1)


if __name__ == "__main__":
    unittest.main()
