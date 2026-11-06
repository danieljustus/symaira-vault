#!/usr/bin/env python3
"""Negative controls for http_drain_contract.py (synthetic rows: algorithm state only).

The real Go/Rust process observations come from `http_drain_contract.py`; these
tests prove that its comparison and its oracle guard reject each difference
that the pre-drain Rust server (immediate exit) or a drifted oracle would show.
"""
import copy
import unittest

import http_drain_contract as c

RESPONSE_200 = {"status_line": "HTTP/1.1 200 OK", "headers": [("connection", "close"), ("content-length", "372"),
                                                              ("content-type", "application/json")],
                "body": '{"jsonrpc":"2.0","id":3,"result":{"content":[],"isError":false}}\n'}
RESPONSE_403 = {"status_line": "HTTP/1.1 403 Forbidden", "headers": [("connection", "close"), ("content-length", "78"),
                                                                    ("content-type", "application/json")],
                "body": '{"error":{"message":"context canceled","code":-32603},"jsonrpc":"2.0","id":2}\n'}
KEEPALIVE_200 = {"status_line": "HTTP/1.1 200 OK", "headers": [("content-length", "37"), ("content-type", "application/json")],
                 "body": '{"jsonrpc":"2.0","id":2,"result":{}}\n'}


def row(case, sig, **extra):
    outcome, status = c.GO_EXPECTED[case]
    response = {None: None, 200: RESPONSE_200, 403: RESPONSE_403}[status]
    if case == "idle-keepalive":
        response = KEEPALIVE_200
    if case == "inflight-keepalive":
        response = RESPONSE_200
    base = dict(case=case, signal=sig, exit_code=0, stdout="", in_window=True, listener_closed=True,
                outcome=outcome, response=response, peer_end="eof",
                during_drain="refused" if case in ("inflight-within", "inflight-keepalive", "second-signal") else None,
                command_outlives_server=True if case == "inflight-exceeds" else (
                    False if case in ("inflight-within", "inflight-keepalive", "second-signal") else None),
                stderr="Received SIGQUIT, shutting down gracefully...\n" if sig == "SIGQUIT" else "",
                delta={"removed": ["vault/.runtime-port"], "added": [], "changed": []}, runtime_records=[])
    base.update(extra)
    return base


def rows():
    return [row(case, sig) for case, sig in c.RUNS]


class DrainContract(unittest.TestCase):
    def test_pinned_inventory(self):
        self.assertEqual(len(c.RUNS), 15)
        self.assertEqual(len(set(c.RUNS)), 15)
        self.assertEqual(set(case for case, _ in c.RUNS), set(c.CASES))
        self.assertEqual({sig for _, sig in c.RUNS}, {"SIGINT", "SIGTERM", "SIGQUIT"})
        self.assertEqual(c.DRAIN_SECONDS, 5.0)
        # One case exceeds the window by command, one by a stalled body; both finishing cases stay below it.
        self.assertGreater(c.CASES["inflight-exceeds"][1][0], c.DRAIN_SECONDS - 1)
        self.assertGreater(c.CASES["slowbody-exceeds"][1][0], c.DRAIN_SECONDS - 1)
        for case in ("inflight-within", "inflight-keepalive", "slowbody-within", "second-signal"):
            self.assertLess(c.CASES[case][1][1], c.DRAIN_SECONDS)

    def test_equal_observations_compare_equal(self):
        c.compare(rows(), rows())
        c.check_oracle(rows())

    def test_every_compared_field_is_enforced(self):
        # The pre-drain server: an in-flight reply is lost, the child outcome and timing differ.
        mutations = {
            "exit_code": 1, "stdout": "x", "stderr": "Received SIGQUIT", "outcome": "force-closed-empty",
            "response": None, "peer_end": "reset", "during_drain": "accepted", "listener_closed": False,
            "command_outlives_server": None, "in_window": False, "runtime_records": [".runtime-port"],
            "delta": {"removed": [], "added": [], "changed": []},
        }
        for field, bad in mutations.items():
            for index in range(len(c.RUNS)):
                mutant = rows()
                if mutant[index].get(field) == bad:
                    continue
                mutant[index][field] = bad
                with self.subTest(field=field, case=c.RUNS[index]):
                    with self.assertRaises(AssertionError):
                        c.compare(rows(), mutant)

    def test_case_lists_must_match(self):
        with self.assertRaises(AssertionError):
            c.compare(rows(), rows()[:-1])
        with self.assertRaises(AssertionError):
            c.compare(rows(), list(reversed(rows())))

    def test_immediate_exit_server_is_rejected(self):
        """What the Rust server did before the drain: every in-flight request was aborted at once."""
        go = rows()
        mutant = rows()
        for r in mutant:
            if r["case"] in ("inflight-within", "inflight-keepalive", "slowbody-within", "second-signal"):
                r.update(outcome="force-closed-empty", response=None)
            if r["case"] in ("inflight-exceeds", "slowbody-exceeds"):
                r.update(in_window=False)
        with self.assertRaises(AssertionError):
            c.compare(go, mutant)

    def test_oracle_guard_rejects_a_drifted_or_vacuous_oracle(self):
        for index, (case, sig) in enumerate(c.RUNS):
            for field, bad in (("exit_code", 1), ("in_window", False), ("listener_closed", False),
                               ("outcome", "force-closed-empty" if c.GO_EXPECTED[case][0] != "force-closed-empty" else "completed"),
                               ("stdout", "x"), ("runtime_records", [".runtime-tls-cert"]),
                               ("delta", {"removed": [], "added": [], "changed": []}),
                               ("stderr", "x" if sig == "SIGQUIT" else "Received SIGQUIT, shutting down gracefully...\n")):
                mutant = rows()
                mutant[index][field] = bad
                with self.subTest(case=case, signal=sig, field=field):
                    with self.assertRaises(AssertionError):
                        c.check_oracle(mutant)
        mutant = rows()
        index = c.RUNS.index(("inflight-keepalive", "SIGINT"))
        mutant[index]["response"] = copy.deepcopy(RESPONSE_200)
        mutant[index]["response"]["headers"] = [("content-length", "372")]
        with self.assertRaises(AssertionError):  # a drained reply must close the connection
            c.check_oracle(mutant)
        index = c.RUNS.index(("inflight-exceeds", "SIGINT"))
        mutant = rows()
        mutant[index]["command_outlives_server"] = False
        with self.assertRaises(AssertionError):  # the uncooperative command must outlive the server
            c.check_oracle(mutant)
        index = c.RUNS.index(("inflight-within", "SIGINT"))
        mutant = rows()
        mutant[index]["during_drain"] = "accepted"
        with self.assertRaises(AssertionError):  # the listener must close at the start of the drain
            c.check_oracle(mutant)

    def test_response_normalization_keeps_everything_but_run_randomness(self):
        raw = (b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nDate: Tue, 03 Nov 2026 02:16:50 GMT\r\n"
               b"Content-Length: 40\r\nConnection: close\r\n\r\n"
               b'{"text":"{\\"duration_ms\\":2026,\\"x\\":\\"DATA_d7b66e17e05bfaa1\\"}"}')
        parsed = c.parse_response(raw)
        self.assertEqual(parsed["status_line"], "HTTP/1.1 200 OK")
        self.assertNotIn("date", [name for name, _ in parsed["headers"]])
        self.assertIn(("connection", "close"), parsed["headers"])
        self.assertIn("duration_ms:N", parsed["body"])
        self.assertIn("DATA_ID", parsed["body"])
        other = raw.replace(b"2026", b"2149").replace(b"d7b66e17e05bfaa1", b"0123456789abcdef")
        self.assertEqual(c.parse_response(other), parsed)
        self.assertNotEqual(c.parse_response(raw.replace(b"200 OK", b"403 Forbidden")), parsed)
        self.assertNotEqual(c.parse_response(raw.replace(b"close", b"keep")), parsed)
        self.assertIsNone(c.parse_response(b""))


if __name__ == "__main__":
    unittest.main()
