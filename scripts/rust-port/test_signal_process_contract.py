#!/usr/bin/env python3
"""Negative controls for signal_process_contract.py: every mutation must be rejected."""
import copy
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import signal_process_contract as contract  # noqa: E402


def record(case, command, sig, ending, **extra):
    row = dict(case=case, command=command, signal=sig, ending=ending, stdout="out\n", stderr="",
               state=["inbox", "tmp", "vault"])
    row.update(extra)
    return row


def go_records():
    broker = dict(state=["inbox", "tmp", "vault", "vault/broker-ca.pem"], listener_closed=True)
    return [
        record("broker-sigint", "broker", "SIGINT", ["exit", 0], **broker),
        record("broker-sighup", "broker", "SIGHUP", ["signal", signal.SIGHUP], **broker),
        record("intake-watch-sigterm", "intake-watch", "SIGTERM", ["exit", 0]),
        record("run-sigterm", "run", "SIGTERM", ["signal", signal.SIGTERM], orphaned_child_alive=True),
        record("run-broker-sigint", "run-broker", "SIGINT", ["signal", signal.SIGINT], orphaned_child_alive=True,
               state=["inbox", "tmp", "vault", "vault/broker-ca.pem"]),
        record("run-group-sigint", "run-group", "SIGINT", ["signal", signal.SIGINT], orphaned_child_alive=False),
        record("run-timeout-group-sigint", "run-group", "SIGINT", ["signal", signal.SIGINT], orphaned_child_alive=False),
        # Inherited SIG_IGN (Go 1.26 sigInstallGoHandler: kept for SIGHUP/SIGINT only unless Notify'd).
        record("broker-ignored-sighup", "broker", "SIGHUP", ["exit", 0], ignored=True, survived=True,
               listener_open_after_ignored_signal=True, **broker),
        record("broker-ignored-sigint", "broker", "SIGINT", ["exit", 0], ignored=True, survived=False, **broker),
        record("run-ignored-sighup", "run", "SIGHUP", ["signal", signal.SIGTERM], ignored=True, survived=True,
               orphaned_child_alive=True),
        record("run-ignored-sigint", "run", "SIGINT", ["signal", signal.SIGTERM], ignored=True, survived=True,
               orphaned_child_alive=True),
        record("run-ignored-sigterm", "run", "SIGTERM", ["signal", signal.SIGTERM], ignored=True, survived=False,
               orphaned_child_alive=True),
        record("run-ignored-sigquit", "run", "SIGQUIT", ["exit", 2], ignored=True, survived=False,
               orphaned_child_alive=True),
        # `mcp --stdio --allow-locked` (indices 13-15) and `ui` on a pseudo-terminal (16-19).
        record("mcp-locked-sigint", "mcp-locked", "SIGINT", ["exit", 0], stderr=contract.LOCKED_WARNING,
               state=["tmp", "vault"]),
        record("mcp-locked-sighup", "mcp-locked", "SIGHUP", ["signal", signal.SIGHUP], stderr=contract.LOCKED_WARNING,
               state=["tmp", "vault", "vault/.runtime-port"]),
        record("mcp-locked-sigquit", "mcp-locked", "SIGQUIT", ["exit", 0],
               stderr=contract.LOCKED_WARNING + "Received SIGQUIT, shutting down gracefully...\n", state=["tmp", "vault"]),
        record("ui-sigint", "ui", "SIGINT", ["exit", 1], stderr=contract.UI_INTERRUPTED * 2, terminal_restored=True,
               alt_screen_left=True, state=["tmp", "vault"]),
        record("ui-sigterm", "ui", "SIGTERM", ["exit", 0], terminal_restored=True, alt_screen_left=True,
               state=["tmp", "vault"]),
        record("ui-sighup", "ui", "SIGHUP", ["signal", signal.SIGHUP], terminal_restored=False,
               alt_screen_left=False, state=["tmp", "vault"]),
        record("ui-sigquit", "ui", "SIGQUIT", ["exit", 2], stderr="<not compared: Go SIGQUIT goroutine dump>",
               terminal_restored=False, alt_screen_left=False, state=["tmp", "vault"]),
    ]


def rust_records():
    rows = copy.deepcopy(go_records())
    for row in rows:
        row["state"] = [n for n in row["state"] if n != "vault/broker-ca.pem"]
    return rows


class SignalContractControls(unittest.TestCase):
    def rejects(self, mutate, pattern=None):
        rust = rust_records()
        mutate(rust)
        with self.assertRaises(AssertionError) as caught:
            contract.compare(go_records(), rust)
        if pattern:
            self.assertIn(pattern, repr(caught.exception))

    def test_unmutated_pair_passes(self):
        contract.compare(go_records(), rust_records())
        contract.check_oracle_expectations(go_records()[:6])
        contract.check_oracle_expectations(go_records())

    def test_death_by_signal_becomes_clean_exit(self):  # the pre-fix SIGHUP behavior
        self.rejects(lambda r: r[1].update(ending=["exit", 0]), "ending")

    def test_clean_exit_becomes_death_by_signal(self):
        self.rejects(lambda r: r[0].update(ending=["signal", signal.SIGINT]), "ending")

    def test_wrong_exit_status(self):
        self.rejects(lambda r: r[0].update(ending=["exit", 1]), "ending")

    def test_stdout_or_stderr_difference(self):
        self.rejects(lambda r: r[0].update(stdout="out\nextra\n"), "stdout")
        self.rejects(lambda r: r[2].update(stderr="panic"), "stderr")

    def test_listener_survives(self):
        self.rejects(lambda r: r[0].update(listener_closed=False), "listener_closed")

    def test_orphan_state_flips(self):
        self.rejects(lambda r: r[3].update(orphaned_child_alive=False), "orphaned_child_alive")
        self.rejects(lambda r: r[5].update(orphaned_child_alive=True), "orphaned_child_alive")

    def test_temporary_ca_directory_left_behind(self):
        self.rejects(lambda r: r[1]["state"].extend([".broker-ca-abc"]), "on-disk state")
        self.rejects(lambda r: r[4]["state"].extend(["vault/.broker-ca-abc"]), "on-disk state")

    def test_ca_exemption_is_not_a_blanket_state_exemption(self):
        self.rejects(lambda r: r[2]["state"].append("tmp/symvault-intake-__ID__"), "on-disk state")
        self.rejects(lambda r: r[3]["state"].append("tmp/leftover"), "on-disk state")

    def test_ca_file_exemption_does_not_cover_non_broker_commands(self):
        go = go_records()
        go[3]["state"] = go[3]["state"] + ["vault/broker-ca.pem"]
        with self.assertRaises(AssertionError):
            contract.compare(go, rust_records())

    def test_case_lists_must_match(self):
        self.rejects(lambda r: r.pop(), "different case lists")

    def test_bounded_run_child_surviving_group_sigint_is_rejected(self):
        # ADR 0034 item 12: `run --timeout` must not leave the secret-bearing
        # child running after a terminal Ctrl-C (Go: the child dies with it).
        self.assertEqual(go_records()[6]["case"], "run-timeout-group-sigint")
        self.rejects(lambda r: r[6].update(orphaned_child_alive=True), "orphaned_child_alive")

    def test_oracle_drift_is_detected(self):
        go = go_records()[:6]
        go[0]["ending"] = ["exit", 1]
        with self.assertRaisesRegex(AssertionError, "oracle drifted"):
            contract.check_oracle_expectations(go)
        go = go_records()[:6]
        go[3]["orphaned_child_alive"] = False
        with self.assertRaisesRegex(AssertionError, "leaves the child"):
            contract.check_oracle_expectations(go)
        go = go_records()[:6]
        go[0]["state"] = ["inbox", "tmp", "vault"]
        with self.assertRaisesRegex(AssertionError, "persistent CA"):
            contract.check_oracle_expectations(go)

    # --- inherited SIG_IGN (M1) ---
    def test_ignored_sighup_killing_rust_is_rejected(self):  # the pre-fix behavior
        self.rejects(lambda r: r[7].update(survived=False, ending=["signal", signal.SIGHUP]), "ending")
        self.rejects(lambda r: r[9].update(survived=False, ending=["signal", signal.SIGHUP]), "ending")

    def test_ignored_sigint_not_overridden_by_notify_is_rejected(self):
        # broker Notify()s SIGINT, so it must stop; surviving would be a hang.
        self.rejects(lambda r: r[8].update(survived=True), "survived")
        # plain run does not Notify, so Go keeps the ignore.
        self.rejects(lambda r: r[10].update(survived=False, ending=["signal", signal.SIGINT]), "ending")

    def test_ignored_sigterm_and_sigquit_must_not_be_protected(self):
        self.rejects(lambda r: r[11].update(survived=True), "survived")
        self.rejects(lambda r: r[12].update(survived=True), "survived")

    def test_ignored_listener_must_stay_up_and_ignored_flag_must_match(self):
        self.rejects(lambda r: r[7].update(listener_open_after_ignored_signal=False), "listener_open_after_ignored_signal")
        self.rejects(lambda r: r[7].pop("ignored"), "ignored")

    def test_ignored_oracle_drift_is_detected(self):
        go = go_records()
        go[7]["survived"] = False
        with self.assertRaisesRegex(AssertionError, "ignored disposition"):
            contract.check_oracle_expectations(go)
        go = go_records()
        go[10]["ending"] = ["exit", 0]
        with self.assertRaisesRegex(AssertionError, "ignored disposition"):
            contract.check_oracle_expectations(go)
        go = go_records()
        go[7]["listener_open_after_ignored_signal"] = False
        with self.assertRaisesRegex(AssertionError, "listener must survive"):
            contract.check_oracle_expectations(go)
        go = go_records()
        go[7]["command"] = "intake-watch-x"
        with self.assertRaisesRegex(AssertionError, "unexpected ignored"):
            contract.check_oracle_expectations(go)

    def test_every_ignored_case_is_exercised_and_expected(self):
        self.assertEqual(len(contract.IGNORED_CASES), 12)
        self.assertEqual(set(contract.IGNORED_CASES), set(contract.GO_EXPECTED_IGNORED))
        # Go respects an inherited ignore for SIGHUP/SIGINT only.
        for (command, sig), (survived, _) in contract.GO_EXPECTED_IGNORED.items():
            if sig in ("SIGTERM", "SIGQUIT"):
                self.assertFalse(survived, (command, sig))

    def test_ignoring_wrapper_sets_sig_ign_through_exec(self):
        self.assertEqual(contract.ignoring(["x"], ()), ["x"])
        probe = ("import signal,sys;sys.stdout.write(','.join(n for n in ('SIGHUP','SIGINT','SIGTERM') "
                 "if signal.getsignal(getattr(signal,n))==signal.SIG_IGN))")
        argv = contract.ignoring([sys.executable, "-c", probe], ("SIGHUP", "SIGINT"))
        out = subprocess.run(argv, capture_output=True, check=True).stdout.decode()
        self.assertEqual(out, "SIGHUP,SIGINT")  # SIGTERM stays default

    def test_survived_signal_window_depends_on_expectation(self):
        class Stub:
            def __init__(self, exit_after):
                self.exit_after, self.timeouts = exit_after, []
                self.popen = self

            def wait(self, timeout):
                self.timeouts.append(timeout)
                if timeout >= self.exit_after:
                    return 0
                raise subprocess.TimeoutExpired("x", timeout)

        slow = Stub(exit_after=3.0)  # exits slower than SURVIVE_WINDOW but within DIE_WINDOW
        self.assertFalse(contract.survived_signal(slow, lambda sig: None, "SIGHUP", should_die=True))
        self.assertEqual(slow.timeouts, [contract.DIE_WINDOW])
        survivor = Stub(exit_after=1e9)
        self.assertTrue(contract.survived_signal(survivor, lambda sig: None, "SIGHUP"))
        self.assertEqual(survivor.timeouts, [contract.SURVIVE_WINDOW])
        self.assertLess(contract.SURVIVE_WINDOW, contract.DIE_WINDOW)

    # --- `mcp --stdio --allow-locked` (CLI-007 residual 2) ---
    def test_locked_server_keeping_os_default_is_rejected(self):  # the pre-fix behavior
        self.rejects(lambda r: r[13].update(ending=["signal", signal.SIGINT]), "ending")
        self.rejects(lambda r: r[15].update(ending=["signal", signal.SIGQUIT]), "ending")

    def test_locked_sigquit_warning_and_runtime_record_are_compared(self):
        self.rejects(lambda r: r[15].update(stderr=contract.LOCKED_WARNING), "stderr")
        self.rejects(lambda r: r[13].update(state=["tmp", "vault", "vault/.runtime-port"]), "on-disk state")

    def test_locked_sighup_must_keep_its_default_action(self):
        self.rejects(lambda r: r[14].update(ending=["exit", 0]), "ending")

    def test_locked_oracle_drift_is_detected(self):
        go = go_records()
        go[13]["ending"] = ["signal", signal.SIGINT]
        with self.assertRaisesRegex(AssertionError, "oracle drifted"):
            contract.check_oracle_expectations(go)
        go = go_records()
        go[13]["state"] = ["tmp", "vault", "vault/.runtime-port"]
        with self.assertRaisesRegex(AssertionError, "runtime port record"):
            contract.check_oracle_expectations(go)
        go = go_records()
        go[15]["stderr"] = contract.LOCKED_WARNING
        with self.assertRaisesRegex(AssertionError, "locked stderr"):
            contract.check_oracle_expectations(go)

    # --- `ui` under a pseudo-terminal (CLI-007 residual 3) ---
    def test_ui_interrupt_must_fail_like_bubbletea(self):  # the pre-fix behavior: clean exit 0
        self.rejects(lambda r: r[16].update(ending=["exit", 0], stderr=""), "ending")
        self.rejects(lambda r: r[16].update(stderr=contract.UI_INTERRUPTED), "stderr")

    def test_ui_sighup_and_sigquit_must_end_the_process_like_go(self):  # the pre-fix SIGHUP: clean exit
        self.rejects(lambda r: r[18].update(ending=["exit", 0], terminal_restored=True, alt_screen_left=True), "ending")
        self.rejects(lambda r: r[19].update(ending=["signal", signal.SIGQUIT]), "ending")

    def test_ui_terminal_state_is_compared(self):
        self.rejects(lambda r: r[17].update(terminal_restored=False), "terminal_restored")
        self.rejects(lambda r: r[17].update(alt_screen_left=False), "alt_screen_left")
        self.rejects(lambda r: r[18].update(terminal_restored=True), "terminal_restored")

    def test_ui_oracle_drift_is_detected(self):
        go = go_records()
        go[17]["terminal_restored"] = False
        with self.assertRaisesRegex(AssertionError, "oracle drifted: terminal"):
            contract.check_oracle_expectations(go)
        go = go_records()
        go[16]["stderr"] = contract.UI_INTERRUPTED
        with self.assertRaisesRegex(AssertionError, "ui interrupt message"):
            contract.check_oracle_expectations(go)
        go = go_records()
        go[17]["stderr"] = "noise"
        with self.assertRaisesRegex(AssertionError, "ui stderr"):
            contract.check_oracle_expectations(go)

    def test_every_new_killing_case_is_expected(self):
        for command in ("mcp-locked", "ui"):
            for sig in contract.KILLING:
                self.assertIn((command, sig), contract.GO_EXPECTED)

    # --- Go-only armed-clipboard observation (CLI-007 residual 1) ---
    @staticmethod
    def clipboard_records():
        return [dict(case=f"mcp-clipboard-armed-{sig.lower()}", command="mcp-clipboard-armed", signal=sig,
                     serving_after_signal=serving, ending=final, clipboard_events=["secret", "clear"])
                for sig, (serving, final) in contract.GO_EXPECTED_CLIPBOARD.items()]

    def test_go_only_clipboard_expectations_hold_and_detect_drift(self):
        contract.check_go_only(self.clipboard_records())
        for index, change in ((0, dict(serving_after_signal=True, ending=None)),  # SIGINT must shut down
                              (1, dict(ending=["exit", 1])),
                              (2, dict(serving_after_signal=False, ending=["signal", signal.SIGHUP])),
                              (0, dict(clipboard_events=["secret"])),  # the clear must happen
                              (1, dict(clipboard_events=["clear", "secret"]))):
            records = self.clipboard_records()
            records[index].update(change)
            with self.assertRaisesRegex(AssertionError, "oracle drifted"):
                contract.check_go_only(records)
        with self.assertRaises(AssertionError):
            contract.check_go_only(self.clipboard_records()[:2])

    def test_ending_and_normalization(self):
        self.assertEqual(contract.ending(-1), ["signal", 1])
        self.assertEqual(contract.ending(2), ["exit", 2])
        home = Path("/h")
        text = contract.normal(b"on http://127.0.0.1:5123 ca /h/vault/.broker-ca-Ab1/broker-ca.pem\r\n", home)
        self.assertEqual(text, "on http://127.0.0.1:__PORT__ ca __CA__\n")
        self.assertEqual(contract.normal(b"/h/vault/broker-ca.pem", home), "__CA__")

    def test_snapshot_keeps_signal_state_and_drops_vault_internals(self):
        with tempfile.TemporaryDirectory() as raw:
            home = Path(raw)
            for name in ("vault/.git/HEAD", "vault/manifest.age", "vault/.lock", "tmp/symvault-intake-Xy12/a",
                         "vault/.broker-ca-Q/broker-ca.pem", "child.pid", "child.py", "vault/stray.tmp"):
                path = home / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("x")
            names = contract.snapshot(home)
            self.assertIn("tmp/symvault-intake-__ID__", names)
            self.assertIn("vault/.broker-ca-Q", names)
            self.assertIn("vault/stray.tmp", names)
            self.assertNotIn("vault/manifest.age", names)
            self.assertNotIn("vault/.git/HEAD", names)
            self.assertFalse({"child.pid", "child.py"} & set(names))


if __name__ == "__main__":
    unittest.main()
