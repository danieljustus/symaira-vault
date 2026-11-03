#!/usr/bin/env python3
"""Unit tests for valuegate.py using fake shell-script binaries.

Fakes are algorithm/driver fixtures only; they are never a Go or Rust
measurement. Run: python3 -B scripts/rust-port/test_valuegate.py
"""
from __future__ import annotations

import contextlib
import copy
import io
import json
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
import valuegate as vg  # noqa: E402

FAKE = """#!/bin/sh
# fake symvault: init/set succeed; everything else sleeps then optionally fails
case "$1" in
  init|set) exit 0 ;;
esac
{fail}
{sleep}
echo ok
"""


def make_fake(directory, name, sleep="", fail=""):
    path = Path(directory, name)
    path.write_text(FAKE.format(sleep=sleep, fail=fail))
    path.chmod(path.stat().st_mode | stat.S_IXUSR)
    return path


def run_main(argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = vg.main(argv)
    return code, out.getvalue(), err.getvalue()


def cmd_result(p95, rss, name="list", n=100, failures=0, rss_n=20):
    return {
        "name": name, "argv": name.split(),
        **{side: {
            "latency_ms": {"n": n, "failures": failures, "p50": p * 0.8, "p95": p, "runs_requested": n},
            "rss_bytes": {"n": rss_n, "median": r, "samples": [r] * rss_n, "error": None},
        } for side, p, r in (("go", p95[0], rss[0]), ("rust", p95[1], rss[1]))},
    }


def doc(go_size=1000, rust_size=1000, commands=None, valid=True):
    return {
        "schema_version": 1, "kind": vg.KIND, "valid": valid, "invalid_reasons": [] if valid else ["x"],
        "binaries": {"go": {"size_bytes": go_size}, "rust": {"size_bytes": rust_size}},
        "commands": commands if commands is not None else [cmd_result((10.0, 10.0), (1000, 1000))],
    }


T = {"minimum_binary_or_rss_improvement": 0.2, "maximum_startup_or_command_p95_regression": 0.1}


class EvaluateRule(unittest.TestCase):
    def test_baseline_thresholds_match_matrix_rule(self):
        self.assertEqual(vg.load_thresholds(), T)

    def test_size_gain_with_flat_p95_passes(self):
        v = vg.evaluate(doc(1000, 700), T)
        self.assertTrue(v["pass"])
        self.assertAlmostEqual(v["size"]["improvement"], 0.3)

    def test_rss_gain_alone_passes(self):
        v = vg.evaluate(doc(1000, 1000, [cmd_result((10, 10), (1000, 700))]), T)
        self.assertTrue(v["pass"])
        self.assertFalse(v["commands"][0]["size_ok"])
        self.assertTrue(v["commands"][0]["rss_ok"])

    def test_boundaries_are_inclusive(self):
        # exactly 20% size gain, exactly 10% p95 regression
        v = vg.evaluate(doc(1000, 800, [cmd_result((10.0, 11.0), (1000, 1000))]), T)
        self.assertTrue(v["pass"], v)

    def test_just_below_gain_fails(self):
        v = vg.evaluate(doc(1000, 801, [cmd_result((10, 10), (1000, 801))]), T)
        self.assertFalse(v["pass"])

    def test_p95_regression_over_ten_percent_fails(self):
        v = vg.evaluate(doc(1000, 100, [cmd_result((10.0, 11.5), (1000, 1000))]), T)
        self.assertFalse(v["pass"])
        self.assertFalse(v["commands"][0]["p95_ok"])

    def test_per_command_reporting_and_overall_requires_all(self):
        cmds = [cmd_result((10, 10), (1000, 500), "list"), cmd_result((10, 20), (1000, 500), "get x")]
        v = vg.evaluate(doc(1000, 1000, cmds), T)
        self.assertEqual([r["pass"] for r in v["commands"]], [True, False])
        self.assertFalse(v["pass"])

    def test_no_gain_anywhere_fails(self):
        v = vg.evaluate(doc(1000, 900, [cmd_result((10, 9), (1000, 900))]), T)
        self.assertFalse(v["pass"])


class InvalidInput(unittest.TestCase):
    def assertInvalid(self, d):
        with self.assertRaises(vg.ValueGateError):
            vg.evaluate(d, T)

    def test_invalid_marked_measurement(self):
        self.assertInvalid(doc(valid=False))

    def test_wrong_kind_and_schema(self):
        d = doc()
        d["kind"] = "other"
        self.assertInvalid(d)
        d = doc()
        d["schema_version"] = 2
        self.assertInvalid(d)

    def test_not_an_object(self):
        self.assertInvalid([])

    def test_missing_pieces(self):
        for mutate in (
            lambda d: d.pop("binaries"),
            lambda d: d["binaries"].pop("rust"),
            lambda d: d.__setitem__("commands", []),
            lambda d: d["commands"][0].pop("go"),
            lambda d: d["commands"][0]["rust"]["latency_ms"].__setitem__("p95", None),
            lambda d: d["commands"][0]["go"]["latency_ms"].__setitem__("p95", 0),
            lambda d: d["commands"][0]["go"]["rss_bytes"].__setitem__("n", 0),
            lambda d: d["commands"][0]["rust"]["latency_ms"].__setitem__("failures", 2),
            lambda d: d["binaries"]["go"].__setitem__("size_bytes", 0),
            lambda d: d["binaries"]["go"].__setitem__("size_bytes", float("nan")),
        ):
            d = copy.deepcopy(doc())
            mutate(d)
            self.assertInvalid(d)

    def test_check_cli_exit_codes(self):
        with tempfile.TemporaryDirectory() as tmp:
            good, bad, broken = (Path(tmp, n) for n in ("good.json", "bad.json", "broken.json"))
            good.write_text(json.dumps(doc(1000, 500)))
            bad.write_text(json.dumps(doc(1000, 990, [cmd_result((10, 10), (1000, 990))])))
            broken.write_text("{not json")
            self.assertEqual(run_main(["check", str(good)])[0], vg.EXIT_PASS)
            code, out, _ = run_main(["check", str(bad)])
            self.assertEqual(code, vg.EXIT_FAIL)
            self.assertIn("overall: FAIL", out)
            self.assertEqual(run_main(["check", str(bad), "--report-only"])[0], vg.EXIT_PASS)
            self.assertEqual(run_main(["check", str(broken)])[0], vg.EXIT_INVALID)
            self.assertEqual(run_main(["check", str(Path(tmp, "missing.json"))])[0], vg.EXIT_INVALID)
            code, out, _ = run_main(["check", str(good), "--json-out"])
            self.assertTrue(json.loads(out)["pass"])


class Helpers(unittest.TestCase):
    def test_percentile_nearest_rank(self):
        values = list(range(1, 101))
        self.assertEqual(vg.percentile(values, 50), 50)
        self.assertEqual(vg.percentile(values, 95), 95)
        self.assertEqual(vg.percentile([7], 95), 7)
        with self.assertRaises(vg.ValueGateError):
            vg.percentile([], 50)

    def test_parse_time_rss(self):
        mac = "        0.00 real\n  2277376  maximum resident set size\n"
        self.assertEqual(vg.parse_time_rss(mac, "Darwin"), 2277376)
        linux = "\tMaximum resident set size (kbytes): 2048\n"
        self.assertEqual(vg.parse_time_rss(linux, "Linux"), 2048 * 1024)
        self.assertIsNone(vg.parse_time_rss("nothing", "Darwin"))

    def test_stripped_detection_unknown_for_scripts(self):
        with tempfile.TemporaryDirectory() as tmp:
            fake = make_fake(tmp, "fake")
            self.assertIsNone(vg.detect_stripped(fake)[0])

    def test_stripped_detection_elf(self):
        import struct

        def elf(with_symtab):
            shoff, shentsize, shnum = 64, 64, 2
            head = bytearray(64)
            head[:4] = b"\x7fELF"
            head[4], head[5] = 2, 1
            struct.pack_into("<Q", head, 0x28, shoff)
            struct.pack_into("<HH", head, 0x3A, shentsize, shnum)
            sh = bytearray(shentsize * shnum)
            struct.pack_into("<I", sh, 4, 1)
            struct.pack_into("<I", sh, 64 + 4, 2 if with_symtab else 3)
            return bytes(head) + bytes(sh)

        with tempfile.TemporaryDirectory() as tmp:
            for flag in (True, False):
                p = Path(tmp, f"elf-{flag}")
                p.write_bytes(elf(flag))
                self.assertEqual(vg.detect_stripped(p)[0], not flag)

    def test_stripped_detection_macho(self):
        import struct

        def macho(nlist_types):
            symoff = 32 + 24
            cmd = struct.pack("<IIIIII", 0x2, 24, symoff, len(nlist_types), symoff + 16 * len(nlist_types), 0)
            header = struct.pack("<IiiIIIII", 0xFEEDFACF, 0x100000C, 0, 2, 1, len(cmd), 0, 0)
            syms = b"".join(struct.pack("<IBBHQ", 0, t, 1, 0, 0) for t in nlist_types)
            return header + cmd + syms

        with tempfile.TemporaryDirectory() as tmp:
            stripped = Path(tmp, "s")
            stripped.write_bytes(macho([0x0F, 0x01, 0x01]))  # one defined + undefined imports
            full = Path(tmp, "f")
            full.write_bytes(macho([0x0F, 0x0F, 0x0F]))
            stab = Path(tmp, "d")
            stab.write_bytes(macho([0x24]))
            self.assertTrue(vg.detect_stripped(stripped)[0])
            self.assertFalse(vg.detect_stripped(full)[0])
            self.assertFalse(vg.detect_stripped(stab)[0])


class MeasureWithFakes(unittest.TestCase):
    def measure(self, tmp, go, rust, *extra, load=(0.5, 0.5, 0.5)):
        out = Path(tmp, "out", "m.json")
        with mock.patch.object(vg, "get_loadavg", return_value=list(load)):
            code, so, se = run_main([
                "measure", "--go", str(go), "--rust", str(rust), "--out", str(out),
                "--runs", "4", "--rss-samples", "3", "--warmup", "1", *extra,
            ])
        return code, out, so, se

    def test_smoke_schema_and_check(self):
        with tempfile.TemporaryDirectory() as tmp:
            go = make_fake(tmp, "go", sleep="sleep 0.03")
            rust = make_fake(tmp, "rust")
            code, out, _, _ = self.measure(tmp, go, rust, "--commands", "version", "list", "get vg/entry-1.password")
            self.assertEqual(code, vg.EXIT_PASS)
            d = json.loads(out.read_text())
            self.assertEqual(d["schema_version"], 1)
            self.assertEqual(d["kind"], vg.KIND)
            self.assertEqual([c["name"] for c in d["commands"]], ["version", "list", "get vg/entry-1.password"])
            for c in d["commands"]:
                for side in ("go", "rust"):
                    self.assertEqual(c[side]["latency_ms"]["failures"], 0)
                    self.assertEqual(c[side]["latency_ms"]["n"], 4)
                    self.assertEqual(c[side]["rss_bytes"]["n"], 3)
                    self.assertGreater(c[side]["rss_bytes"]["median"], 0)
                    self.assertLessEqual(c[side]["latency_ms"]["p50"], c[side]["latency_ms"]["p95"])
            self.assertEqual(d["seed"]["go"]["entries"], vg.SEED_ENTRIES)
            self.assertIn("uname", d["host"])
            self.assertEqual(len(d["load"]["before"]), 3)
            self.assertEqual(d["binaries"]["go"]["size_bytes"], go.stat().st_size)
            self.assertIsNone(d["binaries"]["go"]["stripped"])
            # too few samples => explicitly invalid, check refuses it
            self.assertFalse(d["valid"])
            self.assertTrue(any("latency runs 4" in r for r in d["invalid_reasons"]))
            self.assertTrue(any("RSS samples 3" in r for r in d["invalid_reasons"]))
            self.assertEqual(run_main(["check", str(out)])[0], vg.EXIT_INVALID)

    def test_valid_run_passes_check_against_slower_go(self):
        with tempfile.TemporaryDirectory() as tmp:
            go = make_fake(tmp, "go", sleep="sleep 0.05")
            rust = make_fake(tmp, "rust")
            # make the Rust fake much smaller so the size rule can pass too
            go.write_text(go.read_text() + "# " + "x" * 5000 + "\n")
            out = Path(tmp, "m.json")
            with mock.patch.object(vg, "get_loadavg", return_value=[0.1, 0.1, 0.1]), \
                    mock.patch.object(vg, "MIN_LATENCY_RUNS", 3), mock.patch.object(vg, "MIN_RSS_SAMPLES", 2):
                code, _, _ = run_main(["measure", "--go", str(go), "--rust", str(rust), "--out", str(out),
                                       "--runs", "3", "--rss-samples", "2", "--warmup", "0",
                                       "--commands", "list"])
            self.assertEqual(code, vg.EXIT_PASS)
            d = json.loads(out.read_text())
            self.assertTrue(d["valid"], d["invalid_reasons"])
            code, text, _ = run_main(["check", str(out)])
            self.assertEqual(code, vg.EXIT_PASS, text)
            self.assertIn("overall: PASS", text)

    def test_valid_run_fails_check_when_rust_slower_and_same_size(self):
        with tempfile.TemporaryDirectory() as tmp:
            go = make_fake(tmp, "go")
            rust = make_fake(tmp, "rust", sleep="sleep 0.05")
            out = Path(tmp, "m.json")
            with mock.patch.object(vg, "get_loadavg", return_value=[0.1, 0.1, 0.1]), \
                    mock.patch.object(vg, "MIN_LATENCY_RUNS", 3), mock.patch.object(vg, "MIN_RSS_SAMPLES", 2):
                run_main(["measure", "--go", str(go), "--rust", str(rust), "--out", str(out),
                          "--runs", "3", "--rss-samples", "2", "--warmup", "0", "--commands", "list"])
            code, text, _ = run_main(["check", str(out)])
            self.assertEqual(code, vg.EXIT_FAIL, text)

    def test_loaded_host_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            go, rust = make_fake(tmp, "go"), make_fake(tmp, "rust")
            code, out, _, err = self.measure(tmp, go, rust, load=(7.5, 5.0, 4.0))
            self.assertEqual(code, vg.EXIT_LOADED)
            self.assertFalse(out.exists())
            self.assertIn("refusing", err)

    def test_loaded_host_allowed_is_marked_invalid(self):
        with tempfile.TemporaryDirectory() as tmp:
            go, rust = make_fake(tmp, "go"), make_fake(tmp, "rust")
            code, out, _, _ = self.measure(tmp, go, rust, "--allow-loaded", "--commands", "list", load=(7.5, 5.0, 4.0))
            self.assertEqual(code, vg.EXIT_PASS)
            d = json.loads(out.read_text())
            self.assertFalse(d["valid"])
            self.assertTrue(any("load average before" in r for r in d["invalid_reasons"]))
            self.assertEqual(run_main(["check", str(out)])[0], vg.EXIT_INVALID)

    def test_load_rising_during_run_is_flagged(self):
        with tempfile.TemporaryDirectory() as tmp:
            go, rust = make_fake(tmp, "go"), make_fake(tmp, "rust")
            out = Path(tmp, "m.json")
            with mock.patch.object(vg, "get_loadavg", side_effect=[[1.0, 1, 1], [9.0, 5, 3]]):
                run_main(["measure", "--go", str(go), "--rust", str(rust), "--out", str(out),
                          "--runs", "2", "--rss-samples", "2", "--warmup", "0", "--commands", "list"])
            d = json.loads(out.read_text())
            self.assertFalse(d["valid"])
            self.assertTrue(any("load average after" in r for r in d["invalid_reasons"]))

    def test_failing_command_is_invalid(self):
        with tempfile.TemporaryDirectory() as tmp:
            go = make_fake(tmp, "go")
            rust = make_fake(tmp, "rust", fail='[ "$1" = list ] && exit 3')
            code, out, _, _ = self.measure(tmp, go, rust, "--commands", "list")
            self.assertEqual(code, vg.EXIT_PASS)
            d = json.loads(out.read_text())
            self.assertFalse(d["valid"])
            self.assertTrue(any("failed" in r for r in d["invalid_reasons"]))
            self.assertEqual(d["commands"][0]["rust"]["latency_ms"]["failures"], 4)

    def test_seed_failure_and_bad_binary_are_errors(self):
        with tempfile.TemporaryDirectory() as tmp:
            good = make_fake(tmp, "good")
            bad_seed = Path(tmp, "bad")
            bad_seed.write_text("#!/bin/sh\nexit 9\n")
            bad_seed.chmod(0o755)
            code, _, _, err = self.measure(tmp, good, bad_seed)
            self.assertEqual(code, vg.EXIT_INVALID)
            self.assertIn("seed step", err)
            code, _, _, err = self.measure(tmp, good, Path(tmp, "nope"))
            self.assertEqual(code, vg.EXIT_INVALID)
            self.assertIn("not an executable", err)

    def test_wait4_rss_method(self):
        with tempfile.TemporaryDirectory() as tmp:
            go, rust = make_fake(tmp, "go"), make_fake(tmp, "rust")
            code, out, _, _ = self.measure(tmp, go, rust, "--rss-method", "wait4", "--commands", "list")
            self.assertEqual(code, vg.EXIT_PASS)
            d = json.loads(out.read_text())
            self.assertEqual(d["config"]["rss_method"], "wait4")
            self.assertGreater(d["commands"][0]["go"]["rss_bytes"]["median"], 0)

    def test_sandbox_isolated_from_operator_home(self):
        with tempfile.TemporaryDirectory() as tmp:
            env = vg.Sandbox(tmp, "x").env()
            self.assertTrue(env["HOME"].startswith(tmp))
            self.assertTrue(env["SYMVAULT_VAULT"].startswith(tmp))
            self.assertNotEqual(env["HOME"], os.environ.get("HOME"))


if __name__ == "__main__":
    unittest.main(verbosity=1)
