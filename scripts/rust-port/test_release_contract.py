#!/usr/bin/env python3
"""Self-test of release_contract.py on a synthetic dist (no goreleaser, no build).

The synthetic dist is byte-for-byte minimal but structurally real: tar.gz
archives, ar/deb, rpm headers, apk tar.gz, MCPB zips and CycloneDX SBOMs. The
checker must accept it, and every tamper in `negative_cases` must be rejected.
Run: python3 scripts/rust-port/test_release_contract.py
"""
from __future__ import annotations

import gzip
import hashlib
import io
import json
import os
import struct
import sys
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
import release_contract as rc  # noqa: E402

VERSION = "9.9.9-next"
ARCH_PKG = {"deb": {"amd64": "amd64", "arm64": "arm64"}, "rpm": {"amd64": "x86_64", "arm64": "aarch64"},
            "apk": {"amd64": "x86_64", "arm64": "aarch64"}}


def fake_binary(goos, goarch):
    if goos == "darwin":
        head = struct.pack("<II", 0xFEEDFACF, 0x0100000C)
    else:
        machine = rc.ELF_MACHINE[goarch]
        head = bytearray(64)
        head[:7] = b"\x7fELF\x02\x01\x01"
        struct.pack_into("<H", head, 18, machine)
        struct.pack_into("<Q", head, 32, 64)  # phoff
        struct.pack_into("<HH", head, 54, 56, 0)  # phentsize, phnum=0: static, no PT_INTERP
        head = bytes(head)
    return head + f"|{goos}-{goarch}|".encode() * 4


def tar_bytes(entries, mode="w"):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode=mode) as tf:
        for name, data, perm in entries:
            info = tarfile.TarInfo(name)
            info.size, info.mode = len(data), perm
            tf.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def make_archive(path, goos, goarch, binary):
    wrap = path.name[: -len(".tar.gz")]
    entries = [(f"{wrap}/symvault", binary, 0o755), (f"{wrap}/LICENSE", b"Apache-2.0", 0o644),
               (f"{wrap}/README.md", b"readme", 0o644), (f"{wrap}/docs/man/symvault.1", b".TH SYMVAULT", 0o644)]
    entries += [(f"{wrap}/completions/symvault.{ext}", b"# completion", 0o644) for ext in ("bash", "zsh", "fish")]
    path.write_bytes(gzip.compress(tar_bytes(entries), mtime=0))


def make_sbom(path):
    comps = [{"type": "library", "name": n, "version": "1.0.0", "purl": f"pkg:cargo/{n}@1.0.0"}
             for n in sorted(rc.REQUIRED_SBOM_CRATES) + ["serde", "zip"]]
    path.write_text(json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.7", "components": comps}))


def make_mcpb(path, binary):
    manifest = {"manifest_version": "0.3", "name": "symvault", "version": VERSION,
                "server": {"type": "binary", "entry_point": "server/symvault",
                           "mcp_config": {"command": "${__dirname}/server/symvault", "args": ["serve", "--stdio"]}}}
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("manifest.json", json.dumps(manifest))
        info = zipfile.ZipInfo("server/symvault")
        info.external_attr = 0o755 << 16
        zf.writestr(info, binary)


def make_deb(path, goarch, binary, depends):
    control = (f"Package: symvault\nVersion: {VERSION}\nArchitecture: {ARCH_PKG['deb'][goarch]}\n"
               "Maintainer: danieljustus <x@example.com>\nDescription: Secure password management CLI tool\n"
               "Homepage: https://example.com\n" + (f"Depends: {depends}\n" if depends else ""))
    ctl = gzip.compress(tar_bytes([("./control", control.encode(), 0o644)]), mtime=0)
    data = gzip.compress(tar_bytes([("./usr/bin/symvault", binary, 0o755)]), mtime=0)
    path.write_bytes(rc.build_ar([("debian-binary", b"2.0\n"), ("control.tar.gz", ctl), ("data.tar.gz", data)]))


def make_apk(path, goarch, binary, depends):
    info = (f"pkgname = symvault\npkgver = {VERSION}-r0\narch = {ARCH_PKG['apk'][goarch]}\nlicense = Apache-2.0\n"
            "maintainer = danieljustus <x@example.com>\npkgdesc = Secure password management CLI tool\n"
            "url = https://example.com\n" + "".join(f"depend = {d}\n" for d in depends))
    path.write_bytes(gzip.compress(tar_bytes([(".PKGINFO", info.encode(), 0o644), ("usr/bin/symvault", binary, 0o755)]),
                                   mtime=0))


def rpm_header(tags):
    """tags: {tag: (type, value)}; returns a serialized rpm header structure."""
    index, store = [], bytearray()
    for tag in sorted(tags):
        typ, value = tags[tag]
        off = len(store)
        if typ in (6, 9):
            store += value.encode() + b"\0"
            count = 1
        elif typ == 8:
            for item in value:
                store += item.encode() + b"\0"
            count = len(value)
        else:  # INT32 array
            store += struct.pack(f">{len(value)}I", *value)
            count = len(value)
        index.append(struct.pack(">IIII", tag, typ, off, count))
    return b"\x8e\xad\xe8\x01" + b"\0" * 4 + struct.pack(">II", len(index), len(store)) + b"".join(index) + bytes(store)


def make_rpm(path, goarch, depends):
    tags = {1000: (6, "symvault"), 1001: (6, VERSION.replace("-", "~")), 1022: (6, ARCH_PKG["rpm"][goarch]),
            1014: (6, "Apache-2.0"), 1011: (6, "danieljustus"), 1005: (9, "Secure password management CLI tool"),
            1020: (6, "https://example.com"), 1118: (8, ["/usr/bin/"]), 1116: (4, [0]), 1117: (8, ["symvault"]),
            1049: (8, list(depends))}
    lead = b"\xed\xab\xee\xdb" + b"\0" * 92
    sig = rpm_header({})
    pad = b"\0" * ((8 - (96 + len(sig)) % 8) % 8)
    path.write_bytes(lead + sig + pad + rpm_header(tags))


def build_dist(dist, deb_depends="git"):
    dist.mkdir(parents=True)
    binaries = {}
    sums = []
    for goos, goarch in rc.TARGETS:
        binaries[(goos, goarch)] = fake_binary(goos, goarch)
        archive = dist / f"{rc.PROJECT}_{VERSION}_{goos}_{goarch}.tar.gz"
        make_archive(archive, goos, goarch, binaries[(goos, goarch)])
        make_sbom(dist / f"{archive.name}.sbom.json")
        make_mcpb(dist / f"{rc.PACKAGE}_{VERSION}_{goos}_{goarch}.mcpb", binaries[(goos, goarch)])
        if goos == "linux":
            b = binaries[(goos, goarch)]
            make_deb(dist / f"{rc.PACKAGE}_{VERSION}_linux_{goarch}.deb", goarch, b, deb_depends)
            make_rpm(dist / f"{rc.PACKAGE}_{VERSION}_linux_{goarch}.rpm", goarch, ["git"])
            make_apk(dist / f"{rc.PACKAGE}_{VERSION}_linux_{goarch}.apk", goarch, b, ["git"])
    for name in sorted(rc.expected_checksummed(VERSION)):
        sums.append(f"{hashlib.sha256((dist / name).read_bytes()).hexdigest()}  {name}\n")
    (dist / f"{rc.PROJECT}_{VERSION}_checksums.txt").write_text("".join(sums))
    # GoReleaser bookkeeping that must stay tolerated.
    for name in rc.GORELEASER_INTERNAL_FILES:
        (dist / name).write_text("{}")
    (dist / "man").mkdir()
    (dist / "man" / "symvault.1").write_text(".TH")
    (dist / "symvault-static_linux_amd64_v1").mkdir()
    (dist / "symvault-darwin_darwin_arm64_v8.0").mkdir()
    return binaries


class ReleaseContractSelfTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.dist = self.root / "dist"
        build_dist(self.dist)

    def tearDown(self):
        self._tmp.cleanup()

    def check(self, dist=None):
        chk, _ = rc.check_dist(dist or self.dist, native_runs=False, docker_runs=False)
        return chk

    def test_synthetic_dist_passes(self):
        chk = self.check()
        self.assertEqual([i for i in chk.failed], [])
        names = " | ".join(i["check"] for i in chk.items)
        for needle in ("dist listing is exactly the 16 expected release files", "hard dependency on git",
                       "lists the binary's Rust crates", "checksums file lists exactly the 12"):
            self.assertIn(needle, names)

    def test_missing_git_dependency_is_rejected(self):
        other = self.root / "nodep"
        build_dist(other, deb_depends="")
        failed = [i["check"] for i in self.check(other).failed]
        self.assertTrue(any("linux_amd64.deb: hard dependency on git" in f for f in failed), failed)

    def test_recommends_only_is_not_a_dependency(self):
        self.assertFalse(rc.has_dependency([], "git"))
        self.assertFalse(rc.has_dependency(["gitk"], "git"))
        self.assertTrue(rc.has_dependency(["git (>= 1:2.30)"], "git"))
        self.assertTrue(rc.has_dependency(["git>=2.30"], "git"))

    def test_negative_controls_all_rejected(self):
        results = rc.negative_controls(self.dist, VERSION, scratch_root=self.root)
        self.assertGreaterEqual(len(results), 17)
        not_rejected = [r["control"] for r in results if not r["rejected"]]
        self.assertEqual(not_rejected, [])
        labels = {r["control"] for r in results}
        for needle in ("extra mcpb for an unsupported platform", "extra deb for an unsupported platform",
                       "extra sbom for an unsupported platform", "SBOM edited", "swapped inside an mcpb",
                       "swapped inside a deb"):
            self.assertTrue(any(needle in label for label in labels), needle)

    def test_recomputed_controls_are_rejected_on_content(self):
        results = {r["control"]: r for r in rc.negative_controls(self.dist, VERSION, scratch_root=self.root)}
        for label, r in results.items():
            if r["recomputes_checksums"]:
                self.assertTrue(r["rejected"], label)
                self.assertNotIn("checksum lines match", r["first_failure"], label)

    def test_recomputed_checksums_alone_do_not_hide_tampering(self):
        # Sanity for the control itself: recomputing on an untouched dist stays green.
        copy = self.root / "copy"
        copy.mkdir()
        for f in self.dist.iterdir():
            if f.is_file():
                (copy / f.name).write_bytes(f.read_bytes())
        rc.recompute_checksums(copy, VERSION)
        self.assertEqual(self.check(copy).failed, [])

    def run_main(self, *args):
        report = self.root / "report.json"
        env = {"RELEASE_CONTRACT_ALLOW_ANY_DIST": "1"}
        with mock.patch.dict(os.environ, env), mock.patch.object(rc, "run_binaries", lambda *a, **k: None), \
                mock.patch.object(rc, "DEFAULT_DIST", self.root / "default-dist"), \
                mock.patch.object(sys, "argv", ["release_contract.py", "--check-only", "--dist", str(self.dist),
                                                "--report", str(report), *args]):
            code = rc.main()
        return code, json.loads(report.read_text())

    def test_full_run_is_pass(self):
        code, report = self.run_main()
        self.assertEqual((code, report["status"], report["ok"]), (0, "pass", True))

    def test_skipped_docker_runs_are_partial_not_ok(self):
        code, report = self.run_main("--no-docker")
        self.assertEqual((code, report["status"], report["ok"]), (3, "partial", False))
        self.assertEqual(report["skipped"], ["docker runs"])

    def test_skipped_negative_controls_are_partial_not_ok(self):
        code, report = self.run_main("--no-negative-controls")
        self.assertEqual((code, report["status"], report["ok"]), (3, "partial", False))

    def test_failing_dist_is_fail(self):
        (self.dist / "notes.txt").write_text("stray")
        code, report = self.run_main()
        self.assertEqual((code, report["status"], report["ok"]), (1, "fail", False))

    def test_smoke_script_contents(self):
        with_git = rc.smoke_script(True)
        self.assertIn("apk add --no-cache git", with_git)
        for op in ("init", "set smoke.password --stdin-value", "get smoke.password"):
            self.assertIn(op, with_git)
        self.assertNotIn("apk add", rc.smoke_script(False))


if __name__ == "__main__":
    unittest.main(verbosity=2)
