#!/usr/bin/env python3
"""DIST-001/DIST-002 release-contract checker.

Runs the real release pipeline as a snapshot (no publish, no signing, no tag,
no push) with `dist:` moved outside the repository, then verifies:

  * the dist directory listing is EXACTLY the expected release set: any
    missing file, and any extra file (a deb/mcpb/sbom/archive for an
    unsupported platform, a stray file or directory), is a failure. Only
    GoReleaser's own bookkeeping (artifacts.json, config.yaml, metadata.json,
    man/, per-build output dirs) is tolerated
  * archive names `symaira-vault_<ver>_<os>_<arch>.tar.gz` for exactly
    darwin/arm64, linux/amd64, linux/arm64 and their members
  * checksums file lists exactly the archives, packages and SBOMs, and every
    digest is correct
  * nfpm deb/rpm/apk metadata (hard `git` dependency, ADR 0033) and the
    packaged binary
  * MCPB bundles (manifest + executable server binary == archive binary)
  * CycloneDX SBOM per archive, listing the Rust crates of the binary
  * binary format per target (static ELF / arm64 Mach-O) and real runs:
    `symvault version` (darwin-arm64 natively, linux-arm64 in ubuntu:24.04,
    linux-amd64 in ubuntu:24.04 under QEMU, labelled emulated), then an
    init/set/get round trip with git installed and the clear "git is required"
    error without it (alpine:3.21 containers, native on darwin)

Then it proves the checker can fail: tampered copies of the dist must each be
rejected: missing archive member, flipped byte, missing SBOM/archive/deb/mcpb,
extra platform files, a stray file or directory, an SBOM edited with the
checksums recomputed, and a binary swapped inside an mcpb and inside a deb.
Controls that recompute checksums must be rejected on content, not on a
checksum mismatch.

The run status is `pass` only when every check ran and passed. Skipped runs
(--no-docker) give `partial`, which exits 3 and sets "ok": false.

Publication, tagging, signing and notarization stay out of scope.
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import lzma
import os
import platform
import re
import shutil
import struct
import subprocess
import sys
import tarfile
import tempfile
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_DIST = Path("/Volumes/1TB_NVMe_SN850X/Dev/Symaira_Dev/builds/symaira-vault/dist")
TARGETS = [("darwin", "arm64"), ("linux", "amd64"), ("linux", "arm64")]
PROJECT = "symaira-vault"
PACKAGE = "symvault"
PACKAGE_FORMATS = ["deb", "rpm", "apk"]
# apk/rpm/deb spell the architectures differently.
PKG_ARCH = {
    "deb": {"amd64": "amd64", "arm64": "arm64"},
    "rpm": {"amd64": "x86_64", "arm64": "aarch64"},
    "apk": {"amd64": "x86_64", "arm64": "aarch64"},
}
ARCHIVE_MEMBERS = ["symvault", "LICENSE", "README.md", "completions/symvault.bash",
                   "completions/symvault.zsh", "completions/symvault.fish"]
EXPECTED_MAN = {"symvault.1"}  # every archive must ship at least these pages under docs/man
# Files GoReleaser itself leaves in dist/. Anything else not in the expected
# release set is a failure.
GORELEASER_INTERNAL_FILES = {"artifacts.json", "config.yaml", "metadata.json"}
BUILD_DIR_RE = re.compile(r"symvault-(static|darwin)_[A-Za-z0-9_.\-]+")
REQUIRED_SBOM_CRATES = {"symvault-cli", "symvault-core", "age", "clap", "zeroize"}
SMOKE_SECRET = "Xk9-correct-horse-Battery"
SMOKE_PASSPHRASE = "test-passphrase-123"
SMOKE_IMAGE = "alpine:3.21"
GIT_MISSING_MESSAGE = "git is required but was not found in PATH"
ELF_MACHINE = {"amd64": 62, "arm64": 183}
MACHO_ARM64 = (0x0100000C, 0xFEEDFACF)


def expected_files(version):
    """Return {file name: kind} for the exact set a release snapshot must hold."""
    names = {f"{PROJECT}_{version}_checksums.txt": "checksums"}
    for goos, goarch in TARGETS:
        archive = f"{PROJECT}_{version}_{goos}_{goarch}.tar.gz"
        names[archive] = "archive"
        names[f"{archive}.sbom.json"] = "sbom"
        names[f"{PACKAGE}_{version}_{goos}_{goarch}.mcpb"] = "mcpb"
        if goos == "linux":
            for fmt in PACKAGE_FORMATS:
                names[f"{PACKAGE}_{version}_linux_{goarch}.{fmt}"] = "package"
    return names


def expected_checksummed(version):
    """MCPB bundles are built by a post hook, not a GoReleaser artifact, so
    checksums.txt covers archives, packages and SBOMs only."""
    return {n for n, k in expected_files(version).items() if k in ("archive", "package", "sbom")}


class Checks:
    def __init__(self):
        self.items = []

    def add(self, name, ok, detail: object = ""):
        self.items.append({"check": name, "ok": bool(ok), "detail": str(detail)})
        return bool(ok)

    @property
    def failed(self):
        return [i for i in self.items if not i["ok"]]


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def read_ar(data):
    """Minimal ar(1) reader for .deb files."""
    assert data[:8] == b"!<arch>\n", "not an ar archive"
    pos, out = 8, {}
    while pos + 60 <= len(data):
        hdr = data[pos:pos + 60]
        name = hdr[:16].decode().strip().rstrip("/")
        size = int(hdr[48:58].decode().strip())
        out[name] = data[pos + 60:pos + 60 + size]
        pos += 60 + size + (size & 1)
    return out


def decompress_tar(name, blob):
    if name.endswith(".gz"):
        return tarfile.open(fileobj=io.BytesIO(blob), mode="r:gz")
    if name.endswith(".xz"):
        return tarfile.open(fileobj=io.BytesIO(lzma.decompress(blob)))
    if name.endswith(".zst"):
        raw = subprocess.run(["zstd", "-dc"], input=blob, capture_output=True, check=True).stdout
        return tarfile.open(fileobj=io.BytesIO(raw))
    return tarfile.open(fileobj=io.BytesIO(blob))


def deb_info(path):
    parts = read_ar(Path(path).read_bytes())
    control = next(k for k in parts if k.startswith("control.tar"))
    data = next(k for k in parts if k.startswith("data.tar"))
    with decompress_tar(control, parts[control]) as tf:
        ctrl = tf.extractfile("./control" if "./control" in tf.getnames() else "control").read().decode()
    fields = {}
    for line in ctrl.splitlines():
        if ":" in line and not line.startswith(" "):
            k, v = line.split(":", 1)
            fields[k.strip()] = v.strip()
    with decompress_tar(data, parts[data]) as tf:
        files = {m.name.lstrip("./"): (m.mode & 0o777, tf.extractfile(m).read() if m.isfile() else b"")
                 for m in tf.getmembers() if m.isfile()}
    return {"name": fields.get("Package"), "version": fields.get("Version"), "arch": fields.get("Architecture"),
            "license": None, "maintainer": fields.get("Maintainer"), "description": fields.get("Description"),
            "homepage": fields.get("Homepage"),
            "depends": [d.strip() for d in fields.get("Depends", "").split(",") if d.strip()], "files": files}


def apk_info(path):
    raw = gzip.open(path, "rb").read()  # concatenated gzip members: control (+signature) then data
    files, pkginfo = {}, ""
    with tarfile.open(fileobj=io.BytesIO(raw)) as tf:
        for m in tf.getmembers():
            if m.name == ".PKGINFO":
                pkginfo = tf.extractfile(m).read().decode()
            elif m.isfile() and not m.name.startswith("."):
                files[m.name] = (m.mode & 0o777, tf.extractfile(m).read())
    fields, depends = {}, []
    for line in pkginfo.splitlines():
        if " = " in line and not line.startswith("#"):
            k, v = line.split(" = ", 1)
            fields.setdefault(k, v)
            if k == "depend":
                depends.append(v.strip())
    return {"name": fields.get("pkgname"), "version": fields.get("pkgver"), "arch": fields.get("arch"),
            "license": fields.get("license"), "maintainer": fields.get("maintainer"),
            "description": fields.get("pkgdesc"), "homepage": fields.get("url"), "depends": depends,
            "files": files}


def rpm_info(path):
    data = Path(path).read_bytes()
    assert data[:4] == b"\xed\xab\xee\xdb", "not an rpm (lead magic)"
    pos = 96

    def header(pos):
        assert data[pos:pos + 3] == b"\x8e\xad\xe8", "bad rpm header magic"
        nindex, hsize = struct.unpack(">II", data[pos + 8:pos + 16])
        idx = data[pos + 16:pos + 16 + nindex * 16]
        store = data[pos + 16 + nindex * 16:pos + 16 + nindex * 16 + hsize]
        tags = {}
        for i in range(nindex):
            tag, typ, off, cnt = struct.unpack(">IIII", idx[i * 16:i * 16 + 16])
            if typ in (6, 9):  # STRING, I18NSTRING
                tags[tag] = store[off:store.index(b"\0", off)].decode()
            elif typ == 4:  # INT32 array
                tags[tag] = list(struct.unpack(f">{cnt}I", store[off:off + 4 * cnt]))
            elif typ == 8:  # STRING_ARRAY
                vals, o = [], off
                for _ in range(cnt):
                    e = store.index(b"\0", o)
                    vals.append(store[o:e].decode())
                    o = e + 1
                tags[tag] = vals
        return tags, pos + 16 + nindex * 16 + hsize

    _, pos = header(pos)  # signature header
    pos += (8 - pos % 8) % 8
    tags, _ = header(pos)
    dirs, idx = tags.get(1118, []), tags.get(1116, [])
    names = [(dirs[idx[i]] if i < len(idx) else "") + b for i, b in enumerate(tags.get(1117, []))]
    return {"name": tags.get(1000), "version": tags.get(1001), "arch": tags.get(1022),
            "license": tags.get(1014), "maintainer": tags.get(1011), "description": tags.get(1005),
            "homepage": tags.get(1020), "depends": list(tags.get(1049, [])), "files": {n.lstrip("/"): None for n in names}}


def has_dependency(depends, name):
    """True when `name` is a dependency, ignoring version constraints."""
    return any(re.split(r"[\s(<>=]", d.strip(), maxsplit=1)[0] == name for d in depends or [])


def elf_info(data):
    if data[:4] != b"\x7fELF":
        return None
    e_machine = struct.unpack("<H", data[18:20])[0]
    phoff = struct.unpack("<Q", data[32:40])[0]
    phentsize, phnum = struct.unpack("<HH", data[54:58])
    types = [struct.unpack("<I", data[phoff + i * phentsize:phoff + i * phentsize + 4])[0] for i in range(phnum)]
    return {"machine": e_machine, "dynamic_interp": 3 in types}  # PT_INTERP == 3


def check_binary_format(chk, label, goarch, goos, data):
    if goos == "linux":
        info = elf_info(data)
        chk.add(f"{label}: ELF machine", info and info["machine"] == ELF_MACHINE[goarch], info)
        chk.add(f"{label}: static (no PT_INTERP, musl)", info and not info["dynamic_interp"], info)
    else:
        magic, cputype = struct.unpack("<II", data[:8])
        chk.add(f"{label}: Mach-O arm64", (cputype, magic) == MACHO_ARM64, f"cputype={cputype:#x} magic={magic:#x}")


def check_dist(dist, native_runs=True, docker_runs=True):
    """Return (Checks, context). Pure reader: never mutates dist."""
    chk = Checks()
    ctx = {"artifacts": [], "version": None, "runs": []}
    dist = Path(dist)
    sums_files = sorted(dist.glob(f"{PROJECT}_*_checksums.txt"))
    if not chk.add("checksums file present", len(sums_files) == 1, [p.name for p in sums_files]):
        return chk, ctx
    sums_path = sums_files[0]
    version = sums_path.name[len(PROJECT) + 1:-len("_checksums.txt")]
    ctx["version"] = version
    chk.add("snapshot version shape", re.fullmatch(r"\d+\.\d+\.\d+(-next)?", version), version)

    # --- archives -----------------------------------------------------
    archives = {}
    want_names = {f"{PROJECT}_{version}_{o}_{a}.tar.gz": (o, a) for o, a in TARGETS}
    have = {p.name for p in dist.glob(f"{PROJECT}_*.tar.gz")}
    chk.add("archive set is exactly darwin_arm64+linux_amd64+linux_arm64", have == set(want_names),
            f"missing={sorted(set(want_names) - have)} extra={sorted(have - set(want_names))}")
    # Exact listing: the expected release set and nothing else, whatever the
    # extension (an mcpb/deb/sbom for an unsupported platform is a failure).
    expected = expected_files(version)
    files = {p.name for p in dist.iterdir() if p.is_file()}
    dirs = {p.name for p in dist.iterdir() if p.is_dir()}
    missing_files = sorted(set(expected) - files)
    extra_files = sorted(files - set(expected) - GORELEASER_INTERNAL_FILES)
    extra_dirs = sorted(d for d in dirs if d != "man" and not BUILD_DIR_RE.fullmatch(d))
    chk.add(f"dist listing is exactly the {len(expected)} expected release files",
            not (missing_files or extra_files or extra_dirs),
            f"missing={missing_files} extra_files={extra_files} extra_dirs={extra_dirs}")
    members_by_target, binaries = {}, {}
    for name, (goos, goarch) in want_names.items():
        path = dist / name
        if not path.exists():
            continue
        ctx["artifacts"].append(name)
        wrap = name[:-len(".tar.gz")]
        try:
            with tarfile.open(path, "r:gz") as tf:
                tops = {m.name.split("/")[0] for m in tf.getmembers()}
                names = {m.name for m in tf.getmembers() if m.isfile()}
                chk.add(f"{name}: single wrapper dir {wrap}/", tops == {wrap}, sorted(tops))
                missing = [m for m in ARCHIVE_MEMBERS if f"{wrap}/{m}" not in names]
                chk.add(f"{name}: members {', '.join(ARCHIVE_MEMBERS)}", not missing, f"missing={missing}")
                man = {n[len(f"{wrap}/docs/man/"):] for n in names if n.startswith(f"{wrap}/docs/man/")}
                chk.add(f"{name}: docs/man has {sorted(EXPECTED_MAN)} (+{len(man) - len(EXPECTED_MAN & man)} more)",
                        EXPECTED_MAN <= man and all(m.endswith(".1") for m in man), f"{len(man)} pages")
                members_by_target[(goos, goarch)] = (sorted(names), man)
                bm = next((m for m in tf.getmembers() if m.name == f"{wrap}/symvault"), None)
                if bm:
                    binaries[(goos, goarch)] = tf.extractfile(bm).read()
                    chk.add(f"{name}: symvault is executable", bm.mode & 0o111, oct(bm.mode))
        except Exception as e:  # noqa: BLE001 - report any malformed archive as a failed check
            chk.add(f"{name}: readable tar.gz", False, repr(e))
    man_sets = {k: v[1] for k, v in members_by_target.items()}
    chk.add("man page set identical across archives", len({frozenset(v) for v in man_sets.values()}) <= 1,
            {f"{k[0]}_{k[1]}": len(v) for k, v in man_sets.items()})
    for (goos, goarch), data in binaries.items():
        check_binary_format(chk, f"{goos}_{goarch}", goarch, goos, data)

    # --- checksums ----------------------------------------------------
    listed = {}
    for line in sums_path.read_text().splitlines():
        if line.strip():
            digest, fname = line.split(None, 1)
            listed[fname.strip()] = digest
    for name in sorted(want_names):
        chk.add(f"checksums list {name}", name in listed)
    bad = [f for f, d in listed.items() if not (dist / f).is_file() or sha256(dist / f) != d]
    chk.add(f"all {len(listed)} checksum lines match files on disk", not bad, f"bad={bad}")
    want_sums = expected_checksummed(version)
    chk.add(f"checksums file lists exactly the {len(want_sums)} archives, packages and SBOMs",
            set(listed) == want_sums and len(listed) == len(want_sums),
            f"missing={sorted(want_sums - set(listed))} extra={sorted(set(listed) - want_sums)}")

    # --- nfpm packages ------------------------------------------------
    readers = {"deb": deb_info, "rpm": rpm_info, "apk": apk_info}
    for goos, goarch in TARGETS:
        if goos != "linux":
            continue
        for fmt in PACKAGE_FORMATS:
            name = f"{PACKAGE}_{version}_linux_{goarch}.{fmt}"
            path = dist / name
            if not chk.add(f"package {name} exists", path.exists()):
                continue
            ctx["artifacts"].append(name)
            chk.add(f"checksums list {name}", name in listed)
            try:
                info = readers[fmt](path)
            except Exception as e:  # noqa: BLE001
                chk.add(f"{name}: parseable {fmt}", False, repr(e))
                continue
            chk.add(f"{name}: name", info["name"] == PACKAGE, info["name"])
            chk.add(f"{name}: version contains {version.split('-')[0]}",
                    info["version"] and version.split("-")[0] in info["version"], info["version"])
            chk.add(f"{name}: arch", info["arch"] == PKG_ARCH[fmt][goarch], info["arch"])
            if info["license"] is not None:
                chk.add(f"{name}: license Apache-2.0", info["license"] == "Apache-2.0", info["license"])
            if info["maintainer"] is not None:
                chk.add(f"{name}: maintainer", "danieljustus" in info["maintainer"], info["maintainer"])
            chk.add(f"{name}: description", "password" in (info["description"] or "").lower(), info["description"])
            chk.add(f"{name}: hard dependency on git (ADR 0033)", has_dependency(info["depends"], "git"), info["depends"])
            chk.add(f"{name}: installs usr/bin/symvault", "usr/bin/symvault" in info["files"], sorted(info["files"])[:5])
            entry = info["files"].get("usr/bin/symvault")
            if entry and entry[1] is not None and (goos, goarch) in binaries:
                chk.add(f"{name}: packaged binary == archive binary", entry[1] == binaries[(goos, goarch)])
                chk.add(f"{name}: packaged binary mode 0755", entry[0] == 0o755, oct(entry[0]))

    # --- MCPB ---------------------------------------------------------
    for goos, goarch in TARGETS:
        name = f"{PACKAGE}_{version}_{goos}_{goarch}.mcpb"
        path = dist / name
        if not chk.add(f"mcpb {name} exists", path.exists()):
            continue
        ctx["artifacts"].append(name)
        try:
            with zipfile.ZipFile(path) as zf:
                m = json.loads(zf.read("manifest.json"))
                ok = (m.get("manifest_version") == "0.3" and m.get("name") == "symvault"
                      and m.get("version") == version and m["server"]["type"] == "binary"
                      and m["server"]["entry_point"] == "server/symvault"
                      and m["server"]["mcp_config"]["args"] == ["serve", "--stdio"])
                chk.add(f"{name}: manifest.json", ok, m)
                info = zf.getinfo("server/symvault")
                chk.add(f"{name}: server/symvault executable", (info.external_attr >> 16) & 0o111, oct(info.external_attr >> 16))
                if (goos, goarch) in binaries:
                    chk.add(f"{name}: server binary == archive binary", zf.read("server/symvault") == binaries[(goos, goarch)])
        except Exception as e:  # noqa: BLE001
            chk.add(f"{name}: readable mcpb", False, repr(e))

    # --- SBOM ---------------------------------------------------------
    for archive in sorted(want_names):
        name = f"{archive}.sbom.json"
        path = dist / name
        if not chk.add(f"sbom {name} exists", path.exists()):
            continue
        ctx["artifacts"].append(name)
        try:
            doc = json.loads(path.read_text())
            comps = doc.get("components", [])
            chk.add(f"{name}: CycloneDX with components", doc.get("bomFormat") == "CycloneDX" and len(comps) > 0,
                    f"specVersion={doc.get('specVersion')} components={len(comps)}")
            crates = {c.get("name") for c in comps if str(c.get("purl", "")).startswith("pkg:cargo/")}
            chk.add(f"{name}: lists the binary's Rust crates ({', '.join(sorted(REQUIRED_SBOM_CRATES))})",
                    REQUIRED_SBOM_CRATES <= crates, f"missing={sorted(REQUIRED_SBOM_CRATES - crates)} crates={len(crates)}")
        except Exception as e:  # noqa: BLE001
            chk.add(f"{name}: valid JSON", False, repr(e))
    ctx["artifacts"] += [sums_path.name]
    ctx["artifacts"] += [n for n in want_names if (dist / n).exists() and n not in ctx["artifacts"]]

    # --- runs ---------------------------------------------------------
    if native_runs or docker_runs:
        run_binaries(chk, ctx, version, binaries, native_runs, docker_runs)
    ctx["artifacts"] = sorted(set(ctx["artifacts"]))
    return chk, ctx


def version_ok(out, version):
    return version in out


def smoke_script(with_git_install):
    """Shell run inside an alpine container (or natively): init, set, get."""
    return "\n".join([
        "set -eu",
        "apk add --no-cache git >/dev/null" if with_git_install else "true",
        "export SYMVAULT_ALLOW_ENV_PASSPHRASE=1 SYMVAULT_PASSPHRASE=\"$PASS\" SYMVAULT_VAULT=/tmp/smoke-vault HOME=/tmp",
        "/b/symvault init >/dev/null 2>&1",
        "printf '%s\\n' \"$SECRET\" | /b/symvault set smoke.password --stdin-value >/dev/null 2>&1",
        "/b/symvault get smoke.password 2>/dev/null",
    ])


def run_binaries(chk, ctx, version, binaries, native_runs, docker_runs):
    scratch = DEFAULT_DIST.parent / ".contract-run"
    if scratch.exists():
        shutil.rmtree(scratch)
    scratch.mkdir(parents=True)
    try:
        for (goos, goarch), data in binaries.items():
            d = scratch / f"{goos}_{goarch}"
            d.mkdir()
            exe = d / "symvault"
            exe.write_bytes(data)
            exe.chmod(0o755)
        if native_runs and ("darwin", "arm64") in binaries:
            run_native_darwin(chk, ctx, version, scratch / "darwin_arm64" / "symvault")
        if docker_runs:
            for goarch, plat, mode in [("arm64", None, "native-container (linux/arm64 on Apple silicon host)"),
                                       ("amd64", "linux/amd64", "EMULATED (QEMU/Rosetta linux/amd64)")]:
                if ("linux", goarch) not in binaries:
                    continue
                run_linux_container(chk, ctx, version, scratch / f"linux_{goarch}", goarch, plat, mode)
    finally:
        shutil.rmtree(scratch, ignore_errors=True)


def run_native_darwin(chk, ctx, version, exe):
    host_ok = sys.platform == "darwin" and platform.machine() == "arm64"
    if not chk.add("host is darwin/arm64 (native run possible)", host_ok, f"{sys.platform}/{platform.machine()}"):
        return
    home = Path(tempfile.mkdtemp(dir=DEFAULT_DIST.parent, prefix=".smoke-home-"))
    try:
        p = subprocess.run([str(exe), "version"], capture_output=True, text=True, timeout=60)
        chk.add("darwin_arm64 `symvault version` (native) exit 0 + version", p.returncode == 0 and version_ok(p.stdout, version),
                f"rc={p.returncode} out={p.stdout.strip()!r} err={p.stderr.strip()[:200]!r}")
        ctx["runs"].append({"target": "darwin_arm64", "mode": "native", "op": "version", "stdout": p.stdout.strip()})
        # SYMVAULT_TEST_KEYRING=memory keeps the session cache out of the login keychain.
        env = dict(os.environ, HOME=str(home), SYMVAULT_VAULT=str(home / "vault"), SYMVAULT_ALLOW_ENV_PASSPHRASE="1",
                   SYMVAULT_PASSPHRASE=SMOKE_PASSPHRASE, SYMVAULT_TEST_KEYRING="memory")
        init = subprocess.run([str(exe), "init"], env=env, capture_output=True, text=True, timeout=120)
        setp = subprocess.run([str(exe), "set", "smoke.password", "--stdin-value"], env=env, input=SMOKE_SECRET + "\n",
                              capture_output=True, text=True, timeout=120)
        getp = subprocess.run([str(exe), "get", "smoke.password"], env=env, capture_output=True, text=True, timeout=120)
        chk.add("darwin_arm64 init/set/get round trip (native, git on host)",
                init.returncode == 0 and setp.returncode == 0 and getp.returncode == 0 and getp.stdout.strip() == SMOKE_SECRET,
                f"init={init.returncode} set={setp.returncode} get={getp.returncode} out_matches={getp.stdout.strip() == SMOKE_SECRET}")
        ctx["runs"].append({"target": "darwin_arm64", "mode": "native", "op": "init/set/get",
                            "ok": getp.stdout.strip() == SMOKE_SECRET})
        nogit = dict(env, PATH="/var/empty", SYMVAULT_VAULT=str(home / "vault-nogit"))
        miss = subprocess.run([str(exe), "init"], env=nogit, capture_output=True, text=True, timeout=120)
        chk.add("darwin_arm64 `init` without git fails with the clear message (native)",
                miss.returncode != 0 and GIT_MISSING_MESSAGE in miss.stderr,
                f"rc={miss.returncode} err={miss.stderr.strip()[-200:]!r}")
    finally:
        shutil.rmtree(home, ignore_errors=True)


def run_linux_container(chk, ctx, version, bin_dir, goarch, plat, mode):
    plat_args = ["--platform", plat] if plat else []
    label = f"linux_{goarch}"

    def docker(args, label_suffix, env=None):
        cmd = ["docker", "run", "--rm"] + plat_args + ["-v", f"{bin_dir}:/b:ro"] + (env or []) + args
        try:
            return subprocess.run(cmd, capture_output=True, text=True, timeout=900)
        except Exception as e:  # noqa: BLE001 - docker missing/timeout is a failed check
            chk.add(f"{label} {label_suffix} [{mode}]", False, repr(e))
            return None

    p = docker(["ubuntu:24.04", "/b/symvault", "version"], "`symvault version` in ubuntu:24.04")
    if p is not None:
        chk.add(f"{label} `symvault version` in ubuntu:24.04 [{mode}]", p.returncode == 0 and version_ok(p.stdout, version),
                f"rc={p.returncode} out={p.stdout.strip()!r} err={p.stderr.strip()[-200:]!r}")
        ctx["runs"].append({"target": label, "mode": mode, "op": "version", "image": "ubuntu:24.04", "stdout": p.stdout.strip()})
    env = ["-e", f"PASS={SMOKE_PASSPHRASE}", "-e", f"SECRET={SMOKE_SECRET}"]
    p = docker([SMOKE_IMAGE, "sh", "-c", smoke_script(True)], f"init/set/get in {SMOKE_IMAGE} + git", env)
    if p is not None:
        chk.add(f"{label} init/set/get round trip in {SMOKE_IMAGE} with git [{mode}]",
                p.returncode == 0 and p.stdout.strip().splitlines()[-1:] == [SMOKE_SECRET],
                f"rc={p.returncode} out_matches={p.stdout.strip().splitlines()[-1:] == [SMOKE_SECRET]} err={p.stderr.strip()[-200:]!r}")
        ctx["runs"].append({"target": label, "mode": mode, "op": "init/set/get", "image": SMOKE_IMAGE,
                            "ok": p.stdout.strip().splitlines()[-1:] == [SMOKE_SECRET]})
    # alpine ships without git: the packaged binary must say so, clearly.
    p = docker([SMOKE_IMAGE, "sh", "-c",
                "SYMVAULT_ALLOW_ENV_PASSPHRASE=1 SYMVAULT_PASSPHRASE=\"$PASS\" SYMVAULT_VAULT=/tmp/v HOME=/tmp /b/symvault init"],
               f"init without git in {SMOKE_IMAGE}", env)
    if p is not None:
        chk.add(f"{label} `init` without git fails with the clear message in {SMOKE_IMAGE} [{mode}]",
                p.returncode != 0 and GIT_MISSING_MESSAGE in p.stderr, f"rc={p.returncode} err={p.stderr.strip()[-200:]!r}")
        ctx["runs"].append({"target": label, "mode": mode, "op": "init-without-git", "image": SMOKE_IMAGE})


# --- pipeline ------------------------------------------------------------
def derive_config(dist, workdir):
    text = (ROOT / ".goreleaser.yml").read_text()
    for old, new in [("\ndist: dist\n", f"\ndist: {dist}\n"), ("src: dist/man/*.1", f"src: {dist}/man/*.1")]:
        if text.count(old) != 1:
            raise SystemExit(f"release_contract: expected exactly one {old.strip()!r} in .goreleaser.yml")
        text = text.replace(old, new)
    out = Path(workdir) / "goreleaser.contract.yml"
    out.write_text(text)
    return out


def run_pipeline(dist):
    cargo_target = Path(os.environ.get("CARGO_TARGET_DIR") or ROOT / "target").resolve()
    env = dict(os.environ, DIST_DIR=str(dist), MAN_DIR=f"{dist}/man", CARGO_TARGET_DIR=str(cargo_target))
    # GoReleaser's Rust builder copies `target/<triple>/release/<bin>` relative to
    # the repo and ignores CARGO_TARGET_DIR. When the build tree is external
    # (disk-tight machines), expose it as ./target for the duration of the run.
    link = ROOT / "target"
    made_link = False
    if cargo_target != link.resolve() if link.exists() else cargo_target != link:
        if link.exists() or link.is_symlink():
            raise SystemExit(f"release_contract: {link} exists and CARGO_TARGET_DIR={cargo_target} differs; "
                             "unset CARGO_TARGET_DIR or remove ./target")
        cargo_target.mkdir(parents=True, exist_ok=True)
        link.symlink_to(cargo_target)
        made_link = True
    try:
        with tempfile.TemporaryDirectory() as tmp:
            cfg = derive_config(dist, tmp)
            cmd = ["goreleaser", "release", "--snapshot", "--clean", "--skip=publish,sign", "--config", str(cfg)]
            print("+", " ".join(cmd), flush=True)
            return subprocess.run(cmd, cwd=ROOT, env=env).returncode
    finally:
        if made_link:
            link.unlink()


# --- negative controls ---------------------------------------------------
def rewrite_tar_without(src, dst, drop_suffix):
    with tarfile.open(src, "r:gz") as tin, tarfile.open(dst, "w:gz") as tout:
        for m in tin.getmembers():
            if m.name.endswith(drop_suffix):
                continue
            tout.addfile(m, tin.extractfile(m) if m.isfile() else None)


def recompute_checksums(d, version):
    """Rewrite checksums.txt so every listed digest matches the (tampered) file:
    only content checks, not the digest comparison, can catch the tampering."""
    path = d / f"{PROJECT}_{version}_checksums.txt"
    lines = []
    for line in path.read_text().splitlines():
        if line.strip():
            _, fname = line.split(None, 1)
            lines.append(f"{sha256(d / fname.strip())}  {fname.strip()}\n")
    path.write_text("".join(lines))


def build_ar(members):
    """Write an ar(1) archive from [(name, bytes)] (the inverse of read_ar)."""
    out = bytearray(b"!<arch>\n")
    for name, blob in members:
        out += f"{name + '/':<16}{0:<12}{0:<6}{0:<6}{'100644':<8}{len(blob):<10}`\n".encode()
        out += blob + (b"\n" if len(blob) & 1 else b"")
    return bytes(out)


def swap_deb_binary(path, new_binary):
    parts = read_ar(Path(path).read_bytes())
    data_name = next(k for k in parts if k.startswith("data.tar"))
    buf = io.BytesIO()
    with decompress_tar(data_name, parts[data_name]) as tin, tarfile.open(fileobj=buf, mode="w") as tout:
        for m in tin.getmembers():
            if m.isfile() and m.name.lstrip("./") == "usr/bin/symvault":
                m.size = len(new_binary)
                tout.addfile(m, io.BytesIO(new_binary))
            else:
                tout.addfile(m, tin.extractfile(m) if m.isfile() else None)
    members = [(k, v) for k, v in parts.items() if k != data_name] + [("data.tar", buf.getvalue())]
    Path(path).write_bytes(build_ar(members))


def swap_mcpb_binary(path, new_binary):
    tmp = Path(str(path) + ".tmp")
    with zipfile.ZipFile(path) as zin, zipfile.ZipFile(tmp, "w", zipfile.ZIP_DEFLATED) as zout:
        for item in zin.infolist():
            zout.writestr(item, new_binary if item.filename == "server/symvault" else zin.read(item.filename))
    tmp.replace(path)


def negative_cases(version):
    """{label: (mutate(dir), recomputes_checksums)}"""
    sums = f"{PROJECT}_{version}_checksums.txt"

    def archive(a="linux_amd64"):
        return f"{PROJECT}_{version}_{a}.tar.gz"

    def drop_license(d):
        a = d / archive()
        tmp = d / "x.tgz"
        rewrite_tar_without(a, tmp, "/LICENSE")
        tmp.replace(a)

    def drop_completion(d):
        a = d / archive("darwin_arm64")
        tmp = d / "x.tgz"
        rewrite_tar_without(a, tmp, "completions/symvault.zsh")
        tmp.replace(a)

    def flip_byte(d):
        p = d / archive("linux_arm64")
        b = bytearray(p.read_bytes())
        b[len(b) // 2] ^= 0xFF
        p.write_bytes(bytes(b))

    def drop_sbom(d):
        (d / f"{archive()}.sbom.json").unlink()

    def drop_deb(d):
        (d / f"{PACKAGE}_{version}_linux_arm64.deb").unlink()

    def drop_mcpb(d):
        (d / f"{PACKAGE}_{version}_darwin_arm64.mcpb").unlink()

    def extra_platform_archive(d):
        shutil.copy(d / archive(), d / f"{PROJECT}_{version}_windows_amd64.tar.gz")

    def extra_mcpb(d):
        shutil.copy(d / f"{PACKAGE}_{version}_linux_amd64.mcpb", d / f"{PACKAGE}_{version}_windows_amd64.mcpb")

    def extra_deb(d):
        shutil.copy(d / f"{PACKAGE}_{version}_linux_amd64.deb", d / f"{PACKAGE}_{version}_darwin_arm64.deb")

    def extra_sbom(d):
        shutil.copy(d / f"{archive()}.sbom.json", d / f"{PROJECT}_{version}_windows_amd64.tar.gz.sbom.json")

    def extra_stray_file(d):
        (d / "notes.txt").write_text("not part of the release\n")

    def extra_stray_dir(d):
        (d / "unexpected-dir").mkdir()

    def extra_checksum_line(d):
        extra = d / f"{PACKAGE}_{version}_darwin_arm64.deb"
        shutil.copy(d / f"{PACKAGE}_{version}_linux_amd64.deb", extra)
        p = d / sums
        p.write_text(p.read_text() + f"{sha256(extra)}  {extra.name}\n")

    def drop_checksum_line(d):
        p = d / sums
        p.write_text("".join(l for l in p.read_text().splitlines(True) if "linux_arm64.tar.gz" not in l))

    def edit_sbom_recomputed(d):
        p = d / f"{archive()}.sbom.json"
        doc = json.loads(p.read_text())
        doc["components"] = [c for c in doc["components"] if c.get("name") != "symvault-cli"]
        p.write_text(json.dumps(doc))
        recompute_checksums(d, version)

    def swap_mcpb(d):
        swap_mcpb_binary(d / f"{PACKAGE}_{version}_linux_amd64.mcpb", b"#!/bin/sh\necho swapped\n")
        recompute_checksums(d, version)

    def swap_deb(d):
        swap_deb_binary(d / f"{PACKAGE}_{version}_linux_amd64.deb", b"\x7fELF-swapped")
        recompute_checksums(d, version)

    return {
        "archive missing LICENSE": (drop_license, False),
        "archive missing completions/symvault.zsh": (drop_completion, False),
        "flipped byte in archive (checksum mismatch)": (flip_byte, False),
        "missing SBOM": (drop_sbom, False),
        "missing deb package": (drop_deb, False),
        "missing MCPB bundle": (drop_mcpb, False),
        "extra archive for an unsupported platform": (extra_platform_archive, False),
        "extra mcpb for an unsupported platform": (extra_mcpb, False),
        "extra deb for an unsupported platform": (extra_deb, False),
        "extra sbom for an unsupported platform": (extra_sbom, False),
        "extra stray file": (extra_stray_file, False),
        "extra stray directory": (extra_stray_dir, False),
        "checksum line for an unexpected file (file present, digest correct)": (extra_checksum_line, False),
        "checksum line removed": (drop_checksum_line, False),
        "SBOM edited (symvault-cli component removed), checksums recomputed": (edit_sbom_recomputed, True),
        "binary swapped inside an mcpb, checksums recomputed": (swap_mcpb, True),
        "binary swapped inside a deb, checksums recomputed": (swap_deb, True),
    }


def negative_controls(dist, version, scratch_root=None):
    results = []
    scratch_root = Path(scratch_root) if scratch_root else DEFAULT_DIST.parent
    for label, (mutate, recomputes) in negative_cases(version).items():
        tmp = Path(tempfile.mkdtemp(dir=scratch_root, prefix=".negctl-"))
        try:
            for f in Path(dist).iterdir():
                if f.is_file():
                    shutil.copy2(f, tmp / f.name)
                elif f.is_dir() and f.name == "man":
                    shutil.copytree(f, tmp / f.name)
            mutate(tmp)
            chk, _ = check_dist(tmp, native_runs=False, docker_runs=False)
            sum_failed = any(i["check"].endswith("checksum lines match files on disk") for i in chk.failed)
            # A control that recomputes the checksums is only meaningful if the
            # digest comparison still passes: the rejection must come from content.
            rejected = bool(chk.failed) and not (recomputes and sum_failed)
            results.append({"control": label, "rejected": rejected, "recomputes_checksums": recomputes,
                            "first_failure": chk.failed[0]["check"] if chk.failed else None,
                            "failures": len(chk.failed)})
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
    return results


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--dist", type=Path, default=DEFAULT_DIST)
    ap.add_argument("--report", type=Path, help="default: <dist>/../release-contract-report.json")
    ap.add_argument("--check-only", action="store_true", help="skip goreleaser; check an existing --dist")
    ap.add_argument("--keep-dist", action="store_true", help="do not delete the dist dir afterwards")
    ap.add_argument("--no-docker", action="store_true",
                    help="skip the linux container runs; the result is then `partial` (exit 3, ok=false)")
    ap.add_argument("--no-negative-controls", action="store_true",
                    help="skip the tamper controls; the result is then `partial` (exit 3, ok=false)")
    args = ap.parse_args()
    dist = args.dist.resolve()
    report_path = args.report or dist.parent / "release-contract-report.json"
    if not str(dist).startswith("/Volumes/") and not os.environ.get("RELEASE_CONTRACT_ALLOW_ANY_DIST"):
        print(f"refusing dist outside /Volumes (set RELEASE_CONTRACT_ALLOW_ANY_DIST=1): {dist}", file=sys.stderr)
        return 2
    dist.parent.mkdir(parents=True, exist_ok=True)
    if not args.check_only:
        rc = run_pipeline(dist)
        if rc != 0:
            print(f"goreleaser snapshot failed rc={rc}", file=sys.stderr)
            return rc
    chk, ctx = check_dist(dist, docker_runs=not args.no_docker)
    skipped = (["docker runs"] if args.no_docker else []) + (["negative controls"] if args.no_negative_controls else [])
    report = {"dist": str(dist), "version": ctx["version"], "artifacts": ctx["artifacts"], "runs": ctx["runs"],
              "checks": chk.items, "skipped": skipped}
    ok = not chk.failed
    if ok and not args.no_negative_controls:
        report["negative_controls"] = negative_controls(dist, ctx["version"])
        ok = all(r["rejected"] for r in report["negative_controls"])
    status = "fail" if not ok else ("partial" if skipped else "pass")
    report["status"] = status
    report["ok"] = status == "pass"
    report_path.write_text(json.dumps(report, indent=2) + "\n")
    for i in chk.items:
        print(("PASS " if i["ok"] else "FAIL ") + i["check"] + ("" if i["ok"] else f"  -> {i['detail']}"))
    for r in report.get("negative_controls", []):
        print(("PASS " if r["rejected"] else "FAIL ") + f"negative control: {r['control']} rejected by {r['first_failure']!r}")
    print(f"\nartifacts ({len(ctx['artifacts'])}):")
    for a in ctx["artifacts"]:
        print("  " + a)
    print(f"report: {report_path}  status={status} ok={report['ok']}" + (f" skipped={skipped}" if skipped else ""))
    if not args.keep_dist and not args.check_only:
        shutil.rmtree(dist, ignore_errors=True)
    return {"pass": 0, "fail": 1, "partial": 3}[status]


if __name__ == "__main__":
    sys.exit(main())
