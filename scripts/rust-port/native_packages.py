#!/usr/bin/env python3
"""Stage unsigned Rust Linux packages from the repository's GoReleaser nfpm metadata."""

from __future__ import annotations

import argparse
import os
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[2]
GOARCH = {"amd64": "amd64", "arm64": "arm64"}
RPM_ARCH = {"amd64": "x86_64", "arm64": "aarch64"}
ELF_MACHINE = {"amd64": 62, "arm64": 183}
FORMATS = {"deb", "rpm", "apk"}
STAGE_VERSION = "0.0.0"


def source_config(path: Path = ROOT / ".goreleaser.yml") -> tuple[dict, dict]:
    config = yaml.safe_load(path.read_text(encoding="utf-8"))
    builds = [item for item in config["builds"] if item.get("id") == "symvault-static"]
    nfpms = config.get("nfpms", [])
    if len(builds) != 1 or len(nfpms) != 1:
        raise ValueError("expected one symvault-static build and one nfpm package")
    build, nfpm = builds[0], nfpms[0]
    if build.get("binary") != "symvault" or nfpm.get("formats") != ["deb", "rpm", "apk"]:
        raise ValueError("native package stage only supports current symvault binary and deb/rpm/apk formats")
    if nfpm.get("contents"):
        raise ValueError("nfpm contents changed; update the source-bound package staging contract")
    return build, nfpm


def package_config(nfpm: dict, binary: Path, arch: str, package_format: str) -> dict:
    if arch not in GOARCH or package_format not in FORMATS:
        raise ValueError(f"unsupported package target: {package_format}/{arch}")
    config = {
        key: nfpm[key]
        for key in (
            "package_name", "vendor", "homepage", "maintainer", "description", "license",
            "section", "priority", "recommends",
        )
        if key in nfpm
    }
    config.update(
        name=config.pop("package_name"),
        version=STAGE_VERSION,
        arch=GOARCH[arch],
        platform="linux",
        contents=[{"src": str(binary), "dst": f"{nfpm['bindir'].rstrip('/')}/symvault"}],
    )
    return config


def check_elf(path: Path, arch: str) -> None:
    data = path.read_bytes()[:20]
    if len(data) < 20 or data[:4] != b"\x7fELF" or data[4] != 2 or data[5] != 1:
        raise ValueError(f"{path} is not a little-endian 64-bit ELF binary")
    machine = struct.unpack("<H", data[18:20])[0]
    if machine != ELF_MACHINE[arch]:
        raise ValueError(f"{path} ELF machine {machine} does not match {arch}")
    if not os.access(path, os.X_OK):
        raise ValueError(f"{path} is not executable")


def stage(binary: Path, output: Path, arch: str, nfpm_bin: str) -> list[Path]:
    build, nfpm = source_config()
    if build["binary"] != binary.name:
        raise ValueError(f"expected Rust binary named {build['binary']}, got {binary.name}")
    check_elf(binary, arch)
    output.mkdir(parents=True, exist_ok=True)
    template = nfpm["file_name_template"]
    base = template.replace("{{ .PackageName }}", nfpm["package_name"])
    base = base.replace("{{ .Version }}", STAGE_VERSION).replace("{{ .Os }}", "linux")
    base = base.replace("{{ .Arch }}", arch)
    if "{{" in base or "}}" in base:
        raise ValueError(f"unsupported GoReleaser package filename template: {template}")
    packages = []
    with tempfile.TemporaryDirectory(prefix="symvault-nfpm-") as temp:
        for package_format in nfpm["formats"]:
            target = output / f"{base}.{package_format}"
            config_path = Path(temp) / f"nfpm-{package_format}.yml"
            config_path.write_text(
                yaml.safe_dump(package_config(nfpm, binary.resolve(), arch, package_format), sort_keys=False),
                encoding="utf-8",
            )
            subprocess.run(
                [nfpm_bin, "package", "--config", str(config_path), "--packager", package_format, "--target", str(target)],
                check=True,
            )
            if not target.is_file() or target.stat().st_size == 0:
                raise ValueError(f"nfpm did not create {target}")
            packages.append(target)
    return packages


def output(command: list[str]) -> str:
    return subprocess.run(command, check=True, text=True, capture_output=True).stdout


def deb_fields(package: Path) -> dict[str, str]:
    fields = {}
    for key in ("Package", "Version", "Architecture", "Maintainer", "Description", "Homepage", "Section", "Priority", "Recommends"):
        value = output(["dpkg-deb", "--field", str(package), key]).strip()
        if value:
            fields["name" if key == "Package" else key.lower()] = value.splitlines()[0]
    return fields


def rpm_fields(package: Path) -> dict[str, str]:
    values = output([
        "rpm", "-qp", "--qf",
        "%{NAME}\n%{VERSION}\n%{ARCH}\n%{VENDOR}\n%{URL}\n%{SUMMARY}\n%{LICENSE}\n",
        str(package),
    ]).splitlines()
    if len(values) != 7:
        raise ValueError(f"unexpected rpm query output for {package}")
    fields = dict(zip(("name", "version", "architecture", "vendor", "homepage", "description", "license"), values))
    fields["recommends"] = output(["rpm", "-qp", "--recommends", str(package)]).splitlines()
    return fields


def apk_fields(package: Path) -> dict[str, str]:
    # apk v2 is a concatenated gzip tar stream; inspect only its metadata member.
    workspace = str(ROOT)
    relative = package.resolve().relative_to(ROOT)
    raw = output([
        "docker", "run", "--rm", "-v", f"{workspace}:/work:ro", "alpine:3.23",
        "sh", "-c", f"tar -xOzf /work/{relative.as_posix()} .PKGINFO",
    ])
    fields = {}
    for line in raw.splitlines():
        if " = " in line:
            key, value = line.split(" = ", 1)
            fields[key] = value
    return fields


def package_files(package: Path, package_format: str) -> set[str]:
    if package_format == "deb":
        lines = output(["dpkg-deb", "--contents", str(package)]).splitlines()
        return {
            line.split()[-1].removeprefix(".")
            for line in lines
            if line.split() and line.split()[0].startswith("-") and line.split()[-1].startswith("./")
        }
    if package_format == "rpm":
        return {line.strip() for line in output(["rpm", "-qlp", str(package)]).splitlines() if line.strip()}
    workspace = str(ROOT)
    relative = package.resolve().relative_to(ROOT)
    lines = output([
        "docker", "run", "--rm", "-v", f"{workspace}:/work:ro", "alpine:3.23",
        "sh", "-c", f"tar -tzf /work/{relative.as_posix()}",
    ]).splitlines()
    return {
        "/" + line.strip().removeprefix("./")
        for line in lines
        if line.strip().startswith(("usr/", "bin/", "etc/", "opt/")) and not line.strip().endswith("/")
    }


def verify(package: Path, arch: str) -> None:
    _, nfpm = source_config()
    package_format = package.suffix.lstrip(".")
    if package_format not in FORMATS:
        raise ValueError(f"unknown package format: {package}")
    expected_arch = GOARCH[arch] if package_format == "deb" else RPM_ARCH[arch]
    expected = {
        "name": nfpm["package_name"],
        "version": STAGE_VERSION,
        "architecture": expected_arch,
        "homepage": nfpm["homepage"],
        "license": nfpm["license"],
    }
    if package_format == "deb":
        actual = deb_fields(package)
        expected.pop("license")  # nFPM v2.47 omits the invalid Debian License control field.
        expected.update({
            "maintainer": nfpm["maintainer"], "description": nfpm["description"],
            "section": nfpm["section"], "priority": nfpm["priority"],
            "recommends": ", ".join(nfpm["recommends"]),
        })
    elif package_format == "rpm":
        actual = rpm_fields(package)
        expected.update({"vendor": nfpm["vendor"], "description": nfpm["description"]})
        missing_recommends = set(nfpm["recommends"]) - set(actual["recommends"])
        if missing_recommends:
            raise ValueError(f"{package.name}: missing RPM recommendations {sorted(missing_recommends)}")
    else:
        actual = apk_fields(package)
        actual = {
            "name": actual.get("pkgname"),
            "version": actual.get("pkgver", "").split("-r", 1)[0],
            "architecture": actual.get("arch"),
            "homepage": actual.get("url"),
            "license": actual.get("license"),
            "description": actual.get("pkgdesc"),
        }
        expected["description"] = nfpm["description"]
    for field, wanted in expected.items():
        got = actual.get(field)
        if got != wanted:
            raise ValueError(f"{package.name}: {field} expected {wanted!r}, got {got!r}")
    expected_files = {f"{nfpm['bindir'].rstrip('/')}/symvault"}
    got_files = package_files(package, package_format)
    if got_files != expected_files:
        raise ValueError(f"{package.name}: package files expected {sorted(expected_files)}, got {sorted(got_files)}")


def main() -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    stage_parser = subparsers.add_parser("stage")
    stage_parser.add_argument("--binary", type=Path, required=True)
    stage_parser.add_argument("--output", type=Path, required=True)
    stage_parser.add_argument("--arch", choices=GOARCH, required=True)
    stage_parser.add_argument("--nfpm", default="nfpm")
    verify_parser = subparsers.add_parser("verify")
    verify_parser.add_argument("--package", type=Path, required=True)
    verify_parser.add_argument("--arch", choices=GOARCH, required=True)
    args = parser.parse_args()
    try:
        if args.command == "stage":
            packages = stage(args.binary.resolve(), args.output.resolve(), args.arch, args.nfpm)
            for package in packages:
                print(package)
        else:
            verify(args.package.resolve(), args.arch)
            print(f"PASS {args.package.name}")
    except (OSError, subprocess.CalledProcessError, KeyError, TypeError, ValueError, yaml.YAMLError) as exc:
        print(f"native package check failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
