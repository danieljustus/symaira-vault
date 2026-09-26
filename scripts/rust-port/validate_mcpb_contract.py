#!/usr/bin/env python3
"""Validate a native Rust MCPB against the pinned Go release contract."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import zipfile

GO_RELEASE = "0.22.1"


def expected_manifest(version: str, executable: str) -> dict[str, object]:
    entry_point = f"server/{executable}"
    return {
        "manifest_version": "0.3",
        "name": "symvault",
        "version": version,
        "description": "Secure password manager MCP server",
        "author": {"name": "danieljustus"},
        "server": {
            "type": "binary",
            "entry_point": entry_point,
            "mcp_config": {
                "command": f"${{__dirname}}/{entry_point}",
                "args": ["serve", "--stdio"],
            },
        },
    }


def bundle_manifest(
    bundle: Path, executable: str, version: str, require_executable_mode: bool
) -> dict[str, object]:
    expected_members = {"manifest.json", "server/", f"server/{executable}"}
    with zipfile.ZipFile(bundle) as archive:
        members = set(archive.namelist())
        if members != expected_members:
            raise ValueError(f"unexpected MCPB members: {sorted(members)}")
        manifest = json.loads(archive.read("manifest.json"))
        expected = expected_manifest(version, executable)
        if manifest != expected:
            raise ValueError(f"manifest mismatch: expected {expected!r}, got {manifest!r}")
        binary = archive.getinfo(f"server/{executable}")
        if not archive.read(binary):
            raise ValueError("MCPB binary is empty")
        if require_executable_mode and not ((binary.external_attr >> 16) & 0o111):
            raise ValueError("MCPB entrypoint does not have executable permission bits")
    return manifest


def run_packaged_version(bundle: Path, executable: str, version: str) -> None:
    with zipfile.ZipFile(bundle) as archive, tempfile.TemporaryDirectory(
        prefix="symvault-mcpb-contract-"
    ) as temp_name:
        root = Path(temp_name)
        entry = root / "server" / executable
        entry.parent.mkdir()
        entry.write_bytes(archive.read(f"server/{executable}"))
        home = root / "home"
        home.mkdir()
        if os.name != "nt":
            entry.chmod(0o755)
        env = {
            "PATH": os.environ.get("PATH", ""),
            "HOME": str(home),
            "USERPROFILE": str(home),
            "XDG_CONFIG_HOME": str(home / "config"),
            "XDG_DATA_HOME": str(home / "data"),
            "XDG_CACHE_HOME": str(home / "cache"),
            "NO_COLOR": "1",
            "LANG": "C",
            "TZ": "UTC",
        }
        for key in ("SYSTEMROOT", "WINDIR", "COMSPEC", "PATHEXT"):
            if key in os.environ:
                env[key] = os.environ[key]
        result = subprocess.run(
            [str(entry), "version"],
            cwd=root,
            env=env,
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        expected = f"symvault {version}\n"
        if result.returncode != 0 or result.stdout != expected or result.stderr:
            raise ValueError(
                "packaged version check failed: "
                f"exit={result.returncode}, stdout={result.stdout!r}, stderr={result.stderr!r}"
            )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle", required=True, type=Path)
    parser.add_argument("--reference-bundle", required=True, type=Path)
    parser.add_argument("--reference-sha256", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--os", required=True, choices=("darwin", "freebsd", "linux", "windows"))
    parser.add_argument("--arch", required=True, choices=("amd64", "arm64"))
    args = parser.parse_args()

    executable = "symvault.exe" if args.os == "windows" else "symvault"
    reference_digest = hashlib.sha256(args.reference_bundle.read_bytes()).hexdigest()
    if reference_digest != args.reference_sha256:
        raise SystemExit("pinned Go MCPB SHA-256 mismatch")

    require_executable_mode = args.os != "windows"
    reference_manifest = bundle_manifest(
        args.reference_bundle, executable, GO_RELEASE, require_executable_mode
    )
    candidate_manifest = bundle_manifest(
        args.bundle, executable, args.version, require_executable_mode
    )
    reference_contract = {
        key: value for key, value in reference_manifest.items() if key != "version"
    }
    candidate_contract = {
        key: value for key, value in candidate_manifest.items() if key != "version"
    }
    if candidate_contract != reference_contract:
        raise ValueError("candidate MCPB metadata differs from the pinned Go release manifest")
    run_packaged_version(args.bundle, executable, args.version)
    print(
        f"Validated MCPB for {args.os}/{args.arch}: non-version metadata matches Go v{GO_RELEASE}; "
        f"packaged binary and manifest report {args.version}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
