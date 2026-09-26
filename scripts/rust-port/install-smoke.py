#!/usr/bin/env python3
"""Install the staged Rust release archive in a throwaway prefix and smoke it."""

import argparse
import os
from pathlib import Path, PurePosixPath
import stat
import subprocess
import tarfile
import tempfile
import zipfile


def archive_binary(archive: Path, expected_name: str) -> bytes:
    if archive.name.endswith(".tar.gz"):
        with tarfile.open(archive, "r:gz") as bundle:
            members = [
                member
                for member in bundle.getmembers()
                if PurePosixPath(member.name).name == expected_name
            ]
            if len(members) != 1 or not members[0].isfile():
                raise ValueError(f"expected one regular {expected_name} in {archive}")
            path = PurePosixPath(members[0].name)
            if len(path.parts) != 2 or path.is_absolute() or ".." in path.parts:
                raise ValueError(f"unexpected binary path in {archive}: {path}")
            stream = bundle.extractfile(members[0])
            if stream is None:
                raise ValueError(f"cannot read {expected_name} from {archive}")
            with stream:
                return stream.read()
    if archive.suffix == ".zip":
        with zipfile.ZipFile(archive) as bundle:
            members = [
                name
                for name in bundle.namelist()
                if PurePosixPath(name).name == expected_name
            ]
            if len(members) != 1:
                raise ValueError(f"expected one {expected_name} in {archive}")
            path = PurePosixPath(members[0])
            info = bundle.getinfo(members[0])
            mode = info.external_attr >> 16
            if (
                len(path.parts) != 2
                or path.is_absolute()
                or ".." in path.parts
                or stat.S_ISLNK(mode)
                or info.is_dir()
            ):
                raise ValueError(f"unexpected binary path in {archive}: {path}")
            return bundle.read(info)
    raise ValueError(f"unsupported staged archive: {archive}")


def smoke(archive: Path, expected_version: str) -> None:
    binary_name = "symvault.exe" if archive.suffix == ".zip" else "symvault"
    with tempfile.TemporaryDirectory(prefix="symvault-dist-smoke-") as temporary:
        root = Path(temporary)
        install = root / "prefix" / "bin"
        home = root / "home"
        vault = root / "vault"
        for directory in (install, home, vault):
            directory.mkdir(parents=True)

        executable = install / binary_name
        executable.write_bytes(archive_binary(archive, binary_name))
        executable.chmod(0o755)

        env = {
            key: value
            for key, value in os.environ.items()
            if not key.startswith("SYMVAULT_")
        }
        env.update(
            {
                "HOME": str(home),
                "USERPROFILE": str(home),
                "APPDATA": str(home / "AppData" / "Roaming"),
                "LOCALAPPDATA": str(home / "AppData" / "Local"),
                "XDG_CONFIG_HOME": str(home / ".config"),
                "XDG_DATA_HOME": str(home / ".local" / "share"),
                "SYMVAULT_VAULT": str(vault),
                "SYMVAULT_PASSPHRASE": "distribution-smoke-passphrase",
                "SYMVAULT_ALLOW_ENV_PASSPHRASE": "1",
                "SYMVAULT_NO_ENV_WARNING": "1",
            }
        )
        version = subprocess.run(
            [str(executable), "version"],
            check=True,
            capture_output=True,
            text=True,
            env=env,
        )
        output = version.stdout + version.stderr
        if expected_version not in output:
            raise ValueError(
                f"installed version output does not contain {expected_version!r}: {output.strip()}"
            )

        subprocess.run([str(executable), "init"], check=True, env=env)
        for relative in ("config.yaml", "identity.age"):
            path = vault / relative
            if not path.is_file() or path.stat().st_size == 0:
                raise ValueError(f"init did not persist {path}")
        if not (vault / "entries").is_dir():
            raise ValueError(f"init did not persist {vault / 'entries'}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--version", required=True)
    args = parser.parse_args()
    smoke(args.archive, args.version)
    print("staged Rust archive installed and initialized in an isolated home/vault")


if __name__ == "__main__":
    main()
