#!/usr/bin/env python3
"""Package a native Rust CLI binary with GoReleaser's archive members."""

import argparse
import glob
from pathlib import Path
import tarfile
import zipfile


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--version", required=True)
    parser.add_argument("--goos", choices=("linux", "darwin", "windows", "freebsd"), required=True)
    parser.add_argument("--goarch", choices=("amd64", "arm64"), required=True)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, default=Path("dist/rust"))
    args = parser.parse_args()

    version = args.version.removeprefix("v")
    stem = f"symaira-vault_{version}_{args.goos}_{args.goarch}"
    binary_name = "symvault.exe" if args.goos == "windows" else "symvault"
    binary = args.binary
    if not binary.is_file():
        parser.error(f"release binary does not exist: {binary}")
    if args.goos == "windows" and binary.name != binary_name:
        parser.error("Windows release binary must be named symvault.exe")
    if args.goos != "windows" and binary.name != binary_name:
        parser.error("release binary must be named symvault")

    inputs = [Path("LICENSE"), Path("README.md")]
    for pattern in ("completions/*", "docs/man/*.1"):
        inputs.extend(Path(path) for path in sorted(glob.glob(pattern)))
    members = [path for path in inputs if path.is_file()]
    if len(members) != len(inputs):
        missing = [str(path) for path in inputs if not path.is_file()]
        parser.error(f"GoReleaser archive input is missing: {', '.join(missing)}")
    members.append(binary)

    args.output_dir.mkdir(parents=True, exist_ok=True)
    if args.goos == "windows":
        archive = args.output_dir / f"{stem}.zip"
        with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as output:
            for path in members:
                output.write(path, f"{stem}/{binary_name if path == binary else path.as_posix()}")
    else:
        archive = args.output_dir / f"{stem}.tar.gz"
        with tarfile.open(archive, "w:gz") as output:
            for path in members:
                name = binary_name if path == binary else path.as_posix()
                output.add(path, arcname=f"{stem}/{name}", recursive=False)
    print(archive)


if __name__ == "__main__":
    main()
