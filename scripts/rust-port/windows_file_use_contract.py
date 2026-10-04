#!/usr/bin/env python3
"""Execute native Go/Rust file-use with ordinary .NET read-only sharing."""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import struct
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
ORACLE = "55da4ca13ead39d4000cf6f866ac8671ca86d8f2"
PAYLOAD = b"file-use-secret\0\xff"
READER = r'''param([string]$Marker, [string]$Mode)
$ErrorActionPreference = 'Stop'
$path = $env:SYMVAULT_FILE_CERT_P12
# ReadAllBytes uses the ordinary FileShare.Read reader that exposed #1145.
$bytes = [System.IO.File]::ReadAllBytes($path)
$encoded = [System.Convert]::ToBase64String($bytes)
if ($encoded -cne 'ZmlsZS11c2Utc2VjcmV0AP8=') { throw 'payload mismatch' }
$utf8 = [System.Text.UTF8Encoding]::new($false)
[System.IO.File]::WriteAllText($Marker, $path, $utf8)
$out = [Console]::OpenStandardOutput()
$err = [Console]::OpenStandardError()
$out.Write($bytes, 0, $bytes.Length)
$err.Write($bytes, 0, $bytes.Length)
$base64bytes = $utf8.GetBytes("`n$encoded`n")
$out.Write($base64bytes, 0, $base64bytes.Length)
$err.Write($base64bytes, 0, $base64bytes.Length)
$out.Flush()
$err.Flush()
if ($Mode -eq 'error') { exit 7 }
if ($Mode -eq 'timeout') { Start-Sleep -Seconds 30 }
'''


def run(args, cwd=ROOT, env=None, timeout=180):
    return subprocess.run([str(x) for x in args], cwd=cwd, env=env,
                          capture_output=True, timeout=timeout)


def checked(args, **kwargs):
    result = run(args, **kwargs)
    if result.returncode:
        raise RuntimeError(f"{args[0]} failed ({result.returncode}): "
                           + result.stderr.decode(errors="replace")[-4000:])
    return result.stdout


def pe_machine(binary):
    data = binary.read_bytes()
    assert data[:2] == b"MZ", "acceptance requires a native PE executable"
    offset = struct.unpack_from("<I", data, 0x3c)[0]
    assert data[offset:offset+4] == b"PE\0\0"
    return struct.unpack_from("<H", data, offset+4)[0]


def isolated(home):
    env = {k: v for k, v in os.environ.items() if not k.startswith("SYMVAULT_")}
    temporary = home / "temporary"
    temporary.mkdir()
    env.update(HOME=str(home), USERPROFILE=str(home),
               TMP=str(temporary), TEMP=str(temporary),
               XDG_CONFIG_HOME=str(home / "config"), XDG_DATA_HOME=str(home / "data"),
               XDG_CACHE_HOME=str(home / "cache"), SYMVAULT_TEST_KEYRING="memory",
               SYMVAULT_VAULT=str(home / "vault"),
               SYMVAULT_PASSPHRASE="correct horse battery staple",
               SYMVAULT_ALLOW_ENV_PASSPHRASE="1", SYMVAULT_NO_ENV_WARNING="1")
    return env


def exercise(binary, inspector, home, reader, pwsh):
    home.mkdir()
    env = isolated(home)
    checked([inspector, "init", "--auth", "passphrase"], cwd=home, env=env)
    source = home / "fixture.p12"
    source.write_bytes(PAYLOAD)
    checked([inspector, "file", "add", "work/file-use", "--field", "cert_p12",
             "--from", source], cwd=home, env=env)
    records = []
    for mode in ["ordinary", "error", "timeout", "launch-error"]:
        marker = home / f"{mode}-marker"
        command = [pwsh, "-NoProfile", "-NonInteractive", "-File", reader, marker, mode]
        if mode == "launch-error":
            command = [home / "does-not-exist.exe"]
        args = [binary, "file", "use", "work/file-use#cert_p12"]
        if mode == "timeout":
            args += ["--timeout", "8s"]
        result = run([*args, "--", *command], cwd=home, env=env)
        assert (result.returncode == 0) == (mode == "ordinary"), (mode, result.stderr)
        for stream in [result.stdout, result.stderr]:
            assert b"file-use-secret" not in stream and base64.b64encode(PAYLOAD) not in stream, (mode, stream)
        if mode != "launch-error":
            assert marker.is_file(), (mode, "ordinary reader did not complete", result.stderr)
            materialized = Path(marker.read_bytes().decode("utf-8"))
            assert not materialized.exists(), (mode, "payload file remains")
            assert not materialized.parent.exists(), (mode, "private directory remains")
        assert not list((home / "temporary").glob("symvault-file-*")), (mode, "materialization remains")
        if mode in ["ordinary", "error"]:
            # The public Go/Rust output contract uses *** for each raw and
            # Base64 value; require both replacements after the exact reader.
            for stream in [result.stdout, result.stderr]:
                assert b"***\n***\n" in stream.replace(b"\r\n", b"\n"), (mode, stream)
        if mode == "error":
            assert b"command exited with code 7" in result.stderr, result.stderr
        if mode == "timeout":
            assert b"timed out" in result.stderr, result.stderr
        records.append({"case": mode, "exit": result.returncode,
                        "ordinary_reader_exact_bytes": mode != "launch-error",
                        "raw_and_base64_redacted": True, "file_and_directory_removed": True,
                        "stdout": result.stdout.decode("utf-8").replace("\r\n", "\n"),
                        "stderr": result.stderr.decode("utf-8").replace(str(home), "__HOME__").replace("\r\n", "\n")})
    return records


def inventory(paths, root):
    digest = hashlib.sha256()
    for path in paths:
        digest.update(path.encode()+b"\0"+(root/path).read_bytes()+b"\0")
    return digest.hexdigest()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--rust", required=True, type=Path)
    parser.add_argument("--architecture", required=True, choices=["x64", "arm64"])
    parser.add_argument("--receipt", required=True, type=Path)
    args = parser.parse_args()
    assert platform.system() == "Windows", "this gate requires actual Windows execution"
    pwsh = shutil.which("pwsh")
    assert pwsh, "real PowerShell/.NET is mandatory"
    expected = {"x64": 0x8664, "arm64": 0xAA64}[args.architecture]
    # On Windows ARM64, PROCESSOR_ARCHITEW6432 identifies the native machine
    # even when setup-python supplied an x64 interpreter. Both tested binaries
    # must be ARM64 PE binaries, and are executed below on that native machine.
    native_arch = os.environ.get("PROCESSOR_ARCHITEW6432", os.environ.get("PROCESSOR_ARCHITECTURE", "")).upper()
    assert native_arch == {"x64": "AMD64", "arm64": "ARM64"}[args.architecture], native_arch
    rust = args.rust.resolve()
    assert pe_machine(rust) == expected, "candidate architecture does not match the native runner"
    clean = not checked(["git", "status", "--porcelain=v1", "--untracked-files=normal"]).strip()
    assert clean, "commit the candidate before recording native acceptance"
    tracked = checked(["git", "ls-files"]).decode().splitlines()
    sources = sorted(x for x in tracked if x.startswith(("crates/", "third_party/", "testdata/"))
                     or x in {"Cargo.toml", "Cargo.lock", ".gitattributes", "scripts/rust-port/windows_file_use_contract.py",
                              ".github/workflows/rust-windows-file-use.yml"})
    with tempfile.TemporaryDirectory(prefix="symvault-windows-file-contract-") as raw:
        base = Path(raw)
        tree = base / "oracle"
        checked(["git", "worktree", "add", "--detach", tree, ORACLE])
        try:
            go = base / "go.exe"
            build_env = dict(os.environ, GOOS="windows", GOARCH={"x64": "amd64", "arm64": "arm64"}[args.architecture])
            checked(["go", "build", "-trimpath", "-buildvcs=false", "-o", go, "."], cwd=tree, env=build_env)
            assert pe_machine(go) == expected
            oracle_sources = sorted(x for x in checked(["git", "ls-tree", "-r", "--name-only", ORACLE]).decode().splitlines()
                                    if x in {"go.mod", "go.sum"} or (x.endswith(".go") and not x.endswith("_test.go")))
            reader = base / "ordinary-reader.ps1"
            reader.write_bytes(READER.encode("utf-8"))
            observed_go = exercise(go, go, base / "go-home", reader, pwsh)
            observed_rust = exercise(rust, go, base / "rust-home", reader, pwsh)
            for left, right in zip(observed_go, observed_rust, strict=True):
                for key in ["case", "exit", "ordinary_reader_exact_bytes", "raw_and_base64_redacted", "file_and_directory_removed"]:
                    assert left[key] == right[key], (key, left, right)
                if left["case"] in ["ordinary", "error"]:
                    assert left["stdout"] == right["stdout"], (left, right)
            receipt = {"passed": True, "oracle_commit": ORACLE,
                       "oracle_source_files": oracle_sources,
                       "oracle_source_digest": inventory(oracle_sources, tree),
                       "go_binary_sha256": hashlib.sha256(go.read_bytes()).hexdigest(),
                       "rust_binary_sha256": hashlib.sha256(rust.read_bytes()).hexdigest(),
                       "go_pe_machine": pe_machine(go), "rust_pe_machine": pe_machine(rust),
                       "candidate_commit": checked(["git", "rev-parse", "HEAD"]).decode().strip(),
                       "candidate_worktree_clean": clean, "candidate_source_files": sources,
                       "candidate_source_digest": inventory(sources, ROOT),
                       "driver_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                       "reader_sha256": hashlib.sha256(reader.read_bytes()).hexdigest(),
                       "payload_sha256": hashlib.sha256(PAYLOAD).hexdigest(),
                       "native_os": platform.system(), "native_architecture": native_arch,
                       "requested_architecture": args.architecture, "keyring": "memory",
                       "go": observed_go, "rust": observed_rust}
            args.receipt.write_bytes((json.dumps(receipt, indent=2)+"\n").encode("utf-8"))
            print(f"PASS: four actual Go/Rust file-use cases on native Windows {args.architecture}")
        finally:
            checked(["git", "worktree", "remove", tree])


if __name__ == "__main__":
    main()
