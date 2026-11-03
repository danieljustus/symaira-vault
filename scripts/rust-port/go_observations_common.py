#!/usr/bin/env python3
"""Committed Go observations: capture the Go side once, replay it without Go.

A live Go/Rust differential becomes two modes of the same script:

  capture (`--capture-go`)  run only the Go oracle and write its normalized
                            observations to
                            scripts/rust-port/fixtures/go-observations/<contract>.<goos>.json
  replay (default)          run the Rust side live, load the committed
                            observations and apply the unchanged comparison.

A missing, malformed or foreign (wrong contract / GOOS / oracle commit) observation
file is a failure, never a skip. Nothing in replay mode may start `go`.

The module is also a small CLI for the Makefile targets that only observed a
`go test` / `go run ... --check` run:

  capture-go-json  CONTRACT [--env K=V] -- go test ... -json    keep Action/Package/Test of the finished tests
  replay-go-json   CONTRACT --output PATH                       write them back as `go test -json` rows
  capture-go-text  CONTRACT [--env K=V] -- go test ... -v       keep the `--- PASS: NAME` lines
  replay-go-text   CONTRACT --output PATH
  capture-checked  CONTRACT --file F... [--env K=V] -- cmd      run a Go `--check`, record sha256 of F
  replay-checked   CONTRACT --file F...                         the files still have the recorded bytes
  capture-verdict  CONTRACT --artifact F... [--env K=V] -- cmd  Go verifies a Rust-written artifact
  replay-verdict   CONTRACT --artifact F...                     sha256 of the artifact matches the attestation
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
OBS_DIR = Path(__file__).resolve().parent / "fixtures" / "go-observations"
SCHEMA = 1
HOW_TO_CAPTURE = "run `make go-observations-capture-other` on a host with the Go oracle"


class MissingObservation(AssertionError):
    """The committed Go observation a replay needs is absent or unusable."""


def host_goos():
    return {"Darwin": "darwin", "Linux": "linux", "Windows": "windows"}.get(platform.system(), platform.system().lower())


def host_arch():
    return {"x86_64": "amd64", "AMD64": "amd64", "aarch64": "arm64"}.get(platform.machine(), platform.machine())


def rel(file):
    try:
        return Path(file).relative_to(ROOT)
    except ValueError:
        return Path(file)


def path(contract, goos=None):
    return OBS_DIR / f"{contract}.{goos or host_goos()}.json"


def sha256_file(file):
    return hashlib.sha256(Path(file).read_bytes()).hexdigest()


def go_version(env=None, cwd=ROOT):
    return subprocess.run(["go", "env", "GOVERSION"], cwd=cwd, env=env, capture_output=True, check=True,
                          text=True).stdout.strip()


def canonical(document):
    return json.dumps(document, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def save(contract, observations, *, oracle_commit, version, args, goos=None, material=None):
    """Write the normalized observations of one capture. Returns the file path.

    `material` is Go-written input that the Rust replay needs but that is random per
    run (an encrypted vault seed). It is minted once: an existing document keeps its
    material, so two captures stay byte-identical. Delete the file to mint again.
    """
    goos = goos or host_goos()
    target = path(contract, goos)
    document = {"schema": SCHEMA, "contract": contract, "oracle_commit": oracle_commit, "go_version": version,
                "goos": goos, "goarch": host_arch(), "args": list(args), "observations": observations}
    if material is not None:
        try:
            kept = json.loads(target.read_bytes()).get("material")
        except (OSError, ValueError, AttributeError):
            kept = None
        document["material"] = kept if kept is not None else material
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(canonical(document).encode("utf-8"))
    return target


def existing_material(contract, goos=None):
    """The committed material of this contract, or None (capture mints it then)."""
    try:
        return json.loads(path(contract, goos).read_bytes()).get("material")
    except (OSError, ValueError, AttributeError):
        return None


def load(contract, *, oracle_commit=None, goos=None):
    """Return the committed document for this host; missing or foreign means failure."""
    goos = goos or host_goos()
    source = path(contract, goos)
    if not source.is_file():
        raise MissingObservation(f"missing Go observation {rel(source)}: {HOW_TO_CAPTURE}")
    try:
        document = json.loads(source.read_bytes())
    except ValueError as error:
        raise MissingObservation(f"unreadable Go observation {source.name}: {error}") from error
    need = (isinstance(document, dict) and document.get("schema") == SCHEMA and document.get("contract") == contract
            and document.get("goos") == goos and "observations" in document
            and all(key in document for key in ("oracle_commit", "go_version", "goarch", "args")))
    if not need:
        raise MissingObservation(f"{source.name}: not a schema-{SCHEMA} observation of {contract} on {goos}")
    if oracle_commit is not None and document["oracle_commit"] != oracle_commit:
        raise MissingObservation(f"{source.name}: recorded for oracle {document['oracle_commit']}, expected {oracle_commit}")
    return document


def pack_tree(root):
    """A directory as {relative path: base64, or None for a directory} (sorted, no links)."""
    root = Path(root)
    packed = {}
    for entry in sorted(root.rglob("*")):
        name = str(entry.relative_to(root))
        if entry.is_dir() and not entry.is_symlink():
            packed[name] = None
        elif entry.is_file():
            packed[name] = base64.b64encode(entry.read_bytes()).decode("ascii")
    return packed


def unpack_tree(files, root):
    """Write a pack_tree() mapping below `root` with private modes (0700 dirs, 0600 files)."""
    root = Path(root)
    root.mkdir(parents=True, exist_ok=True)
    os.chmod(root, 0o700)
    for name, data in files.items():
        target = root / name
        for parent in reversed([q for q in target.parents if q != root and root in q.parents]):
            parent.mkdir(exist_ok=True)
            os.chmod(parent, 0o700)
        if data is None:
            target.mkdir(exist_ok=True)
            os.chmod(target, 0o700)
        else:
            target.write_bytes(base64.b64decode(data))
            os.chmod(target, 0o600)


IDENTITIES = [("server-ca", None, True, None), ("server", "server-ca", False, "serverAuth"),
              ("client-ca", None, True, None), ("client", "client-ca", False, "clientAuth"),
              ("foreign-ca", None, True, None), ("foreign-client", "foreign-ca", False, "clientAuth")]


def mint_tls_identities(root, scratch):
    """Twelve public-fixture TLS files (same names and shape as the Go
    http_tls_identity generator: P-256 chains valid for a day) with the openssl CLI.

    `root` is created 0700 and only receives <name>.pem / <name>.key; keys, CSRs
    and configuration go to `scratch`.
    """
    root, scratch = Path(root), Path(scratch)
    root.mkdir(mode=0o700)
    scratch.mkdir(parents=True, exist_ok=True)

    def run(*command):
        done = subprocess.run([str(x) for x in command], capture_output=True)
        assert done.returncode == 0, (command[:3], done.stderr.decode(errors="replace")[-1500:])

    for name, issuer, is_ca, usage in IDENTITIES:
        key, csr, ext = root / f"{name}.key", scratch / f"{name}.csr", scratch / f"{name}.cnf"
        subject = f"/CN=public-http-tls-{name}"
        if is_ca:
            extensions = ("basicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,digitalSignature,keyCertSign,cRLSign\n"
                          "subjectKeyIdentifier=hash\n")
        else:
            extensions = (f"basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage={usage}\n"
                          "subjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n")
            if usage == "serverAuth":
                extensions += "subjectAltName=DNS:localhost,DNS:vault.example.test,IP:127.0.0.1,IP:::1\n"
        extensions = extensions.replace("\\n", "\n")
        ext.write_text("[req]\ndistinguished_name=dn\nprompt=no\n[dn]\nCN=x\n[v3]\n" + extensions)
        run("openssl", "genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256", "-pkeyopt", "ec_param_enc:named_curve", "-out", key)
        certificate = root / f"{name}.pem"
        if issuer is None:
            run("openssl", "req", "-x509", "-new", "-sha256", "-key", key, "-subj", subject, "-days", "1",
                "-config", ext, "-extensions", "v3", "-out", certificate)
        else:
            run("openssl", "req", "-new", "-key", key, "-subj", subject, "-out", csr)
            run("openssl", "x509", "-req", "-sha256", "-in", csr, "-CA", root / f"{issuer}.pem", "-CAkey", root / f"{issuer}.key",
                "-set_serial", int.from_bytes(os.urandom(8), "big") >> 1, "-days", "1",
                "-extfile", ext, "-extensions", "v3", "-out", certificate)
        os.chmod(key, 0o600)
        os.chmod(certificate, 0o600)
    return sorted(p.name for p in root.iterdir())


def mint_api_chain(root, scratch):
    """ca.pem / leaf.pem / leaf-key.pem of the API transport contract (what the Go
    probe's `cert` mode wrote): a CA and a P-256 leaf valid for dns-api.example.test."""
    root, scratch = Path(root), Path(scratch)
    scratch.mkdir(parents=True, exist_ok=True)
    ca_ext, leaf_ext = scratch / "ca.cnf", scratch / "leaf.cnf"
    header = "[req]\ndistinguished_name=dn\nprompt=no\n[dn]\nCN=x\n[v3]\n"
    ca_ext.write_text(header + "basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\n")
    leaf_ext.write_text(header + "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\n"
                        "subjectAltName=DNS:dns-api.example.test\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n")

    def run(*command):
        done = subprocess.run([str(x) for x in command], capture_output=True)
        assert done.returncode == 0, (command[:3], done.stderr.decode(errors="replace")[-1500:])

    key_options = ["-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256", "-pkeyopt", "ec_param_enc:named_curve"]
    run("openssl", "genpkey", *key_options, "-out", scratch / "ca.key")
    run("openssl", "genpkey", *key_options, "-out", root / "leaf-key.pem")
    run("openssl", "req", "-x509", "-new", "-sha256", "-key", scratch / "ca.key", "-subj", "/CN=public native API fixture CA",
        "-days", "1", "-config", ca_ext, "-extensions", "v3", "-out", root / "ca.pem")
    run("openssl", "req", "-new", "-key", root / "leaf-key.pem", "-subj", "/CN=dns-api.example.test", "-out", scratch / "leaf.csr")
    run("openssl", "x509", "-req", "-sha256", "-in", scratch / "leaf.csr", "-CA", root / "ca.pem", "-CAkey", scratch / "ca.key",
        "-set_serial", 2, "-days", "1", "-extfile", leaf_ext, "-extensions", "v3", "-out", root / "leaf.pem")
    for name in ("ca.pem", "leaf.pem", "leaf-key.pem"):
        os.chmod(root / name, 0o600)


def first_difference(left, right, where="$"):
    if type(left) is not type(right):
        return f"{where}: {type(left).__name__} != {type(right).__name__}"
    if isinstance(left, dict):
        for key in sorted(set(left) | set(right)):
            if key not in left or key not in right:
                return f"{where}.{key}: present on one side only"
            found = first_difference(left[key], right[key], f"{where}.{key}")
            if found:
                return found
        return None
    if isinstance(left, list):
        if len(left) != len(right):
            return f"{where}: length {len(left)} != {len(right)}"
        for index, (a, b) in enumerate(zip(left, right)):
            found = first_difference(a, b, f"{where}[{index}]")
            if found:
                return found
        return None
    return None if left == right else f"{where}: {left!r} != {right!r}"


def compare(recorded, live, what):
    found = first_difference(recorded, live)
    assert found is None, f"{what}: recorded Go observation differs from live Rust: {found}"


def add_capture_flag(parser):
    parser.add_argument("--capture-go", action="store_true",
                        help="run only the Go oracle and write its observations (needs Go)")


def stable_args(args, *names):
    """Argument names/values that identify a capture, without host paths."""
    return [f"{name}={getattr(args, name)}" for name in names]


# ---- reductions of `go test` output ----------------------------------------------

def reduce_go_json(text):
    """Finished-test rows only (no timings, no output), deduplicated and sorted."""
    rows = set()
    for line in text.splitlines():
        if not line.startswith("{"):
            continue
        row = json.loads(line)
        if row.get("Action") in {"pass", "skip", "fail"}:
            rows.add((row.get("Package", ""), row.get("Test", ""), row["Action"]))
    return [{"Action": action, "Package": package, **({"Test": test} if test else {})}
            for package, test, action in sorted(rows)]


def reduce_go_text(text):
    names = set()
    for line in text.splitlines():
        stripped = line.strip()
        for verdict in ("PASS", "FAIL", "SKIP"):
            prefix = f"--- {verdict}: "
            if stripped.startswith(prefix):
                names.add((verdict, stripped[len(prefix):].split(" ")[0]))
    return [f"--- {verdict}: {name} (0.00s)" for verdict, name in sorted(names)]


def _run(command, env_pairs):
    env = os.environ.copy()
    env.update(pair.split("=", 1) for pair in env_pairs or [])
    result = subprocess.run(command, cwd=ROOT, env=env, capture_output=True, text=True)
    sys.stdout.write(result.stderr[-2000:] if result.returncode else "")
    if result.returncode:
        sys.stdout.write(result.stdout[-4000:])
        raise SystemExit(f"{' '.join(command[:3])}...: exit {result.returncode}")
    return result, env


def tree_oracle_commit():
    """Last commit that touched the in-tree Go sources: stable across unrelated commits."""
    return subprocess.run(["git", "log", "-1", "--format=%H", "--", "*.go", "go.mod", "go.sum"], cwd=ROOT,
                          capture_output=True, text=True, check=True).stdout.strip()


def _oracle(env):
    return tree_oracle_commit(), go_version(env)


def _fail(message):
    raise SystemExit(f"go_observations_common: FAIL: {message}")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("capture-go-json", "capture-go-text", "capture-checked", "capture-verdict"):
        p = sub.add_parser(name)
        p.add_argument("contract")
        p.add_argument("--env", action="append", default=[])
        p.add_argument("--file", action="append", default=[])
        p.add_argument("--artifact", action="append", default=[])
    for name in ("replay-go-json", "replay-go-text"):
        p = sub.add_parser(name)
        p.add_argument("contract")
        p.add_argument("--output", required=True)
    for name in ("replay-checked", "replay-verdict"):
        p = sub.add_parser(name)
        p.add_argument("contract")
        p.add_argument("--file", action="append", default=[])
        p.add_argument("--artifact", action="append", default=[])
    argv = list(sys.argv[1:] if argv is None else argv)
    command = []
    if "--" in argv:
        split = argv.index("--")
        argv, command = argv[:split], argv[split + 1:]
    args = parser.parse_args(argv)

    try:
        if args.command.startswith("capture-"):
            assert command, "no command after --"
            result, env = _run(command, args.env)
            commit, version = _oracle(env)
            if args.command == "capture-go-json":
                observations = {"events": reduce_go_json(result.stdout)}
            elif args.command == "capture-go-text":
                observations = {"lines": reduce_go_text(result.stdout + result.stderr)}
            elif args.command == "capture-checked":
                assert args.file, "--file required"
                observations = {"files": {f: sha256_file(ROOT / f) for f in sorted(args.file)}, "check_exit": 0}
            else:
                assert args.artifact, "--artifact required"
                observations = {"artifacts": {f: sha256_file(ROOT / f) for f in sorted(args.artifact)}, "verdict": "go-accepts"}
            target = save(args.contract, observations, oracle_commit=commit, version=version, args=command)
            print(f"captured {rel(target)}")
            return 0
        document = load(args.contract)
        observed = document["observations"]
        if args.command == "replay-go-json":
            rows = observed["events"]
            Path(args.output).write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in rows))
        elif args.command == "replay-go-text":
            Path(args.output).write_text("".join(line + "\n" for line in observed["lines"]))
        elif args.command == "replay-checked":
            expected = observed["files"]
            if sorted(args.file) != sorted(expected):
                _fail(f"{args.contract}: recorded files {sorted(expected)}, asked {sorted(args.file)}")
            for name, digest in expected.items():
                if sha256_file(ROOT / name) != digest:
                    _fail(f"{name} no longer has the bytes the Go check accepted")
        else:
            expected = observed["artifacts"]
            if sorted(args.artifact) != sorted(expected):
                _fail(f"{args.contract}: recorded artifacts {sorted(expected)}, asked {sorted(args.artifact)}")
            for name, digest in expected.items():
                if sha256_file(ROOT / name) != digest:
                    _fail(f"{name} differs from the artifact the Go verdict covers")
            assert observed["verdict"] == "go-accepts"
        print(f"replayed {rel(path(args.contract))}")
        return 0
    except MissingObservation as error:
        _fail(str(error))
    except (AssertionError, KeyError, OSError, ValueError) as error:
        _fail(f"{type(error).__name__}: {error}")


if __name__ == "__main__":
    sys.exit(main())
