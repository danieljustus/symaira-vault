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
  replay-go-json   CONTRACT --output PATH [--append]            write them back as `go test -json` rows
  capture-go-text  CONTRACT [--env K=V] -- go test ... -v       keep the `--- PASS: NAME` lines
  replay-go-text   CONTRACT --output PATH
  capture-checked  CONTRACT --file F... [--env K=V] -- cmd      run a Go `--check`, record sha256 of F
  replay-checked   CONTRACT --file F...                         the files still have the recorded bytes
  capture-verdict  CONTRACT --artifact F... [--env K=V] -- cmd  Go verifies a Rust-written artifact
  replay-verdict   CONTRACT --artifact F...                     sha256 of the artifact matches the attestation

Reverse checks (Go verifies what Rust wrote) cannot be replayed without Go; they are attested once:

  attest NAME --artifact LABEL=PATH... [--env K=V] [--note T] -- cmd
        run the Go-side verdict `cmd` (must exit 0) and write
        docs/rust-port/evidence/go-removal-attestations/NAME.<goos>.json: sha256 of every Rust artifact,
        the Go verdict (command, exit code, sha256 of its output), the oracle commit and the Rust commit
  attest-ci NAME --run-url U --job-id N --commit SHA --source PATH...
        a native attestation taken from a recorded CI run (a disposable host this machine is not) instead of a local
        Go run; allowed only when `git diff --quiet SHA HEAD -- PATH...` holds, and every verification recomputes the
        digest of PATH...: changed sources invalidate it.
  verify-attestation NAME
        replay: the attestation exists for this host, is well-formed, has exactly the expected artifact labels, was
        built from a commit that is an ancestor of HEAD and records an accepting Go verdict (missing = failure,
        unless the documented ACCEPTED_GAPS names this OS: then the gap is printed and the check passes). It is a
        STATIC, historical claim: Go is not re-run, and the artifact digests are provenance, not a pin on future builds.
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
ATTEST_DIR = ROOT / "docs" / "rust-port" / "evidence" / "go-removal-attestations"
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
    text = canonical(document).encode("utf-8")
    leaked = operator_paths(text)
    if leaked:
        raise ValueError(f"{contract}: refusing to record operator paths {leaked}")
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(text)
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


TREE_ROOT = "@TREE_ROOT@"
# What must never reach a committed observation or attestation: operator workstation paths and the
# random mkdtemp directories of a capture (macOS /var/folders/.., Linux /tmp/<prefix>-<random>).
OPERATOR_PATH = re.compile(rb"/Volumes/|/Users/|/var/folders/|/private/var/|/private/tmp/|/tmp/[A-Za-z0-9_.-]{4,}")


def path_forms(root):
    """Every spelling of a directory a tool may print: as given, resolved (/private/var on macOS), longest first."""
    root = Path(root)
    forms = {str(root), str(root.resolve()), os.path.realpath(root)}
    forms |= {f[len("/private"):] for f in list(forms) if f.startswith("/private/")}
    return sorted(forms, key=len, reverse=True)


def tokenize_paths(data, tokens):
    """bytes -> bytes with every directory in `tokens` ({directory: token}) replaced by its token."""
    for directory, token in tokens.items():
        for form in path_forms(directory):
            data = data.replace(form.encode(), token.encode())
    return data


def restore_paths(data, tokens):
    """The inverse of tokenize_paths for this run's directories ({token: directory})."""
    for token, directory in tokens.items():
        data = data.replace(token.encode(), str(directory).encode())
    return data


def operator_paths(data):
    """Distinct operator-path matches in raw bytes, in their base64 decodings, and in JSON string values
    (packed trees and material hold file contents as base64)."""
    found = {m.group(0).decode() for m in OPERATOR_PATH.finditer(data)}
    for chunk in re.finditer(rb"[A-Za-z0-9+/]{16,}={0,2}", data):
        raw = chunk.group(0)
        try:
            decoded = base64.b64decode(raw + b"=" * (-len(raw) % 4))
        except ValueError:
            continue
        found |= {"base64:" + m.group(0).decode() for m in OPERATOR_PATH.finditer(decoded)}
    return sorted(found)


def pack_tree(root):
    """A directory as {relative path: base64, or None for a directory} (sorted, no links).

    The directory itself (and its /private spelling) is stored as the `@TREE_ROOT@` token, so a Go-written
    config.yaml does not record the capture host's temporary path; unpack_tree() puts the replay's own
    directory back. A path that is still an operator path after that is an error, never a commit.
    """
    root = Path(root)
    packed = {}
    for entry in sorted(root.rglob("*")):
        name = str(entry.relative_to(root))
        if entry.is_dir() and not entry.is_symlink():
            packed[name] = None
        elif entry.is_file():
            data = tokenize_paths(entry.read_bytes(), {root: TREE_ROOT})
            leaked = operator_paths(data)
            if leaked:
                raise ValueError(f"{name}: would record operator paths {leaked}")
            packed[name] = base64.b64encode(data).decode("ascii")
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
            target.write_bytes(restore_paths(base64.b64decode(data), {TREE_ROOT: root}))
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


# The Go oracle every helper-driven capture and attestation is keyed to. It is a fixed commit like the other
# contracts' pins: the last commit that touched the in-tree Go sources (`git log -1 -- '*.go' go.mod go.sum`)
# when these observations were recorded. Keying them to "the last *.go commit of the checkout" broke as soon
# as the Go sources were removed, and in shallow clones.
ORACLE_COMMIT = "19e4021c0e375ac06ae0a7203682e4a43176ca0f"


def tree_oracle_commit():
    """The pinned oracle commit. Capture (which has Go and the git history) first proves that the checkout's
    Go sources are still exactly those of the pin; a deliberate bump of ORACLE_COMMIT is then the only way
    to record observations of different Go."""
    moved = subprocess.run(["git", "diff", "--quiet", ORACLE_COMMIT, "--", "*.go", "go.mod", "go.sum"], cwd=ROOT,
                           capture_output=True)
    if moved.returncode != 0:
        raise SystemExit(f"go_observations_common: the Go sources differ from the pinned oracle {ORACLE_COMMIT[:8]} (or the "
                         "commit is missing from this clone): recording would label other Go with that pin; bump "
                         "ORACLE_COMMIT deliberately and recapture")
    return ORACLE_COMMIT


def _oracle(env):
    return tree_oracle_commit(), go_version(env)


def attestation_path(name, goos=None):
    return ATTEST_DIR / f"{name}.{goos or host_goos()}.json"


# What each attestation must cover: the artifact labels its `rust_artifacts_sha256` holds. A file with other
# labels (or none) is not an attestation of this check, whatever else it says. The attestations are static
# historical claims: "at oracle ORACLE_COMMIT, built from rust_commit, live Go accepted these artifacts".
# Nothing re-runs Go; the Rust sides of the same checks run live in the make targets that verify them.
DATA_SAFETY = "data-safety-contract"
DATA_SAFETY_REVERSE = [f"ffi-seed#{i}" for i in range(5)] + [f"go-init#{i}" for i in range(3, 8)] + ["zero-key#2"]
EXPECTED_ARTIFACTS = {
    "audit-differential": ["rust-output.jsonl"],
    "crypto-differential": ["rust-output.txt"],
    "reencrypt-journal-differential": ["symvault"],
    "kdf-go-rust-integration": ["symvault"],
    "ffi-differential": ["symvault"],
    "pairing-oracle": ["symvault"],
    "native-keyring-interop": ["rust-native-keyring-test"],
    DATA_SAFETY: sorted(DATA_SAFETY_REVERSE),
}
# Gaps that are accepted, documented and visible: the verifying target prints them and passes. An entry here
# is not a skip of a check that exists; the attestation cannot be produced on that OS (see the text).
ACCEPTED_GAPS = {
    ("tui-contract", "darwin"): (
        "the fifteen-case live Go-vs-Rust terminal comparison drives the real macOS pasteboard, so it only runs on a disposable "
        "CI host (rust-tui.yml, macos-latest) and no darwin Go observation is recorded; every successful rust-tui.yml macOS run "
        "predates Rust TUI sources that differ from this tree (crates/symvault-platform/src/{text_clipboard,desktop_commands}.rs, "
        "crates/symvault-store/src), so no CI run covers this code. The darwin lane keeps tui_harness_test.py; the gap closes "
        "when rust-tui.yml passes on macos-latest at this tree (record it with `attest-ci`)."),
}
CI_RUN_URL = re.compile(r"https://github\.com/danieljustus/symaira-vault/actions/runs/[0-9]+")


def portable(text):
    """Text with this checkout, cargo target, home and temp directories replaced by placeholders."""
    text = str(text)
    for value, token in ((ROOT, "<repo>"), (os.environ.get("CARGO_TARGET_DIR"), "<cargo-target>"),
                         (os.environ.get("TMPDIR"), "<tmp>"), (Path.home(), "<home>")):
        if value:
            for form in path_forms(value):
                if form.count("/") >= 2:
                    text = text.replace(form.rstrip("/"), token)
    return text


def git_output(*argv):
    return subprocess.run(["git", *argv], cwd=ROOT, capture_output=True, text=True, check=True).stdout.strip()


def sources_digest(paths):
    """One digest over the bytes of the named repository files (path and content, sorted)."""
    digest = hashlib.sha256()
    for name in sorted(paths):
        digest.update(name.encode() + b"\0" + (ROOT / name).read_bytes() + b"\0")
    return digest.hexdigest()


def write_attestation(name, artifacts, command, env_pairs, note, require=None, forbid=None):
    """Run the Go verdict `command` once and persist the attestation (deterministic keys, no timestamps).

    `require` / `forbid`: regular expressions the command's output must / must not match, so a verdict that
    printed a SKIP instead of running the Go half cannot be attested."""
    result, env = _run(command, env_pairs)
    output = result.stdout + result.stderr
    if require and not re.search(require, output):
        raise SystemExit(f"attest {name}: the verdict output does not match /{require}/")
    if forbid and re.search(forbid, output):
        raise SystemExit(f"attest {name}: the verdict output matches /{forbid}/: the Go half did not run")
    return record_attestation(name, artifacts, command, env, result.returncode, output, note)


def record_attestation(name, artifacts, command, env, returncode, output, note):
    """Persist the attestation of a Go verdict that has already run (its command, exit code and output)."""
    digests = {}
    for item in artifacts:
        label, _, file = item.partition("=")
        digests[label] = sha256_file(Path(file) if Path(file).is_absolute() else ROOT / file)
    verdict = {"command": [portable(x) for x in command], "exit_code": returncode,
               "output_sha256": hashlib.sha256(output.encode()).hexdigest(), "accepted": returncode == 0}
    return store_attestation(name, digests, verdict, note, env=env)


def store_attestation(name, digests, verdict, note, *, env=None, extra=None):
    document = {"schema": SCHEMA, "name": name, "direction": note, "oracle_commit": tree_oracle_commit(),
                "go_version": go_version(env), "goos": host_goos(), "goarch": host_arch(),
                "rust_commit": git_output("rev-parse", "HEAD"), "rust_artifacts_sha256": digests, "go_verdict": verdict}
    document.update(extra or {})
    text = canonical(document).encode("utf-8")
    leaked = operator_paths(text)
    if leaked:
        raise ValueError(f"{name}: refusing to record operator paths {leaked}")
    target = attestation_path(name)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(text)
    return target


def write_ci_attestation(name, *, run_url, job_id, commit, source_paths, note):
    """A native attestation that comes from a recorded CI run instead of a local Go run. The run's commit must
    have byte-identical `source_paths` to this checkout (checked now, and recomputed by every verification)."""
    assert CI_RUN_URL.fullmatch(run_url) and int(job_id) > 0 and re.fullmatch(r"[0-9a-f]{40}", commit), "malformed CI run"
    assert source_paths, "no source paths"
    same = subprocess.run(["git", "diff", "--quiet", commit, "HEAD", "--", *source_paths], cwd=ROOT).returncode == 0
    assert same, f"{name}: the sources differ between CI commit {commit[:8]} and HEAD"
    document = {"schema": SCHEMA, "name": name, "direction": note, "source": "ci-run", "goos": host_goos(),
                "run_url": run_url, "job_id": int(job_id), "commit": commit, "source_paths": sorted(source_paths),
                "source_digest": sources_digest(source_paths), "oracle_commit": ORACLE_COMMIT}
    target = attestation_path(name)
    target.write_bytes(canonical(document).encode("utf-8"))
    return target


def accepted_gap(name):
    return ACCEPTED_GAPS.get((name, host_goos()))


def check_attestation(name):
    source = attestation_path(name)
    if not source.is_file():
        raise MissingObservation(f"missing Go removal attestation {rel(source)}: run its attest target with the Go oracle present")
    document = json.loads(source.read_bytes())
    bad = f"{rel(source)}: not an accepting, well-formed attestation of {name}"
    if document.get("source") == "ci-run":
        paths = document.get("source_paths")
        ok = (document.get("schema") == SCHEMA and document.get("name") == name and document.get("goos") == host_goos()
              and CI_RUN_URL.fullmatch(str(document.get("run_url", ""))) and isinstance(document.get("job_id"), int)
              and re.fullmatch(r"[0-9a-f]{40}", str(document.get("commit", ""))) and isinstance(paths, list) and paths
              and re.fullmatch(r"[0-9a-f]{64}", str(document.get("source_digest", ""))))
        if not ok:
            raise MissingObservation(bad)
        if sources_digest(paths) != document["source_digest"]:
            raise MissingObservation(f"{rel(source)}: the sources the CI run exercised have changed since ({', '.join(paths)})")
        return document
    verdict = document.get("go_verdict", {})
    artifacts = document.get("rust_artifacts_sha256") or {}
    ok = (document.get("schema") == SCHEMA and document.get("name") == name and document.get("goos") == host_goos()
          and verdict.get("accepted") is True and verdict.get("exit_code") == 0
          and document.get("oracle_commit") == ORACLE_COMMIT
          and re.fullmatch(r"[0-9a-f]{40}", str(document.get("rust_commit", "")))
          and sorted(artifacts) == EXPECTED_ARTIFACTS.get(name)
          and all(re.fullmatch(r"[0-9a-f]{64}", str(v)) for v in artifacts.values()))
    if not ok:
        raise MissingObservation(bad)
    # The attested Rust build is part of this history; an unknown commit (shallow clone, foreign file) fails.
    ancestor = subprocess.run(["git", "merge-base", "--is-ancestor", document["rust_commit"], "HEAD"], cwd=ROOT,
                              capture_output=True)
    if ancestor.returncode != 0:
        raise MissingObservation(f"{rel(source)}: rust_commit {document['rust_commit'][:8]} is not an ancestor of HEAD "
                                 "(foreign attestation, or a shallow clone: fetch the full history)")
    return document


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
        p.add_argument("--append", action="store_true", help="append to OUTPUT instead of replacing it")
    p = sub.add_parser("attest")
    p.add_argument("name")
    p.add_argument("--env", action="append", default=[])
    p.add_argument("--artifact", action="append", default=[])
    p.add_argument("--note", default="")
    p.add_argument("--require-output", default=None, help="regex the verdict output must match")
    p.add_argument("--forbid-output", default=None, help="regex the verdict output must not match (e.g. SKIP)")
    p = sub.add_parser("attest-ci")
    p.add_argument("name")
    p.add_argument("--run-url", required=True)
    p.add_argument("--job-id", required=True, type=int)
    p.add_argument("--commit", required=True)
    p.add_argument("--source", action="append", default=[], help="repository file the CI run exercised (byte-identical now)")
    p.add_argument("--note", default="")
    p = sub.add_parser("verify-attestation")
    p.add_argument("name")
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
        if args.command == "attest":
            assert command and args.artifact, "attest needs --artifact LABEL=PATH and a command after --"
            print(f"attested {rel(write_attestation(args.name, args.artifact, command, args.env, args.note, args.require_output, args.forbid_output))}")
            return 0
        if args.command == "attest-ci":
            target = write_ci_attestation(args.name, run_url=args.run_url, job_id=args.job_id, commit=args.commit,
                                          source_paths=args.source, note=args.note)
            print(f"attested {rel(target)} from CI run {args.run_url} job {args.job_id}")
            return 0
        if args.command == "verify-attestation":
            try:
                document = check_attestation(args.name)
            except MissingObservation:
                gap = accepted_gap(args.name)
                if gap is None or attestation_path(args.name).exists():
                    raise
                print(f"ACCEPTED GAP: {args.name} has no attestation on {host_goos()} (documented, not a pass of the Go check): {gap}")
                return 0
            if document.get("source") == "ci-run":
                print(f"attestation ok (static CI-run evidence): {args.name} ({document['run_url']}, job {document['job_id']}, "
                      f"commit {document['commit'][:8]}, sources unchanged)")
            else:
                print(f"attestation ok (static, historical; Go is NOT re-run): {args.name} (Go {document['go_version']} accepted Rust "
                      f"build {document['rust_commit'][:8]} at oracle {document['oracle_commit'][:8]})")
            return 0
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
            with open(args.output, "a" if args.append else "w") as out:
                out.write("".join(json.dumps(row, sort_keys=True) + "\n" for row in rows))
        elif args.command == "replay-go-text":
            with open(args.output, "a" if args.append else "w") as out:
                out.write("".join(line + "\n" for line in observed["lines"]))
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
