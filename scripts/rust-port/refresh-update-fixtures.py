#!/usr/bin/env python3
"""Re-observe update contracts before refreshing source-bound provenance.

No self-update runs: CLI cases use fresh caches/dry-run or an unsupported
Homebrew installation; checker tests use bounded loopback transports.
"""

import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / "crates/symvault-cli/tests/fixtures"
SCRIPT = Path(__file__).relative_to(ROOT).as_posix()
NAMES = ["update-apply-unsupported", "update-apply-stable",
         "update-check-cache", "update-check-http", "update-apply-transaction"]
ORACLE_GO = "go1.26.6"
COREKIT = "github.com/danieljustus/symaira-corekit"
COREKIT_VERSION = "v0.17.1-0.20260904101640-f3d3eb79b9b1"

HTTP_HELPER = r'''
package main
import (
 "context"
 "encoding/json"
 "fmt"
 "net/http"
 "net/http/httptest"
 "os"
 "time"
 "github.com/danieljustus/symaira-vault/internal/update"
)
func main() {
 var cases []map[string]any
 if err := json.NewDecoder(os.Stdin).Decode(&cases); err != nil { panic(err) }
 for _, c := range cases {
  server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
   w.Header().Set("Content-Type", "application/json")
   fmt.Fprint(w, c["response"].(string))
  }))
  checker := update.NewChecker(server.Client())
  checker.LatestReleaseURL = server.URL
  checker.CacheTTL = 0
  ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
  result, err := checker.Check(ctx, c["current"].(string))
  cancel(); server.Close()
  if err != nil { panic(err) }
  c["latest"] = result.LatestVersion
  c["release_url"] = result.ReleaseURL
  c["update_available"] = result.UpdateAvailable
 }
 if err := json.NewEncoder(os.Stdout).Encode(cases); err != nil { panic(err) }
}
'''


def run(args, **kwargs):
    return subprocess.run(args, cwd=ROOT, timeout=180, check=True,
                          stdout=subprocess.PIPE, **kwargs)


def digest(files, commit=None):
    result = hashlib.sha256()
    for name in files:
        data = (run(["git", "show", f"{commit}:{name}"]).stdout if commit
                else (ROOT / name).read_bytes())
        result.update(name.encode() + b"\0" + data + b"\0")
    return result.hexdigest()


def verify_tests(packages, names, env):
    output = run(["go", "test", "-json", "-count=1", "-run",
                  "^(" + "|".join(names) + ")$", *packages], env=env).stdout
    events = [json.loads(line) for line in output.splitlines()]
    passed = {event.get("Test") for event in events if event["Action"] == "pass"}
    if not set(names).issubset(passed):
        raise RuntimeError("required Go observations did not execute: " +
                           str(set(names) - passed))


def source_pin_files(files):
    # The pin identifies unchanged production code, not unrelated dependencies.
    # The full capture digest still enforces BOTH module files in every corpus.
    return [name for name in files if name not in {"go.mod", "go.sum"}]


def check_build_identity(version, corekit):
    if version != ORACLE_GO:
        raise RuntimeError(f"oracle requires {ORACLE_GO}, got {version}")
    if corekit.get("Version") != COREKIT_VERSION or corekit.get("Replace") is not None:
        raise RuntimeError("oracle requires the exact CoreKit module without replacement")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--commit", required=True, help="immutable production-Go source revision")
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    commit = run(["git", "rev-parse", args.commit + "^{commit}"]).stdout.decode().strip()
    fixtures = {name: json.loads((FIXTURES / name / "cases.json").read_text())
                for name in NAMES}
    version = run(["go", "env", "GOVERSION"]).stdout.decode().strip()
    corekit_module = json.loads(run(["go", "list", "-mod=readonly", "-m", "-json", COREKIT]).stdout)
    check_build_identity(version, corekit_module)
    if run(["go", "env", "GOWORK"]).stdout.decode().strip() not in {"", "off"}:
        raise RuntimeError("oracle capture must not use a Go workspace")
    generated_on = run(["go", "env", "GOOS"]).stdout.decode().strip()
    for name, fixture in fixtures.items():
        files = fixture["oracle"]["source_files"]
        for module_file in ["go.mod", "go.sum"]:
            if module_file not in files:
                files.append(module_file)
        pinned = source_pin_files(files)
        if digest(pinned) != digest(pinned, commit):
            raise RuntimeError(f"{name}: working sources differ from {commit}")

    generator_hash = digest([SCRIPT])
    with tempfile.TemporaryDirectory(prefix="update-fixture-") as temporary:
        temp = Path(temporary)
        test_env = dict(os.environ, XDG_CACHE_HOME=str(temp / "test-cache"),
                        XDG_CONFIG_HOME=str(temp / "test-config"))
        binaries = {}
        for name in ["update-apply-unsupported", "update-apply-stable", "update-check-cache"]:
            for case in fixtures[name]["cases"]:
                build_version = case.get("version", "dev")
                if build_version not in binaries:
                    binary = temp / ("symvault-go-" + build_version)
                    run(["go", "build", "-ldflags", "-X main.version=" + build_version,
                         "-o", str(binary), "."])
                    binaries[build_version] = binary
                binary = binaries[build_version]
                with tempfile.TemporaryDirectory(dir=temp, prefix="home-") as home_dir:
                    home = Path(home_dir)
                    env = {k: v for k, v in os.environ.items()
                           if not k.startswith("SYMVAULT_")}
                    env.update(HOME=str(home), USERPROFILE=str(home),
                               XDG_CACHE_HOME=str(home / "cache"),
                               XDG_CONFIG_HOME=str(home / "config"),
                               HOMEBREW_PREFIX=str(binary.parent),
                               HTTP_PROXY="http://127.0.0.1:1", HTTPS_PROXY="http://127.0.0.1:1",
                               ALL_PROXY="http://127.0.0.1:1", NO_PROXY="", LANG="C", LC_ALL="C", TZ="UTC")
                    if "cache" in case:
                        cache_hash = hashlib.sha256(b"danieljustus\0symaira-vault").hexdigest()
                        cache = home / "cache/symaira/updatecheck" / (cache_hash + ".json")
                        cache.parent.mkdir(parents=True)
                        cache.write_text(case["cache"])
                    argv = case.get("argv")
                    if argv is None:
                        argv = ["update", "apply", "--dry-run"] if name == "update-apply-stable" else ["update", "check"]
                        if case["json"]:
                            argv.append("--json")
                        if case.get("quiet"):
                            argv.append("--quiet")
                    process = subprocess.run([str(binary), *argv], env=env, timeout=10,
                                             stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    observed = dict(exit=process.returncode, stdout=process.stdout.decode(),
                                    stderr=process.stderr.decode())
                    for key, value in observed.items():
                        if value != case[key]:
                            raise RuntimeError(f"{case['id']}: {key} changed: {value!r}")
                    case.update(observed)

        with tempfile.TemporaryDirectory(prefix=".update-oracle-", dir=ROOT / "scripts/rust-port") as helper_dir:
            helper = Path(helper_dir) / "main.go"
            helper.write_text(HTTP_HELPER)
            http = fixtures["update-check-http"]
            observed = json.loads(run(["go", "run", str(helper)],
                                      input=json.dumps(http["cases"]).encode(), env=test_env).stdout)
            if observed != http["cases"]:
                raise RuntimeError("real Go checker HTTP observations changed")
            http["cases"] = observed
        # The old hand-captured manifest misspelled the existing test's name.
        # Record and require the actual test instead of accepting zero cases.
        http_tests = fixtures["update-check-http"]["oracle"]["go_tests"]
        http_tests = ["TestCheckerRejectsPrerelease" if name == "TestCheckerRejectsPrereleaseRelease"
                      else name for name in http_tests]
        verify_tests(["./internal/update"], http_tests, test_env)
        fixtures["update-check-http"]["oracle"]["go_tests"] = http_tests
        transaction = fixtures["update-apply-transaction"]
        verify_tests(["github.com/danieljustus/symaira-corekit/updatecheck/updateapply",
                      "github.com/danieljustus/symaira-corekit/updatecheck/extract"],
                     [case["go_test"] for case in transaction["cases"]], test_env)
        corekit = Path(corekit_module["Dir"])
        core_hash = hashlib.sha256()
        for name in transaction["oracle"]["corekit_source_files"]:
            core_hash.update(name.encode() + b"\0" + (corekit / name).read_bytes() + b"\0")
        if core_hash.hexdigest() != transaction["oracle"]["corekit_source_digest"]:
            raise RuntimeError("corekit transaction implementation changed")

    # Do not publish new provenance unless every actual observation above passes.
    outputs = {}
    for name, fixture in fixtures.items():
        oracle = fixture["oracle"]
        oracle.update(commit=commit, go_version=version,
                      source_pin_digest=digest(source_pin_files(oracle["source_files"]), commit),
                      source_digest=digest(oracle["source_files"]),
                      generator_files=[SCRIPT], generator_digest=generator_hash,
                      generated_on=(oracle["generated_on"] if args.check else generated_on),
                      captured=(oracle.get("captured", "2026-10-03")
                                                     if args.check else datetime.date.today().isoformat()))
        outputs[name] = json.dumps(fixture, ensure_ascii=False, indent=2) + "\n"
    for name, data in outputs.items():
        path = FIXTURES / name / "cases.json"
        if args.check:
            if json.loads(path.read_text()) != json.loads(data):
                raise RuntimeError(f"{path}: fixture is stale")
        else:
            path.write_text(data)
        print(f"PASS actual {version}/{generated_on} {name} ({len(fixtures[name]['cases'])} cases)")


if __name__ == "__main__":
    main()
