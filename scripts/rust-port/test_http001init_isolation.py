#!/usr/bin/env python3
"""Prove the HTTP fixture executable selects memory before Go package init.

The unsafe control uses a disposable go-keyring module copy selected by a
temporary modfile; its absolute /usr/bin/security path is redirected to a
logging stub. It never invokes the operator's credential helper or writes to
an OS keychain.
"""
import json
import os
from pathlib import Path
import shlex
import shutil
import signal
import subprocess
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[2]
KEYRING_IMPORT = "github.com/zalando/go-keyring"
FIXTURE = ROOT / "testdata/port/mcp/http-initialize.json"


def clean_env(tmpdir, log_path):
    env = os.environ.copy()
    for key in ("CI", "GITHUB_ACTIONS", "HEADLESS", "SYMVAULT_TEST_KEYRING"):
        env.pop(key, None)
    env.update(
        GOWORK="off",
        GOFLAGS="",
        GOTOOLCHAIN=env.get("GOTOOLCHAIN", "go1.26.6"),
        SYMVAULT_KEYRING_HELPER_LOG=str(log_path),
    )
    for key, leaf in (
        ("HOME", "home"),
        ("USERPROFILE", "home"),
        ("XDG_CONFIG_HOME", "config"),
        ("XDG_DATA_HOME", "data"),
        ("XDG_CACHE_HOME", "cache"),
        ("TMPDIR", "tmp"),
        ("TMP", "tmp"),
        ("TEMP", "tmp"),
    ):
        path = tmpdir / leaf
        path.mkdir(mode=0o700, parents=True, exist_ok=True)
        env[key] = str(path)
    return env


def run_bounded(argv, env, timeout=60):
    process = subprocess.Popen(
        argv,
        cwd=ROOT,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        start_new_session=True,
    )
    timed_out = False
    try:
        output, _ = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            output, _ = process.communicate(timeout=3)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            output, _ = process.communicate()
    group_alive = False
    try:
        os.killpg(process.pid, 0)
        group_alive = True
    except ProcessLookupError:
        pass
    if timed_out:
        raise AssertionError(f"timed out: {argv!r}\n{output.decode(errors='replace')}")
    if group_alive:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        raise AssertionError(f"child process group survived command exit: {process.pid}")
    return process.returncode, output.decode(errors="replace")


def helper_pids(log_path):
    if not log_path.exists():
        return []
    pids = []
    for line in log_path.read_text().splitlines():
        fields = line.split("\t", 1)
        if not fields or not fields[0].isdigit():
            raise AssertionError(f"malformed helper instrumentation record: {line!r}")
        pids.append(int(fields[0]))
    return pids


def assert_helpers_exited(pids):
    for pid in pids:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            continue
        raise AssertionError(f"instrumented credential-helper process {pid} survived")


def main():
    if sys.platform != "darwin":
        print("SKIP: absolute-keychain-helper instrumentation is macOS-specific")
        return 0

    target = ROOT / "target"
    target.mkdir(exist_ok=True)
    fixture_before = FIXTURE.read_bytes()
    with tempfile.TemporaryDirectory(prefix="http001-keyring-isolation-", dir=target) as scratch:
        tmpdir = Path(scratch)
        helper = tmpdir / "security-probe"
        helper.write_text(
            "#!/bin/sh\n"
            "set -eu\n"
            "printf '%s\\t%s\\n' \"$$\" \"$*\" >> \"$SYMVAULT_KEYRING_HELPER_LOG\"\n"
            "case \"${1-}\" in\n"
            "  -i) while IFS= read -r line; do :; done; exit 0 ;;\n"
            "  find-generic-password|delete-generic-password)\n"
            "    printf '%s\\n' 'security: item could not be found in the keychain.'\n"
            "    exit 44 ;;\n"
            "esac\n"
            "exit 0\n"
        )
        helper.chmod(0o700)
        compile_env = os.environ.copy()
        for key in ("CI", "GITHUB_ACTIONS", "HEADLESS", "SYMVAULT_TEST_KEYRING", "SYMVAULT_PASSPHRASE", "SYMVAULT_ALLOW_ENV_PASSPHRASE"):
            compile_env.pop(key, None)
        compile_tmp = tmpdir / "compile-tmp"
        compile_tmp.mkdir(mode=0o700)
        compile_env.update(
            GOWORK="off",
            GOFLAGS="",
            GOTOOLCHAIN=compile_env.get("GOTOOLCHAIN", "go1.26.6"),
            TMPDIR=str(compile_tmp),
        )
        module_dir = subprocess.check_output(
            ["go", "list", "-f", "{{.Dir}}", KEYRING_IMPORT],
            cwd=ROOT,
            env=compile_env,
            text=True,
            timeout=60,
        ).strip()
        module_cache = subprocess.check_output(
            ["go", "env", "GOMODCACHE"],
            cwd=ROOT,
            env=compile_env,
            text=True,
            timeout=60,
        ).strip()
        go_cache = tmpdir / "go-cache"
        go_cache.mkdir(mode=0o700)
        compile_env.update(GOMODCACHE=module_cache, GOCACHE=str(go_cache))
        keyring_source = Path(module_dir) / "keyring_darwin.go"
        original = keyring_source.read_text()
        old_path = '"/usr/bin/security"'
        if original.count(old_path) != 1:
            raise AssertionError("go-keyring macOS helper path was not a unique instrumentation target")
        instrumented_module = tmpdir / "go-keyring"
        shutil.copytree(module_dir, instrumented_module)
        replacement = instrumented_module / "keyring_darwin.go"
        replacement.chmod(0o600)
        replacement.write_text(original.replace(old_path, json.dumps(str(helper)), 1))
        modfile = tmpdir / "instrumented.mod"
        modfile.write_text(
            (ROOT / "go.mod").read_text()
            + f"\nreplace {KEYRING_IMPORT} => {instrumented_module}\n"
        )
        shutil.copy2(ROOT / "go.sum", tmpdir / "instrumented.sum")
        binary = tmpdir / "http001initgen"
        build_rc, build_output = run_bounded(
            ["go", "build", f"-modfile={modfile}", "-o", str(binary), "./scripts/rust-port/cmd/http001initgen"],
            compile_env,
            timeout=180,
        )
        if build_rc != 0:
            raise AssertionError(f"instrumented generator build failed:\n{build_output}")
        binary_bytes = binary.read_bytes()
        if str(helper).encode() not in binary_bytes or b"/usr/bin/security" in binary_bytes:
            raise AssertionError("instrumentation did not replace the executable's absolute keychain helper")

        log_path = tmpdir / "helper.log"
        control_env = clean_env(tmpdir, log_path)
        control_env["GOMODCACHE"] = module_cache
        control_env["GOCACHE"] = str(go_cache)
        control_rc, control_output = run_bounded([str(binary), "--check"], control_env)
        control_pids = helper_pids(log_path)
        if not control_pids:
            raise AssertionError(
                "negative control did not detect the init-time OS-keyring path "
                f"(exit {control_rc})\n{control_output}"
            )
        assert_helpers_exited(control_pids)

        tool_root = subprocess.check_output(
            ["go", "env", "GOROOT"],
            cwd=ROOT,
            env=compile_env,
            text=True,
            timeout=60,
        ).strip()
        go_binary = Path(tool_root) / "bin" / "go"
        if not go_binary.is_file():
            raise AssertionError(f"selected Go toolchain executable is missing: {go_binary}")
        wrapper = tmpdir / "go-wrapper"
        wrapper.write_text(
            "#!/bin/sh\n"
            "set -eu\n"
            "if [ \"${1-}\" != run ]; then echo 'unexpected Go subcommand' >&2; exit 64; fi\n"
            "shift\n"
            "exec env "
            f"GOROOT={shlex.quote(tool_root)} GOTOOLCHAIN=local "
            f"{shlex.quote(str(go_binary))} run -modfile={shlex.quote(str(modfile))} \"$@\"\n"
        )
        wrapper.chmod(0o700)

        log_path.unlink(missing_ok=True)
        make_env = clean_env(tmpdir, log_path)
        make_env["GOMODCACHE"] = module_cache
        make_env["GOCACHE"] = str(go_cache)
        isolated_rc, isolated_output = run_bounded(
            ["make", "--no-print-directory", "mcp-http-init-fixtures-run", f"GO={wrapper}"],
            make_env,
            timeout=180,
        )
        if isolated_rc != 0:
            raise AssertionError(f"standalone Make target failed without inherited isolation flags:\n{isolated_output}")
        if helper_pids(log_path):
            raise AssertionError("memory-isolated Make target invoked the instrumented OS credential helper")
        if FIXTURE.read_bytes() != fixture_before:
            raise AssertionError("--check modified the committed HTTP initialize fixture")

    print(
        "PASS: executable negative control detected "
        f"{len(control_pids)} fake credential-helper call(s) (exit {control_rc}); "
        "standalone Make check exited 0 without inherited isolation flags or helper calls; "
        "helper processes exited cleanly; fixture bytes unchanged."
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (AssertionError, OSError, subprocess.SubprocessError) as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        raise SystemExit(1)
