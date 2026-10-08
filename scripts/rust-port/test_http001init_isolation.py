#!/usr/bin/env python3
"""Prove the HTTP fixture Make entrypoint selects memory before Go package init.

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
GO_TOOLCHAIN = "go1.26.6"


def clean_env(tmpdir, log_path, inherited=None):
    env = dict(os.environ if inherited is None else inherited)
    for key in (
        "CI",
        "GITHUB_ACTIONS",
        "HEADLESS",
        "SYMVAULT_TEST_KEYRING",
        "SYMVAULT_PASSPHRASE",
        "SYMVAULT_ALLOW_ENV_PASSPHRASE",
        "MAKEFILES",
        "MAKEFLAGS",
        "MAKEOVERRIDES",
        "MFLAGS",
    ):
        env.pop(key, None)
    env.update(
        GOWORK="off",
        GOFLAGS="",
        GOTOOLCHAIN=GO_TOOLCHAIN,
        SYMVAULT_KEYRING_HELPER_LOG=str(log_path),
        SYMVAULT_KEYRING_BACKEND_LOG=str(tmpdir / "backend.log"),
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
    scratch_path = None
    with tempfile.TemporaryDirectory(prefix="http001-keyring-isolation-", dir=target) as scratch:
        tmpdir = Path(scratch)
        scratch_path = tmpdir
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
        for key in (
            "CI",
            "GITHUB_ACTIONS",
            "HEADLESS",
            "SYMVAULT_TEST_KEYRING",
            "SYMVAULT_PASSPHRASE",
            "SYMVAULT_ALLOW_ENV_PASSPHRASE",
            "MAKEFILES",
            "MAKEFLAGS",
            "MAKEOVERRIDES",
            "MFLAGS",
        ):
            compile_env.pop(key, None)
        compile_tmp = tmpdir / "compile-tmp"
        compile_tmp.mkdir(mode=0o700)
        compile_env.update(
            GOWORK="off",
            GOFLAGS="",
            GOTOOLCHAIN=GO_TOOLCHAIN,
            TMPDIR=str(compile_tmp),
        )
        toolchain_info = subprocess.check_output(
            ["go", "env", "GOVERSION", "GOMODCACHE", "GOROOT"],
            cwd=ROOT,
            env=compile_env,
            text=True,
            timeout=60,
        ).splitlines()
        if len(toolchain_info) != 3:
            raise AssertionError(f"unexpected Go toolchain metadata: {toolchain_info!r}")
        go_version, module_cache, tool_root = toolchain_info
        if go_version != GO_TOOLCHAIN:
            raise AssertionError(f"HTTP-init probe requires pinned {GO_TOOLCHAIN}, got {go_version!r}")
        module_dir = subprocess.check_output(
            ["go", "list", "-f", "{{.Dir}}", KEYRING_IMPORT],
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
        if len(control_pids) != 4:
            raise AssertionError(
                "negative control did not observe the four expected init-time OS-keyring calls "
                f"(observed {len(control_pids)}, exit {control_rc})\n{control_output}"
            )
        if control_rc != 0:
            raise AssertionError(f"raw negative-control --check failed unexpectedly (exit {control_rc}): {control_output}")
        assert_helpers_exited(control_pids)

        go_binary = Path(tool_root) / "bin" / "go"
        if not go_binary.is_file():
            raise AssertionError(f"selected Go toolchain executable is missing: {go_binary}")
        backend_log = tmpdir / "backend.log"
        wrapper = tmpdir / "go-wrapper"
        wrapper.write_text(
            "#!/bin/sh\n"
            "set -eu\n"
            "printf '%s\\n' \"${SYMVAULT_TEST_KEYRING-unset}\" >> \"$SYMVAULT_KEYRING_BACKEND_LOG\"\n"
            "if [ \"${1-}\" != run ]; then echo 'unexpected Go subcommand' >&2; exit 64; fi\n"
            "shift\n"
            "exec env "
            f"GOROOT={shlex.quote(tool_root)} GOTOOLCHAIN=local "
            f"{shlex.quote(str(go_binary))} run -modfile={shlex.quote(str(modfile))} \"$@\"\n"
        )
        wrapper.chmod(0o700)

        log_path.unlink(missing_ok=True)
        backend_log.unlink(missing_ok=True)
        hostile_parent = os.environ.copy()
        hostile_parent.update(
            MAKEFLAGS="SYMVAULT_TEST_KEYRING=memory",
            MAKEOVERRIDES="SYMVAULT_TEST_KEYRING=memory",
            SYMVAULT_TEST_KEYRING="memory",
        )
        make_env = clean_env(tmpdir, log_path, hostile_parent)
        leaked = [
            key
            for key in (
                "MAKEFILES",
                "MAKEFLAGS",
                "MAKEOVERRIDES",
                "MFLAGS",
                "SYMVAULT_TEST_KEYRING",
                "SYMVAULT_PASSPHRASE",
                "SYMVAULT_ALLOW_ENV_PASSPHRASE",
            )
            if key in make_env
        ]
        if leaked:
            raise AssertionError(f"positive control leaked inherited override/backend variables: {leaked}")
        make_env["GOMODCACHE"] = module_cache
        make_env["GOCACHE"] = str(go_cache)
        isolated_rc, isolated_output = run_bounded(
            ["make", "--no-print-directory", "mcp-http-init-fixtures-generate", f"GO={wrapper}"],
            make_env,
            timeout=180,
        )
        if isolated_rc != 0:
            raise AssertionError(f"memory-isolated Make generator failed:\n{isolated_output}")
        safe_backends = backend_log.read_text().splitlines() if backend_log.exists() else []
        if safe_backends != ["memory"]:
            raise AssertionError(f"Make generator did not pass memory before Go startup: {safe_backends!r}")
        if helper_pids(log_path):
            raise AssertionError("memory-isolated Make generator invoked the instrumented OS credential helper")
        if FIXTURE.read_bytes() != fixture_before:
            raise AssertionError("memory-isolated Make generation changed the committed HTTP initialize fixture")

        unsafe_makefile = tmpdir / "missing-export.mk"
        unsafe_makefile.write_text(
            "PORT_MCP_HTTP_INIT_FIXTURE := testdata/port/mcp/http-initialize.json\n"
            ".PHONY: unsafe\n"
            "unsafe:\n"
            "\t@printf '%s\\n' \"$${SYMVAULT_TEST_KEYRING-unset}\" >> \"$$SYMVAULT_KEYRING_BACKEND_LOG\"\n"
            f"\t{shlex.quote(str(binary))} --check --output $(PORT_MCP_HTTP_INIT_FIXTURE); rc=$$?; printf 'generator_rc=%s\\n' \"$$rc\" >> \"$$SYMVAULT_KEYRING_BACKEND_LOG\"; exit $$rc\n"
            "\t@test ! -s \"$$SYMVAULT_KEYRING_HELPER_LOG\"\n"
        )
        log_path.unlink(missing_ok=True)
        backend_log.unlink(missing_ok=True)
        unsafe_rc, unsafe_output = run_bounded(
            ["make", "--no-print-directory", "-f", str(unsafe_makefile), "unsafe"],
            make_env,
            timeout=60,
        )
        unsafe_pids = helper_pids(log_path)
        if unsafe_rc == 0 or len(unsafe_pids) != 4:
            raise AssertionError(
                "missing-export Makefile did not fail with four helper calls despite hostile inherited "
                f"MAKEFLAGS/MAKEOVERRIDES (exit {unsafe_rc}, helper calls {len(unsafe_pids)})\n{unsafe_output}"
            )
        unsafe_backends = backend_log.read_text().splitlines() if backend_log.exists() else []
        if unsafe_backends != ["unset", "generator_rc=0"]:
            raise AssertionError(f"missing-export control backend/command result was unexpected: {unsafe_backends!r}")
        assert_helpers_exited(unsafe_pids)
        if FIXTURE.read_bytes() != fixture_before:
            raise AssertionError("HTTP initialize fixture bytes changed during isolation controls")

    if scratch_path is None or scratch_path.exists():
        raise AssertionError(f"probe scratch directory was not torn down: {scratch_path}")
    print(
        "PASS: Go 1.26.6 executable negative control reached the instrumented helper "
        f"({len(control_pids)} calls, exit {control_rc}); safe Make generate selected memory before Go startup "
        "with zero helper calls; missing-export Make control failed with inherited overrides scrubbed "
        f"({len(unsafe_pids)} fake-helper calls); helper processes exited; fixture bytes and temp cleanup verified."
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (AssertionError, OSError, subprocess.SubprocessError) as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        raise SystemExit(1)
