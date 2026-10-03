#!/usr/bin/env python3
"""Kill the real source-drift test at its ready point; prove checkout immutability."""

import os
from pathlib import Path
import signal
import subprocess
import tempfile
import time


def kill_owned(process):
    if os.name == "nt":
        subprocess.run(["taskkill", "/PID", str(process.pid), "/T", "/F"],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15, check=False)
    else:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    process.wait(timeout=15)


root = Path(__file__).resolve().parents[2]
source = root / "scripts/rust-port/cmd/store004gen/process_group_unix.go"
before, mode = source.read_bytes(), source.stat().st_mode
suffix = ".exe" if os.name == "nt" else ""
env = dict(os.environ, GOTOOLCHAIN="go1.26.6")
goroot = subprocess.check_output(["go", "env", "GOROOT"], env=env, text=True).strip()
go = str(Path(goroot) / "bin" / ("go" + suffix))
env["PATH"] = str(Path(goroot) / "bin") + os.pathsep + env["PATH"]
env["GOMODCACHE"], env["GOCACHE"] = subprocess.check_output(
    [go, "env", "GOMODCACHE", "GOCACHE"], env=env, text=True).splitlines()
with tempfile.TemporaryDirectory(prefix="store004-cancel-", dir=os.environ.get("TMPDIR")) as directory:
    sandbox = Path(directory)
    binary = sandbox / ("store004.test" + suffix)
    with (sandbox / "build.log").open("w") as output:
        compiler = subprocess.Popen([go, "test", "-c", "-o", str(binary), "./scripts/rust-port/cmd/store004gen"],
                                    cwd=root, env=env, stdout=output, stderr=subprocess.STDOUT,
                                    start_new_session=os.name != "nt")
        try:
            result = compiler.wait(timeout=120)
        except BaseException:
            kill_owned(compiler)
            raise
        if result != 0:
            raise RuntimeError("test compilation failed: " + (sandbox / "build.log").read_text())
    for key in ["HOME", "USERPROFILE", "TMPDIR", "TMP", "TEMP", "XDG_CONFIG_HOME", "XDG_DATA_HOME"]:
        env[key] = str(sandbox)
    env["SYMVAULT_TEST_STORE004_PAUSE_AFTER_DRIFT"] = "1"
    log = sandbox / "test.log"
    with log.open("w") as output:
        process = subprocess.Popen([str(binary), "-test.run=^TestCheckFixtureRejectsProcessGroupSourceDrift$",
                                    "-test.v", "-test.timeout=0"], cwd=root, env=env,
                                   stdout=output, stderr=subprocess.STDOUT, start_new_session=os.name != "nt")
        ready = False
        try:
            # Two real oracle calls each have a 2-minute bound. Do not let
            # Go's test alarm kill their owner before process-group cleanup.
            deadline = time.monotonic() + 600
            while "STORE004_ISOLATED_DRIFT_READY" not in log.read_text():
                assert source.read_bytes() == before and source.stat().st_mode == mode, "tracked source changed"
                if process.poll() is not None:
                    raise RuntimeError("test exited before isolated drift readiness: " + log.read_text())
                if time.monotonic() >= deadline:
                    raise TimeoutError("source-drift test did not reach its ready point")
                time.sleep(0.02)
            ready = True
        finally:
            if not ready and os.name != "nt" and process.poll() is None:
                # Cancel the Go owner context first: oracle children have
                # separate groups, and runOracle must kill and await them.
                process.send_signal(signal.SIGINT)
                try:
                    process.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    kill_owned(process)
                    raise
            else:
                # At readiness no oracle is running. On Windows killing the
                # owner also closes its kill-on-close oracle Job Objects.
                kill_owned(process)
    assert process.returncode != 0, "cancellation did not terminate the test"
    assert source.read_bytes() == before and source.stat().st_mode == mode, "cancellation changed tracked source"
print("PASS: real source-drift test killed after isolated mutation; tracked bytes/mode unchanged")
