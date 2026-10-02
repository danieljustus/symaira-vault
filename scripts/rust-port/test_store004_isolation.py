#!/usr/bin/env python3
"""Kill the real source-drift test at its ready point; prove checkout immutability."""

import os
from pathlib import Path
import signal
import subprocess
import tempfile
import time


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
        subprocess.run([go, "test", "-c", "-o", str(binary), "./scripts/rust-port/cmd/store004gen"],
                       cwd=root, env=env, stdout=output, stderr=subprocess.STDOUT, check=True, timeout=120)
    for key in ["HOME", "USERPROFILE", "TMPDIR", "TMP", "TEMP", "XDG_CONFIG_HOME", "XDG_DATA_HOME"]:
        env[key] = str(sandbox)
    env["SYMVAULT_TEST_STORE004_PAUSE_AFTER_DRIFT"] = "1"
    log = sandbox / "test.log"
    with log.open("w") as output:
        process = subprocess.Popen([str(binary), "-test.run=^TestCheckFixtureRejectsProcessGroupSourceDrift$",
                                    "-test.v", "-test.timeout=90s"], cwd=root, env=env,
                                   stdout=output, stderr=subprocess.STDOUT, start_new_session=os.name != "nt")
        try:
            deadline = time.monotonic() + 90
            while "STORE004_ISOLATED_DRIFT_READY" not in log.read_text():
                assert source.read_bytes() == before and source.stat().st_mode == mode, "tracked source changed"
                if process.poll() is not None:
                    raise RuntimeError("test exited before isolated drift readiness: " + log.read_text())
                if time.monotonic() >= deadline:
                    raise TimeoutError("source-drift test did not reach its ready point")
                time.sleep(0.02)
        finally:
            if os.name == "nt":
                process.kill()
            else:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            process.wait(timeout=10)
    assert process.returncode != 0, "cancellation did not terminate the test"
    assert source.read_bytes() == before and source.stat().st_mode == mode, "cancellation changed tracked source"
print("PASS: real source-drift test killed after isolated mutation; tracked bytes/mode unchanged")
