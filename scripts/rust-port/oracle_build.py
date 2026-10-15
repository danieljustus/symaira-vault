"""Compile immutable Go oracles with the existing owned-process harness."""
import hashlib
import os
from pathlib import Path
import subprocess
import sys
import time

from mcp_oracle import pinned_go

ROOT = Path(__file__).resolve().parents[2]


def build_go(source, output, package, observations):
    source, output = Path(source).resolve(), Path(output).resolve()
    runner = Path(os.environ.get('SYMVAULT_ORACLE_BUILD_RUNNER',
                  ROOT / 'target' / ('oraclebuild.exe' if os.name == 'nt' else 'oraclebuild'))).resolve()
    if not runner.is_file():
        raise RuntimeError('Build scripts/rust-port/cmd/oraclebuild before oracle capture')
    go, env, compiler = pinned_go(os.environ.copy(), source)
    row: dict[str, object] = dict(package=package, compiler=compiler,
               runner_sha256=hashlib.sha256(runner.read_bytes()).hexdigest(),
               budget_seconds=600, passed=False)
    observations.append(row)
    started = time.monotonic()
    try:
        # The helper owns descendants via Unix groups / Windows Job Objects.
        # Its 600s compile budget matches mcp_fixture_contract.run_step; the
        # outer 620s guard reserves time for owned-tree and output cleanup.
        result = subprocess.run([str(runner), str(go), str(source), str(output), package],
                                cwd=ROOT, env=env, capture_output=True, timeout=620)
        row.update(exit_code=result.returncode, timed_out=result.returncode == 124,
                   stdout_sha256=hashlib.sha256(result.stdout).hexdigest(),
                   stderr_sha256=hashlib.sha256(result.stderr).hexdigest())
        if result.returncode:
            raise RuntimeError('owned oracle build failed: ' + result.stderr.decode(errors='replace')[-2000:])
        row.update(passed=True, binary_sha256=hashlib.sha256(output.read_bytes()).hexdigest())
    except subprocess.TimeoutExpired:
        row.update(timed_out=True, wrapper_timeout=True)
        raise
    finally:
        row['elapsed_seconds'] = time.monotonic() - started


def remove_oracle_worktree(tree, report, checked):
    """Keep the original failure even if Git cleanup also fails."""
    primary = sys.exception()
    if primary is not None:
        report['passed'] = False
        report['primary_failure'] = {'type': type(primary).__name__, 'message': str(primary)[-2000:]}
    try:
        checked(['git', 'worktree', 'remove', '--force', tree])
    except Exception as cleanup:
        report['passed'] = False
        report['cleanup_failure'] = {'type': type(cleanup).__name__, 'message': str(cleanup)[-2000:]}
        if primary is None:
            raise
