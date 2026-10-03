"""Run the sync I/O-error regression with a broken stderr pipe.

Usage: python3 scripts/rust-port/check_git_diagnostic_stderr.py <sync-test-binary>
Build that executable with cargo test -p symvault-sync --lib --no-run --locked.
No operator state or credentials are used.
"""
import os
import subprocess
import sys

reader, writer = os.pipe()
os.close(reader)
try:
    result = subprocess.run(
        [sys.argv[1], "--exact", "git::tests::output_diagnostics_preserve_missing_file_error", "--nocapture"],
        stdout=subprocess.PIPE,
        stderr=writer,
        text=True,
        timeout=30,
        check=False,
    )
finally:
    os.close(writer)
print(result.stdout)
print(f"exit_code={result.returncode}")
if result.returncode != 0 or "1 passed" not in result.stdout:
    raise SystemExit("Broken-stderr regression failed or did not execute")
