"""Shared compile-step budget and robust worktree cleanup for oracle scripts.

A cold ``windows-latest`` runner needs well over two minutes to compile the Go
oracle (``go build -trimpath -buildvcs=false -o ... .``).  Compile steps
therefore get their own generous budget, separate from every per-case product
or process timeout, which stay untouched so a hanging product is still caught.
"""
import os
import sys
import time

BUILD_TIMEOUT_ENV = 'SYMVAULT_ORACLE_BUILD_TIMEOUT'
DEFAULT_BUILD_TIMEOUT = 900


def oracle_build_timeout(environ=None):
    """Seconds allowed for one compile step; override with SYMVAULT_ORACLE_BUILD_TIMEOUT.

    A malformed or non-positive override is an error, never a silent fallback:
    a mistyped value must not quietly restore the budget that already failed.
    """
    raw = (os.environ if environ is None else environ).get(BUILD_TIMEOUT_ENV)
    if raw is None or raw == '':
        return DEFAULT_BUILD_TIMEOUT
    try:
        value = float(raw)
    except ValueError:
        raise ValueError(f'{BUILD_TIMEOUT_ENV} must be a positive number of seconds, got {raw!r}') from None
    if not value > 0 or value == float('inf'):
        raise ValueError(f'{BUILD_TIMEOUT_ENV} must be a positive number of seconds, got {raw!r}')
    return int(value) if value == int(value) else value


def remove_worktree(action, description, attempts=5, delay=2.0, sleep=time.sleep):
    """Run ``action`` (a zero-argument worktree removal), retrying transient failures.

    On Windows a just-killed ``go.exe`` can still hold the oracle directory, so
    ``git worktree remove`` fails with "Permission denied" for a short while.
    Retries back off linearly.  If removal still fails while another exception
    is propagating, that original failure must stay the reported one: the
    cleanup failure is written to stderr and swallowed.  With no exception in
    flight, the last cleanup error is raised, so a leaked worktree cannot pass.
    """
    primary = sys.exception()
    last = None
    for attempt in range(1, attempts + 1):
        try:
            action()
            return True
        except Exception as error:  # noqa: BLE001 - any removal failure is retried
            last = error
            if attempt < attempts:
                sleep(delay * attempt)
    print(f'WARNING: could not remove {description} after {attempts} attempts: '
          f'{type(last).__name__}: {str(last)[-1000:]}', file=sys.stderr)
    if primary is None:
        assert last is not None
        raise last
    return False
