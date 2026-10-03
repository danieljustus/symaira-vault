# Bounded Windows Git initialization recovery

Issue #1099's original run `35610080000` is green at attempt 2 on the same
`e30789d0` source, confirming a transient failure. Its original generic error
cannot distinguish directory creation from Git-process I/O. Existing operation
labels now retain that distinction without printing paths, arguments or output.

Initialization retries only the individual idempotent directory/init/ref/config
operation whose I/O error has native Windows code 5. It waits 100 ms and tries
once more. Persistent denial still fails; non-Windows code 5, a command's exit
status 5, other I/O codes and timeouts are not retried. No global Git timeout,
permission or cleanup rule changes.

Retrying the entire constructor would be unsafe for correctness: `.git` may
already exist after an earlier successful step, causing a subsequent whole-init
call to skip the unfinished `symbolic-ref`/user configuration. The regression
creates a real repository, removes the final email setting, injects one native
Windows error at that operation and verifies the real Git configuration is
finished despite the existing `.git`. Additional controls keep persistent errors
bounded and preserve every non-retryable error class. Injection is explicitly
synthetic; it does not prove which historical operation originally failed.

Native Windows CI must execute these regressions and the real divergent-pull,
merge-preservation and Git-I/O cases before merge. This repair does not promote
GIT-002/003 or close the distinct historical archive exception #1026.
