# ADR 0010: Intake polling, quarantine and native evidence

## Status

Accepted maintainer-delegated decision, 2026-10-04. Implementation is in
progress; issue #1238 and the complete IO-003 contract remain open.

## Decision and rationale

Keep the production Go polling model. Do not install an OS service as a side
effect of running `intake watch`. The caller selects a directory, interval and
debounce. Remember each accepted source snapshot during the process lifetime;
after restart, encrypted quarantine attachment hashes prevent duplicate writes.
There is no persistent watcher ledger or automatic source promotion in Go.

Own private staging copies until the scan or watcher exits. Never delete or move
a watched source. Store exact source bytes as an encrypted attachment, with its
name, length and SHA-256; write only under `quarantine/<import-id>/`. Preserve
the first bounded non-empty suggestion for each field. Dedupe and existing-entry
checks share one vault ReadSession per batch, so resource errors abort rather
than being skipped as ordinary unreadable entries.

Match Go's distinct one-shot modes: text `--once` writes a review batch when
there are accepted files, while `--once --json` only reports staging and does
not unlock or write a vault. Its random staging paths are no longer present
after exit. Preserve this existing scripting behavior during migration; change
it only through a separately versioned interface. Notifications are best effort
and use only a generated batch ID and entry count.

`watch disable` operates on the same fixed HOME-derived LaunchAgent path as Go.
An absent plist succeeds on every OS. An existing plist is removed only on
macOS after a best-effort unload; Linux/Windows return the existing explicit
unsupported result. No system-wide service discovery or deletion is added.

Use pinned ctrlc 3.5.2 with its termination adapter for Unix SIGINT/SIGTERM and
Windows console events. A process-owned callback only sends a stop notification;
the CLI owns its polling loop and spool cleanup. Reuse a lazy unlock runtime
across batches. Empty scans never open a vault or credential provider. This
avoids implementing a separate unsafe Windows console handler in the CLI.
Whole-CLI prompt/signal semantics remain governed by #1242; an idle watcher
termination test is not proof that arbitrary interactive work can be killed.

## Actual evidence and remaining work

The live driver rebuilds immutable Go source
`55da4ca13ead39d4000cf6f866ac8671ca86d8f2` in a detached worktree and runs both
CLIs in disposable HOME/XDG roots with a memory keyring. Its receipt binds the
full Go source inventory, both binaries, the driver, the candidate source
inventory and native OS. Acceptance rejects a dirty candidate; development
receipts must explicitly identify their dirty state.

Seventeen actual Linux Go/Rust observations pass: empty scans, defaulted
durations, invalid arguments/directories, disable/no-op, JSON staging with
private-copy cleanup, encrypted batch creation, repeat hash deduplication and
idle SIGINT/SIGTERM. Real Go reads the Rust-written attachment and credential;
the attachment bytes and source bytes match exactly. The comparison exposed
and repaired Go's argument-error exit code and the shared Rust unlock helper's
missing `SYMVAULT_NO_ENV_WARNING` handling. Strict Clippy and existing watcher,
scan, spool and run-loop tests also pass locally.

Random batch IDs and staging paths are opaque. Compare their structure and
effects, and normalize only those generated identities in output comparisons.
OS/parser diagnostic wording stays under CLI-005; require actual denial, exit
code, stderr placement and absence of vault writes here.

The new watch paths are reachable, but the ordinary file-intake CLI and its five
parent flags still need completion. IO-003 stays in_progress until that surface,
the additional batch/error cases and actual macOS/Linux/Windows jobs pass.
Polling is the oracle's native behavior; an OS event-watcher implementation is
not an additional acceptance requirement. Broader platform UI and release gates
are not promoted by these injected and disposable-root checks.
