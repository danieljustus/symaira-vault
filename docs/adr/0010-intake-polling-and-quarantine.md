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

Connect ordinary `intake <file...>` to the same staging and quarantine path.
Expose all five parent flags: dry-run, batch-limit, max-files, move-to-trash and
ocr-text. Preserve Go's nonpositive-limit defaults, content-based type detection,
empty-file error and metadata-only suggestions. Dry-run never opens a vault.
JSON is compared structurally; distinct JSON field suggestions may have a
different array order because Go iterates object keys in unspecified order.
This does not decide precedence for conflicting aliases; that belongs to the
complete importer contract in #1247.

Read each newly written encrypted attachment back before considering its source
eligible for the optional macOS Trash action. Verify the exact attachment and
its metadata using the same bounded ReadSession. This makes the advertised
write-before-cleanup rule concrete. Watch mode never moves sources. Finder
automation remains best effort, as in Go; disposable CLI tests do not establish
interactive Finder permission or broader platform UI acceptance.

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

Thirty-four actual Linux Go/Rust observations pass: empty scans, defaulted and
invalid durations, invalid arguments/directories, disable/no-op, JSON staging
with private-copy cleanup, encrypted batch creation, repeat hash deduplication,
idle SIGINT/SIGTERM, ordinary file intake, dry-run, OCR text, content sniffing,
empty files, batch limits and valued/repeated Boolean flags. Real Go reads the
Rust-written attachment and credential; attachment and source bytes match
exactly. The comparison exposed and repaired argument-error exit codes, empty
file handling, parser confidence and the shared Rust unlock helper's missing
`SYMVAULT_NO_ENV_WARNING` handling. The owning CLI/sync suites pass locally
(620 tests, five explicitly ignored); their optional differential tests are not
substitutes for the separately executed actual Go/Rust driver.

Random batch IDs and staging paths are opaque. Compare their structure and
effects, and normalize only those generated identities in output comparisons.
OS/parser diagnostic wording stays under CLI-005; require actual denial, exit
code, stderr placement and absence of vault writes here.

The actual CLI gap report has no intake path, flag or alias gaps. The native
workflow requires clean candidate receipts, real Go observations and named
cases on macOS/Linux/Windows, including a real Windows console-control event.
IO-003 stays in_progress until those actual native jobs pass.
Polling is the oracle's native behavior; an OS event-watcher implementation is
not an additional acceptance requirement. Broader platform UI and release gates
are not promoted by these injected and disposable-root checks.
