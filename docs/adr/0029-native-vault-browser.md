# ADR 0029: An owned native terminal vault browser

Status: implementation checkpoint for the requested MacBook handoff; complete
native acceptance pending, 2026-10-04. References #1239 and the remaining
#1242/#1248 platform contracts.

## Decisions and rationale

Use exact-pinned ratatui 0.30.2 with its crossterm 0.29 backend and crossterm
0.29.0 events/native Windows support. Disable optional widgets, macros, image
and alternate backends. Keep rendering/composition in `symvault-cli`; the
domain and encrypted Store remain independent of the terminal frameworks.
Retain every existing locked dependency version when resolving the new graph.
The new maintained libraries avoid a second handwritten cross-platform terminal
and layout engine. Native terminal restoration remains our explicit owner.

Use existing vault resolution, unlock, resource admission, encrypted entry
mutations and Git auto-commit. Only the currently selected decrypted entry is
retained for display, with recursive string erasure when it is replaced or
dropped. Metadata/type cache payload has a sixteen-MiB bound. Render only the
detail rows that fit the visible panel. Strip terminal escape/control sequences
from paths, keys, values, filters and diagnostic text before rendering. Mask
the Go-sensitive name substrings by default; explicit `r` admits display of
those fields. No implicit reveal or generated-password persistence is added.

The terminal guard restores raw mode, alternate screen and cursor on return,
error and unwind. Suspend it while the external editor owns the foreground
terminal, then re-enter and redraw. Add/edit share the existing private bounded
JSON document, secure deletion and checked encrypted writer. No initial entry
is written before the edited document is valid. An empty editor document cancels
the write. Framework display buffers necessarily contain deliberately revealed
text until overwritten; this design does not claim erasure of every allocator
or terminal-history copy. Overwrite the alternate screen before normal exit.

The browser's explicit clipboard caller reuses the existing macOS adapter and
uses pinned arboard 3.6.1 text-only native Windows/X11 ownership elsewhere.
No clipboard content is read during initialization. Operations report opaque
provider failures. One retained clipboard worker owns expiry and serialized replacement, including
while an external editor owns the foreground terminal. Scope exit wakes and
joins that worker; no clipboard payload is queued to it. Quit,
external cancellation and scope exit clear any successful owned copy, including
when a zero duration disables the timer. This last choice deliberately closes
the Go zero-duration quit-cleanup gap; actual Go observation must accompany
acceptance of the decision. Existing MCP provider routing is a separate contract.

arboard's Windows implementation requires clipboard-win 5.4.1 and error-code
3.4.0 under the permissive Boost Software License 1.0. Allow that license only
for these exact packages/versions through `licenses.exceptions`, retaining the
general allowlist. Preserve upstream source license/copyright notices. Changing
either pinned implementation requires another supply-chain review; do not hide
the rejection or allow unspecified future Boost-licensed dependencies.

## Go browser inventory

The executable browser entry point is `cmd/ui.go` -> `ui.Run(NewTUIModel)`.
Its behavior lives in `tui.go`, `tui_keys.go`, `tui_filter.go`, `tui_commands.go`,
`tui_view.go` and `keybindings.go`, plus theme/render/native secure-input and
clipboard boundaries. The adjacent wizard/QR components have other callers;
their existence does not make their initialization flows part of `ui`.

| Mode/boundary | Actual behavior to preserve |
| --- | --- |
| Normal | Two panels, selected entry, masked sensitive values, navigation via arrows/j/k/Home/End, explicit r reveal/redact, help and quit |
| Name filter | Trimmed case-insensitive subsequence matching; Enter/Esc returns to normal while retaining the name query; q is input |
| Tag filter | Case-insensitive tag-prefix matching combined with name query; Esc clears tag query |
| Sort | Name/updated/type ascending and descending; compare timestamp instants rather than serialized offsets; type tie uses name |
| Add | Enter a path, open the external editor with a password placeholder, persist only its valid result |
| Edit/delete | Explicit y/Y confirmation; n/N/Esc cancels; successful mutation reloads current data and metadata |
| Generate | Default 20, accepted 1–512, s toggles symbols; copy the generated password without writing it to an entry |
| Copy | Re-read selected entry; prefer password/secret/token/seed_phrase/api_key/private_key, then first alphabetic field; do not reveal it on screen |
| Clipboard | Configured auto-clear, replacement, provider errors and cleanup before quit; zero-duration choice above is explicit |
| Help | Preserve the twelve ordered public keybindings and exact public table formatting; additionally expose actual add/Home/End behavior in browser help |
| Unlock/terminal | Existing locked/uninitialized handling; actual Unix controlling PTY and native Windows private console; restore terminal modes after quit/editor/error |

## Evidence and limits

Five actual encrypted-store browser regressions pass locally: implicit masking
and explicit reveal/redact, navigation/filter and canceled/confirmed deletion,
copy/expiry/zero-duration scope cleanup, sensitive/escape surfaces, and generated
password non-persistence plus timestamp offset ordering. Strict CLI/platform
Clippy, the locked build, formatting and cargo-deny checks pass. The combined
actual Linux CLI/platform run passes 545 tests with six pre-existing ignores
(492/5 for CLI, 53/1 for platform). These unit/integration tests use an injected
clipboard in the browser tests and do not prove native clipboard delivery.

Separate actual Go/Rust Unix controlling-PTY and authenticated private X11
observations establish native copy, configured expiry, quit clearing, explicit
reveal/redact, navigation, filters, six sort modes, help, resize, generation
without encrypted-entry mutation, and valid/invalid editor handling. During the
paused real valid editor the copy expires for both implementations. Actual Unix
termios observation finds Go leaves the editor in raw mode; Rust restores the
original foreground mode. Retain that deliberate terminal correction: external
editors own ordinary foreground terminal semantics. It avoids requiring each
editor to repair the browser's terminal state itself.

Those observations are development evidence from a dirty candidate, not a
completed clean-candidate acceptance run. The fifteen-case driver currently
stops at the Go empty-editor rendezvous, before add/delete/zero-TTL/cancellation
and locked/uninitialized cases. The short keybinding smoke separately matched
the public output bytes. The zero-TTL quit correction above still requires its
actual Go observation. Source-bound clean/native macOS-arm64 and Windows ConPTY
acceptance and a meaningful independent source mutation remain outstanding.
At that checkpoint the complete TUI CI workflow had not been added. #1239 and CLI/host-provider
rows stay in progress. See the dated MacBook handoff and its retained failed
development receipt; do not treat a passing prefix as the whole driver passing.

## Acceptance harness repair

The terminal decoder does not implement xterm OSC 10/11 color reports. A bounded
real Go editor-only reproduction exposed a late OSC 11 query immediately after
the confirmation screen and intermittent missing key/exit observations. Go's
lazy termenv report reader and Bubble Tea's key reader share that terminal.
Advertising `xterm-256color` was therefore an invalid capability assumption,
not evidence that the editor environment allowlist needed weakening. Advertise
the supported `screen-256color` profile instead. Eight consecutive real,
unmodified pinned-Go empty-editor operations then completed with unchanged
encrypted entries and no clipboard access. The historical failure receipt is
unchanged; its exact original scheduling cannot be reconstructed from a screen.

Recheck a wait predicate after the process-exit observation. Exit can happen
between those reads; observing the exit in the second read must not falsely
reject a valid exit/receipt predicate. A deterministic interleaving test covers
that race. The fixture console wrapper publishes its result atomically and
retains the controlling session until the parent has read the native modes.
This avoids Darwin's revoked slave ioctls after the session leader exits.

Darwin's kernel `PENDIN` bookkeeping bit (`0x20000000`, pending-input
reprocessing) may change independently of application mode restoration. A real
before/after observation differed only in that bit. Exclude only that bit on
Darwin in both independent mode readers; preserve comparison of all other
native fields, including input echo/canonical/raw processing and output modes.
The observer never repairs the terminal to manufacture a passing result.

Keep editor filtering unchanged. Its private sidecar now supplies a console
baseline, and the actual editor reports terminal ownership and absence of the
fixture-only environment canary, passphrase variable and memory-keyring switch.
Record and assert foreground restoration on Windows as well as Unix, rather
than substituting a final-mode assertion for editor-mode evidence.

Receipt schema 2 requires explicit per-case success, the exact ordered fifteen
cases for each binary, native target identity, clean source at start/end,
complete source inventories and a fresh run-owned Rust rebuild matching the
executed binary. Retain failed rows, terminal bytes and ordinary child logs;
replay checks contained regular artifacts, byte counts, hashes, canary absence
and native console restoration. Replay requires an explicitly supplied receipt
digest and full candidate commit. Synthetic validator controls are not native
execution evidence. Production-source controls separately reject a dirty
candidate, a binary from altered source, and a clean committed default-reveal
mutant through the real runtime gate.

The next clean Linux run advanced past empty-editor handling and retained an
actual deletion-status false failure: Rust correctly reported
`Deleted alpha/login`, which the old whole-screen absence predicate mistook for
a remaining entry. Check selected-entry detail plus the changed count instead,
then retain the independent encrypted-store deletion assertion. The committed
`tui_delete_status_fixture.json` is a lossless base64 encoding of that genuine
Linux terminal capture, with its original digest, bytes and candidate/job IDs;
it is not a synthesized terminal session. Replay proves the old predicate's
failure and rejects a structural control with a still-visible selected entry.

Keep source/binary comparison byte-exact. Same-source native MacBook builds
failed that comparison; retained binary diagnosis found exactly sixteen changed
`LC_UUID` bytes and the dependent thirty-two-byte first-page CodeDirectory hash,
with every other byte equal. Explicit `-reproducible` still mismatched. The
initial `-Wl,-no_uuid` attempt is explicitly rejected: native Darwin 27 dyld
aborted the real build scripts before any test executed because `LC_UUID` is
required. Bundled LLD 22 also cannot parse this SDK's `arm64e.x1` TAPI target;
no replacement SDK or dependency is introduced. A bounded native opt-level 1
smoke instead produced exactly identical bytes in two different output
directories, executed both artifacts, retained `LC_UUID`/CodeDirectory and
passed strict native signature verification. The acceptance-only Darwin dev
and test profiles use opt-level 1; full CLI rebuild equality remains required,
not inferred from that smoke. Windows uses the native linker's `/Brepro`
option. Release/debug packaging is unchanged. Retain the actual rebuilt binary
even on mismatch and record effective flags/profile. Never normalize binary
differences away or replace an externally supplied binary silently.

The next genuine Linux prefix reached zero-TTL, then correctly rejected an
invalid fixture assumption. The pinned Go initializer's `omitempty` tag omits
numeric zero; the actual persisted configuration reloaded as thirty seconds,
not a disabled timer. Preserve that original failure and distinguish this
round-trip behavior from the configured-zero scenario. The fixture now writes
an explicit `clipboard.auto_clear_duration: 0` through the existing YAML
parser and independently loads it through production `config.Load`; record
requested, initial round-trip and effective durations. Actual clipboard-free
Go controls observe `2 -> 2` and `0 -> 30 -> 0`. No production config code or
oracle pin is changed. Require retained delivery beyond the two-second enabled
timer before quitting the configured-zero case. Observe cleanup after actual
CLI exit but before releasing the console wrapper/provider session; record
post-wrapper delivery separately so fixture teardown cannot manufacture TUI
cleanup. A structural order test guards that observation boundary.

The next native Linux capture still correctly failed closed. A bounded actual
clipboard-free reader control identified the remaining precondition: initial
`detectLegacyMode` saves configuration on the first `vault.OpenWithPassphrase`,
including the supposedly observational before-snapshot, and omits zero again.
Use genuine explicit nonlegacy metadata in the newly initialized format-two
fixture, exercise the real opener before publishing the seed, and record both
opened-vault and persisted durations for each runtime case. Actual controls
keep zero intact through three consecutive production opens/snapshots (and
likewise retain two). Reject the observed thirty-second mutation through replay.
This is a repair of fixture initialization, not a reinterpretation of the
failing clipboard observation or an OS-dependent exception.

Clipboard-free actual error processes also disprove the old handwritten Go
exit-six expectation. The pinned Go CLI exits one for wrong passphrase and
three for uninitialized vault; the unchanged Rust implementation exits one for
both. Use those captured classes in a single shared table; uninitialized
three-versus-one stays a declared #1241 residual, not normalized parity.

The native Windows failure retained only the real unlock prompt, with no
delivered passphrase/browser output. Send the actual ConPTY Enter carriage
return, rather than the Unix line-feed input; the complete native rerun must
still prove delivery. Pinned pywinpty 3.0.5 `terminate()` already cancels I/O.
Calling `cancel_io()` again raised the observed `Element not found` and erased
the primary failing row. Do not repeat that cancellation; close both sockets,
join the actual reader and require termination. Keep a secondary cleanup
failure on the original failing row, or fail an otherwise successful row. A
structural injected-primary-plus-cleanup test proves both observations and
terminal bytes are preserved. No schema replay may approve a known failure
merely by changing its success flag.
Attempt every owned cleanup even when termination or socket close fails; keep
all such errors in an exception group. A structural two-fault test proves the
other socket close and bounded reader join still execute.

Seventeen artifact/schema controls start from the genuine passing native
receipt and invoke the actual CLI replay. Each deliberately refreshed digest
belongs only to its negative-control input, never a replacement acceptance
anchor. Preserve omitted versus explicit null snapshot fields and JSON types.
Reject existing execution-receipt paths; isolate replay command logs so another
validation cannot overwrite the original runtime or prior replay observations.

The new `rust-tui.yml` runs the full owning crate checks and actual Go/Rust
comparison on fresh Linux, Darwin arm64 (`xcode-27`) and Windows ConPTY runners,
including the source-mutation controls. Native receipts remain pending until
those operations execute and their downloaded artifacts are verified. Personal
MacBook runs are limited to pure/injected tests, compilation, source-only binary
proof and the explicitly clipboard-free real-editor regression. #1239 remains
in progress; exit taxonomy differences remain tracked by #1241 and this browser
does not establish all signal or host-provider contracts.
