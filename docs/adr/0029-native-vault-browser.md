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
The new complete TUI CI workflow has not been added. #1239 and CLI/host-provider
rows stay in progress. See the dated MacBook handoff and its retained failed
development receipt; do not treat a passing prefix as the whole driver passing.
