# Device acceptance runbook for the Rust cutover

Audience: the maintainer, at his Apple Silicon MacBook (Touch ID), an iPhone,
Xcode, an Apple Developer account (App Store Connect / TestFlight) and a
browser. Run once, at the end, on the cutover candidate. Each step is sized for
about ten minutes of hands-on time (S6 adds passive waiting for Apple).

This runbook closes the hardware residuals that
[ADR 0037](../adr/0037-proposed-ratification-at-rust-cutover.md) lists under
"Device acceptance (human)". They are not ratified and not automated; the
result is a manual acceptance note, recorded with the template at the end and
pasted into [contract-matrix.md](contract-matrix.md) by the coordinator.

| Step | Closes (matrix row / issue) | Needs |
|---|---|---|
| S1 Touch ID unlock | SESSION-003, #1243, #1034 | Mac with Touch ID, shipped binary |
| S2 Clipboard, permissions, secure UI, notification | PLATFORM-001, PLATFORM-002 | Mac, logged-in desktop, shipped binary |
| S3 MCP `copy_to_clipboard` / `autotype` | MCP-003, PLATFORM-001 | Mac, TextEdit, shipped binary |
| S4 OAuth consent in a real browser | HTTP-003 | Mac, browser, shipped binary |
| S5 iPhone: FFI device slice, backup flag, memory | FFI-001, FFI-002, #1251, #870 | iPhone, Xcode, signing |
| S6 TestFlight internal beta | #938 (FFI-001 end to end) | iPhone, App Store Connect |

Everything marked **BLOCKER for coordinator** is not implemented or not
buildable today. The step says what is missing instead of inventing a command.
The blockers are collected in the register at the end.

Order: S0, then S1 to S4 in one sitting (about 50 minutes), then S5, then S6.
S1 to S4 use the same scratch vault. Run the cleanup (S9) when done.

---

## S0. Prerequisites and scratch setup

### What the coordinator must hand over

| Item | Used by | How the coordinator produces it |
|---|---|---|
| **BIN**: absolute path of the cutover candidate `symvault` for macOS arm64 | S1 to S4 | The shipped artefact, not a debug build. `make build` (runs `rust-cli`, release profile, `target/release/symvault`) or the unpacked release archive. State which. |
| Build SHA of BIN | all | `git rev-parse HEAD` of the build tree, plus `SYMVAULT_VERSION` if set. |
| Signature state of BIN | S1, S2, S3 | Output of `codesign -dv --verbose=4 BIN`. [distribution.md](../distribution.md) says macOS binaries are currently unsigned (Apple Silicon still gives them an ad-hoc signature); [macos-notarization.md](../macos-notarization.md) says Developer ID notarization is pending secrets. **BLOCKER for coordinator:** say which signature the candidate has. Keychain ACLs and Accessibility/Automation grants are tied to the code identity, so S1 to S3 results are only valid for that identity. |
| `client/.build/mobilecore/SymvaultFFI.xcframework` and the generated `client/Symvault.xcodeproj` | S5, S6 | `bash scripts/build-vaultcore.sh` then `(cd client && xcodegen generate)`. `./scripts/ios-testflight.sh preflight` does both and builds an unsigned device app. Needs the pinned Rust toolchain with `aarch64-apple-ios` and `aarch64-apple-ios-sim`, full Xcode with the iOS SDK, and `xcodegen`. |
| A release (non-beta) Xcode | S5, S6 | `scripts/ios-testflight.sh` skips `Xcode-beta.app` on purpose; Apple can reject beta-SDK uploads. |

### Machine prerequisites (one-time)

- macOS in an unlocked, logged-in Aqua session. Touch ID enrolled with at least
  one finger. Lid open (Touch ID sensor reachable).
- Terminal app of your choice (Terminal.app, iTerm, Ghostty). Whichever you
  use is the "responsible process" macOS shows in privacy dialogs; note which.
- Turn off any clipboard-history manager (Raycast, Alfred, Maccy, Paste, ...)
  and Universal Clipboard for the S2 and S3 clipboard checks. A manager that
  keeps the copied value makes the auto-clear warning fire legitimately.
- `python3`, `curl`, `openssl`, `sqlite3`, `security`, `osascript`, `pbpaste`
  (all ship with macOS or the Xcode command line tools).

### Scratch vault that never touches the real vault

Everything lives under `/private/tmp/symvault-acceptance`. The real vault
(`~/.local/share/symaira-vault` or `~/.symvault`) is not opened. The wrappers
below pass `--vault` explicitly and point `XDG_*` at the scratch directory so
no global config is read or written.

`HOME` is deliberately **not** changed. Keychain Services locates the login
keychain from the real user session; a fake `HOME` would silently test a
different keychain. The scratch vault path is part of the Keychain service
name (`symvault-biometric:<vault dir>`), so its items cannot collide with the
real vault's.

Paste this block once. Replace the `BIN=` line. Plain shell assignments only;
nothing is exported and no directory is changed.

```sh
BIN=/ABSOLUTE/PATH/TO/symvault
S=/private/tmp/symvault-acceptance
E="$HOME/symvault-device-acceptance-evidence"
mkdir -p "$S/xdg/config" "$S/xdg/data" "$S/xdg/cache" "$S/empty" "$E"
chmod 700 "$S"

# sv: real login keychain, NO env passphrase. Used by S1.
cat > "$S/sv" <<EOF
#!/bin/sh
exec /usr/bin/env -u CI -u GITHUB_ACTIONS -u HEADLESS -u SYMVAULT_TEST_KEYRING \\
  -u SYMVAULT_PASSPHRASE -u SYMVAULT_ALLOW_ENV_PASSPHRASE \\
  XDG_CONFIG_HOME="$S/xdg/config" XDG_DATA_HOME="$S/xdg/data" XDG_CACHE_HOME="$S/xdg/cache" \\
  "$BIN" --vault "$S/vault" "\$@"
EOF

# sv-mem: in-memory session keyring + scratch passphrase from the environment.
# Used by S2 to S4 so they never write a keychain item.
cat > "$S/sv-mem" <<EOF
#!/bin/sh
exec /usr/bin/env -u CI -u GITHUB_ACTIONS -u HEADLESS \\
  XDG_CONFIG_HOME="$S/xdg/config" XDG_DATA_HOME="$S/xdg/data" XDG_CACHE_HOME="$S/xdg/cache" \\
  SYMVAULT_TEST_KEYRING=memory SYMVAULT_NO_ENV_WARNING=1 \\
  SYMVAULT_PASSPHRASE=acceptance-scratch-passphrase SYMVAULT_ALLOW_ENV_PASSPHRASE=1 \\
  "$BIN" --vault "$S/vault" "\$@"
EOF
chmod 700 "$S/sv" "$S/sv-mem"

# Provenance for the result record
"$BIN" version
shasum -a 256 "$BIN"
codesign -dv --verbose=4 "$BIN" 2>&1 | head -20
uname -mrs; sw_vers

# Scratch vault (test passphrase: acceptance-scratch-passphrase) and one entry
"$S/sv-mem" init --auth passphrase
"$S/sv-mem" add scratch/login --username scratch-user --type password --force --value 'Sx-Test-Pw-4711'
"$S/sv-mem" list
"$S/sv-mem" get scratch/login.password --print
```

Expected: `Vault initialized at /private/tmp/symvault-acceptance/vault`, the list
shows `scratch/login`, and the last command prints `Sx-Test-Pw-4711`. (`--force`
skips the password-strength check, which the short test value would trip; `add`
without `--value` opens an interactive form, which this runbook avoids.) If any of
these fail, stop: the binary or the runbook is wrong, record it.

`BIN`, `S` and `E` are plain shell variables and live as long as this terminal
tab. Later blocks re-assign `S` but use `E` as is; in a new tab, run the first
three assignment lines (`BIN=`, `S=`, `E=`) again before anything else.

Evidence screenshots: `screencapture -x "$E/<name>.png"`, or with a delay while
a dialog is up: `screencapture -T 4 -x "$E/<name>.png" &` before you trigger
the dialog.

The scratch passphrase is a test value, not a credential. Do not reuse it.

---

## S1. Touch ID unlock through the shipped binary (SESSION-003)

**Purpose.** Closes the SESSION-003 hardware residual: the Touch ID prompt
(accept, cancel, failure) through the JXA `LAContext` evaluation, the real
default-keychain path `SecurityBiometricItems::system()`, cross-binary
access-control behaviour, and the item layout the default (login) keychain
actually stores. Also the #1243 acceptance line "the keychain prompt names
SymVault" and the #1034 symptom (a prompt naming `/usr/bin/security`).

How it works in this tree (read from source, so you know what to expect):

- `symvault unlock` is the command that reaches Touch ID. Order: reuse a
  cached session if present; else, if `authMethod` is `touchid` and a GUI
  session exists and no `CI`/`GITHUB_ACTIONS`/`HEADLESS`/
  `SYMVAULT_TEST_KEYRING=memory` is set: probe the keychain item **without
  reading it**, show the Touch ID dialog, then read the item.
  (`crates/symvault-cli/src/session_commands.rs`, `load_touch_id_passphrase`.)
- The dialog is produced by `/usr/bin/osascript` running a JXA `LAContext`
  script with reason `Unlock Symaira Vault vault` and a 30 s timeout
  (`crates/symvault-platform/src/macos.rs`). The dialog may therefore name
  `osascript`, not SymVault. Record exactly what it says; do not interpret.
- The passphrase item is a generic password, service
  `symvault-biometric:<vault dir>`, account `passphrase`, raw passphrase bytes,
  written and read through Security.framework (no `security` subprocess).
- The session cache (a different keychain item, service `symvault:<vault>|...`)
  intentionally goes through `/usr/bin/security`
  (`crates/symvault-platform/src/os_keyring.rs`). A dialog naming `security`
  for **that** item is by design; a dialog naming `security` for the
  `symvault-biometric:` item is the #1034 failure.
- Cancel and failure are silent in `unlock`: the Touch ID error is swallowed and
  the command falls back to the passphrase prompt.

### S1.1 Enable Touch ID on the scratch vault

```sh
S=/private/tmp/symvault-acceptance
"$S/sv" auth status
"$S/sv" auth set touchid
```

At `Passphrase:` type `acceptance-scratch-passphrase`.

Expected: `Auth method set to touchid`. No Touch ID dialog here (saving is not
biometric-gated). If a keychain dialog appears, screenshot it and record the
application name.

If you get `touch ID is not available in this Symaira Vault build or on this
Mac`, the JXA availability probe failed; record it and stop S1.

### S1.2 Item layout and ACL (no prompt expected, no secret read)

```sh
S=/private/tmp/symvault-acceptance
SVC="symvault-biometric:$S/vault"
security find-generic-password -s "$SVC" -a passphrase           # attributes only
security dump-keychain -a "$HOME/Library/Keychains/login.keychain-db" 2>/dev/null \
  | awk -v s="$SVC" 'BEGIN{RS="keychain: "; ORS=""} index($0,s){print "keychain: " $0}' \
  | tee "$E/s1-item-acl.txt"
```

Expected: one item, `"svce"<blob>="symvault-biometric:/private/tmp/symvault-acceptance/vault"`,
`"acct"<blob>="passphrase"`, class `genp`, and an `access:` section. Record
which applications the ACL trusts (it should name the `symvault` binary, not
only `security`) and whether an `accessibility` attribute is present.
`kSecAttrAccessibleWhenUnlockedThisDeviceOnly` stores no attribute on file
keychains (matrix reviewer probe); this is the first look at the login keychain.
Record what you see; absence is a finding to note, not a failure.

### S1.3 Accept

```sh
S=/private/tmp/symvault-acceptance
"$S/sv" lock
screencapture -T 4 -x "$E/s1-touchid-accept.png" &
"$S/sv" unlock
echo "unlock exit=$?"
"$S/sv" unlock --check; echo "check exit=$?"
"$S/sv" list
```

Touch the sensor when the dialog appears.

Expected: Touch ID dialog with reason text `Unlock Symaira Vault vault`; after
touch, `unlock` exits 0 with no passphrase prompt; `unlock --check` prints
`Session active` and exits 0; `list` prints `scratch/login` without prompting.
No keychain-access dialog at any point.

Pass: all of the above and no dialog naming `security`. Record the exact
application name shown in the Touch ID dialog and its text.

### S1.4 Cancel

```sh
S=/private/tmp/symvault-acceptance
"$S/sv" lock
screencapture -T 4 -x "$E/s1-touchid-cancel.png" &
"$S/sv" unlock
```

Click **Cancel** in the dialog. Expected: the command shows its passphrase
prompt (the Touch ID error is swallowed). Press Ctrl-C there. Then:

```sh
S=/private/tmp/symvault-acceptance
"$S/sv" unlock --check; echo "check exit=$?"
```

Expected: `no active session`, non-zero exit. Pass: no session was created and
the passphrase was not revealed anywhere.

### S1.5 Failure (wrong finger, and timeout)

Wrong finger:

```sh
S=/private/tmp/symvault-acceptance
"$S/sv" lock
"$S/sv" unlock
```

Touch with a finger that is **not** enrolled until the dialog stops offering
retries. Record what the dialog offers after the failures (retry, password
fallback, close) and what `unlock` does afterwards.
Expected: no session; passphrase prompt (Ctrl-C out). `unlock --check` fails.

Timeout (30 s limit in code):

```sh
S=/private/tmp/symvault-acceptance
"$S/sv" lock
"$S/sv" unlock
```

Do nothing for 40 seconds. Expected: dialog disappears at about 30 s, passphrase
prompt follows. Ctrl-C. Record observed seconds.

### S1.6 Cross-binary access (the #1034 shape)

```sh
S=/private/tmp/symvault-acceptance
SVC="symvault-biometric:$S/vault"
screencapture -T 4 -x "$E/s1-security-read.png" &
security find-generic-password -s "$SVC" -a passphrase -w
```

A keychain dialog is expected. **Click Deny.** Record the application name and
the item name in the dialog. This shows what a foreign reader sees; it is the
reverse of the #1034 bug (there the *vault* reader was `security`). Pass: the
dialog names `security`, not `symvault`, as the requester.

Optional second binary (an identical copy at another path):

```sh
S=/private/tmp/symvault-acceptance
BIN=/ABSOLUTE/PATH/TO/symvault
cp "$BIN" "$S/symvault-copy"
"$S/sv" lock
/usr/bin/env -u CI -u SYMVAULT_TEST_KEYRING XDG_CONFIG_HOME="$S/xdg/config" \
  XDG_DATA_HOME="$S/xdg/data" XDG_CACHE_HOME="$S/xdg/cache" \
  "$S/symvault-copy" --vault "$S/vault" unlock
```

Touch the sensor. Record whether a keychain dialog appears and what it names.
No pass/fail rule: an ad-hoc signed copy with the same code directory hash may
be trusted, a differently signed one will prompt. This is evidence for the
signature question in S0.

### S1.7 Go item read by Rust (optional, about 10 extra minutes)

The residual "reading a Rust-written item with Go's cgo store" and the reverse
(the #1243 migration line: existing Go-written items unlock with Rust) need a
Touch ID Mac and a Go build from the archive tag `legacy/go-oracle`
(`go.mod` says `go 1.26.6`; `touchid_darwin.go` builds with `darwin && cgo`).

**BLOCKER for coordinator:** no prepared Go binary exists. If the maintainer
wants this residual closed, the coordinator builds it, for example:

```sh
REPO=/ABSOLUTE/PATH/TO/symaira-vault
S=/private/tmp/symvault-acceptance
git -C "$REPO" worktree add "$S/go-oracle" legacy/go-oracle
CGO_ENABLED=1 go -C "$S/go-oracle" build -o "$S/symvault-go" .
```

and states the Go-side commands (same command names as the Go-era help; not
verified here). Then: with `$S/symvault-go --vault $S/vault-go` run `auth set
touchid` and `unlock`, and unlock the **same** vault with the Rust binary, and
the reverse for the scratch vault above. Pass: neither direction shows a
passphrase prompt or a foreign-requester keychain dialog. Skip and record
"not run" if the coordinator did not build it.

---

## S2. Clipboard, auto-clear, permission prompts, secure UI, notification

**Purpose.** PLATFORM-001 (clipboard and autotype on a real desktop) and
PLATFORM-002 (GUI secure input, notification delivery, accessibility prompt).
Autotype itself is exercised through MCP in S3; this step gets the permission
prompts out of the way and does the CLI clipboard path.

### S2.1 Clipboard copy and auto-clear (CLI `get`)

```sh
S=/private/tmp/symvault-acceptance
"$S/sv-mem" config set --file "$S/vault/config.yaml" clipboard.auto_clear_duration 10
printf 'before' | pbcopy
"$S/sv-mem" get scratch/login.password
pbpaste; echo
```

Run `get` directly in a terminal (stdout must be a TTY or it prints instead of
copying). Expected on stderr: `[copied to clipboard]`, then a countdown
`[clearing clipboard in 10s]` ticking each second, then `[clipboard cleared]`.
Exit code 0. `pbpaste` right after the command returns must be empty (the
command blocks for the whole countdown, so run `pbpaste` afterwards, and
separately check mid-way, see below).

Mid-way check, two terminal tabs: in tab 1 run `"$S/sv-mem" get
scratch/login.password`; in tab 2 within the countdown run `pbpaste`. Expected
`Sx-Test-Pw-4711` in tab 2, empty after the clear.

Pass: value present during the countdown, empty afterwards, no
`Warning: ... consider disabling clipboard-history retention` line.

Negative and cancel branches:

- Ctrl-C during the countdown. Expected: the clipboard is cleared at once
  (`[clipboard cleared]`), exit 0.
- `"$S/sv-mem" get scratch/login.password --print` prints the value and leaves
  the clipboard untouched (`pbpaste` still shows `before` after `printf
  'before' | pbcopy`).
- Optional: turn a clipboard-history manager back on and repeat. Expected: the
  warning line appears. Records that the warning works on a real pasteboard.

Record: the three stderr lines verbatim, `pbpaste` values at each point.

### S2.2 Automation and Accessibility prompts (prime them)

macOS shows these prompts for the responsible process (your terminal app).
Trigger them now so S3 sees a settled state.

```sh
osascript -e 'tell application "System Events" to get name of first application process whose frontmost is true'
```

Expected: first time, a dialog `"<terminal>" wants access to control "System
Events"`; click **OK/Allow**. Output: the frontmost app name. This is the same
call the autotype focus guard makes before typing
(`crates/symvault-platform/src/macos.rs`, `type_text`).

The `keystroke` call needs Accessibility. Do not trigger it here, because a
keystroke would land in whatever is focused. The first real `autotype` in S3.4
raises that prompt (or its error) with TextEdit focused; do the denied branch
there first, then grant. Before S3, just open System Settings, Privacy &
Security, Accessibility, and note whether your terminal app is already listed
and switched on (that decides which S3.4 branch you see). Screenshot it.

### S2.3 GUI secure input and notification (PLATFORM-002)

**BLOCKER for coordinator:** no shipped command reaches these. `MacOsPlatform`
implements `Notifier` and `SecureUi` (`macos.rs`), but no CLI or MCP code calls
them: ADR 0034 item 28 (no GUI secure-input or approval backend, fail closed
without a TTY) and item 29 (no desktop notifications in Rust MCP). Until the
maintainer decides item 28 option B (wire the adapters), the through-the-binary
delivery check does not exist. If option A (fail closed) is ratified, record
S2.3 as "not applicable; ADR 0034 item 28/29".

What can be checked today is the host capability the adapters rely on. These
two commands are the adapter scripts from `macos.rs` run by hand. They prove
macOS delivers the dialog and notification to `osascript`, not that SymVault
does:

```sh
osascript -l JavaScript -e "var app = Application.currentApplication(); app.includeStandardAdditions = true; app.displayNotification('symvault acceptance probe', { withTitle: 'Symaira Vault' });"
osascript -l JavaScript -e "var app = Application.currentApplication(); app.includeStandardAdditions = true; var answer = app.displayDialog('', { withTitle: 'Symaira Vault acceptance', defaultAnswer: '', hiddenAnswer: true }); answer.textReturned;"
```

Expected: a notification banner titled `Symaira Vault` (attributed to Script
Editor or osascript, record which; if nothing appears, check System Settings,
Notifications, for Script Editor); and a dialog with a masked text field.
Type `probe`, press OK; the command prints `probe`. Cancel gives an execution
error `User canceled. (-128)`. Record all of it, and label the result "host
capability probe only".

---

## S3. MCP `copy_to_clipboard` and `autotype` on the host (MCP-003)

**Purpose.** MCP-003 and PLATFORM-001: the two tools against the real macOS
pasteboard and a real focused application, through a minimal stdio MCP
session. Tools are `copy_to_clipboard` (copies the entry's `password` field)
and `autotype` (types a string field into the frontmost app, default field
`password`); both are real tool names in `crates/symvault-mcp`.

### S3.1 Negative first: tools denied for the default profile

The scratch vault's default agent `cli` has `canUseClipboard` and
`canUseAutotype` false. Wire format: newline-delimited JSON-RPC 2.0 on stdin,
one request per line; only protocol frames on stdout, diagnostics on stderr.

```sh
S=/private/tmp/symvault-acceptance
INIT='{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"device-acceptance","version":"1"}}}'
NOTE='{"jsonrpc":"2.0","method":"notifications/initialized"}'
CALL='{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"autotype","arguments":{"path":"scratch/login","field":"password"}}}'
printf '%s\n' "$INIT" "$NOTE" "$CALL" | "$S/sv-mem" mcp --stdio --agent cli
```

Expected: a response for id 1, then for id 2 an error (a JSON-RPC error or an
`isError` result; record which) containing
`autotype operations not permitted for this agent`. Nothing typed anywhere.
The same call with `copy_to_clipboard` should say `clipboard operations not
permitted for this agent`.

### S3.2 Enable the permissions on the scratch agent

```sh
S=/private/tmp/symvault-acceptance
for k in canUseClipboard canUseAutotype; do
  "$S/sv-mem" config set --file "$S/vault/config.yaml" agents.cli.$k true
done
"$S/sv-mem" config get --file "$S/vault/config.yaml" agents.cli.canUseClipboard
"$S/sv-mem" config get --file "$S/vault/config.yaml" agents.cli.canUseAutotype
"$S/sv-mem" config validate "$S/vault/config.yaml"
```

Expected: `true`, `true`, and a clean validate. Do **not** set `tier: admin`
on this agent: the admin preset switches `approvalMode` to `prompt` and
`requireApproval` to true, which would make `copy_to_clipboard` prompt and
`autotype` refuse with `autotype denied: approval required but cannot be
granted` (`crates/symvault-core/src/tier.rs`, `call.rs`). The `cli` agent that
`init` creates has no tier and no approval mode, which means no approval.
The `config set` dotted-path form is documented in the man page example
(`symvault config set agents.claude-code.canWrite true`); this exact key set was
not executed while writing this runbook (blocker B4). If `set` or `validate`
rejects it, record the error text and tell the coordinator: that is a runbook
defect, not a product result.

### S3.3 `copy_to_clipboard` and its auto-clear

```sh
S=/private/tmp/symvault-acceptance
INIT='{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"device-acceptance","version":"1"}}}'
NOTE='{"jsonrpc":"2.0","method":"notifications/initialized"}'
CALL='{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"copy_to_clipboard","arguments":{"path":"scratch/login"}}}'
printf 'before' | pbcopy
(
  printf '%s\n' "$INIT" "$NOTE" "$CALL"
  sleep 3;  echo "T+3s  clipboard: [$(pbpaste)]" >&2
  sleep 10; echo "T+13s clipboard: [$(pbpaste)]" >&2
) | "$S/sv-mem" mcp --stdio --agent cli
grep -c copy_to_clipboard "$S/vault/audit-cli.log"
```

The subshell keeps stdin open for 13 s so the server stays alive for the timed
clear (auto-clear is 10 s from S2.1).

Expected: the id 2 response carries the text `{"success": true}`; **the
password is not in any response**; `T+3s clipboard: [Sx-Test-Pw-4711]`;
`T+13s clipboard: []`; the audit log has at least one `copy_to_clipboard` row.
Pass: all four. Record the response frame verbatim (it must not contain
`Sx-Test-Pw-4711`).

Cancel branch: repeat but replace the `sleep 10` with a Ctrl-C of the whole
pipeline at T+3s. Expected: the clipboard is cleared on SIGINT (matrix MCP-003:
INT/TERM clear the active clipboard). Check with `pbpaste` afterwards.

### S3.4 `autotype` into a real application

Prepare: `open -a TextEdit`, press ⌘N, choose Format, Make Plain Text (⇧⌘T) so
nothing is auto-corrected. Leave the terminal visible so you can click TextEdit.

```sh
S=/private/tmp/symvault-acceptance
INIT='{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"device-acceptance","version":"1"}}}'
NOTE='{"jsonrpc":"2.0","method":"notifications/initialized"}'
CALL='{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"autotype","arguments":{"path":"scratch/login","field":"password"}}}'
echo "You have 8 seconds: click into the TextEdit document now." >&2
(
  printf '%s\n' "$INIT" "$NOTE"
  sleep 8
  printf '%s\n' "$CALL"
  sleep 3
) | "$S/sv-mem" mcp --stdio --agent cli
```

Click into the TextEdit text area within the 8 seconds.

Expected, first run, Accessibility **not** granted to the terminal: the id 2
result is an error `autotype failed: ...` (the `System Events` `keystroke`
refusal; record its text) and nothing is typed. Screenshot the macOS prompt.

Then grant it: System Settings, Privacy & Security, Accessibility, switch on
your terminal app (and Automation, System Events, if offered). Run the block
again. Expected: TextEdit shows exactly `Sx-Test-Pw-4711`, the response is
`{"success": true}`, and the response frame does not contain the password.
Pass: typed text equals the field value, once, in the focused app.

Focus-guard branch (code: `focus::guard` captures the frontmost process,
waits 200 ms and captures again; a change aborts):
if you can, switch applications at the exact moment the call is sent. The
expected error is `autotype: active window changed between capture and send -
aborting to prevent typing into the wrong app`. This is hard to hit by hand;
record "not triggered" if it does not occur. It is covered by fixture
(`testdata/port/platform/focus.json`) already.

Record: whether the Automation and Accessibility prompts appeared, their
wording, which application they named, the typed result, and the audit rows
(`grep autotype "$S/vault/audit-cli.log"`).

---

## S4. One OAuth consent flow in a real browser (HTTP-003)

**Purpose.** HTTP-003: discovery, dynamic client registration, authorize, the
**browser consent page**, authorization code, token exchange, against a local
`symvault mcp` HTTP server, driven by a real browser. The Go/Rust protocol
legs are already pinned by tests; this closes the UI leg.

Facts that shape the commands (from `crates/symvault-cli/src/mcp_commands.rs`
and `crates/symvault-mcp/src/oauth.rs`):

- There is no flag to enable OAuth: the HTTP server (`symvault mcp` without
  `--stdio`) always serves `/.well-known/oauth-authorization-server`,
  `/oauth/register`, `/mcp/oauth/authorize`, `/mcp/oauth/authorize/confirm`,
  `/mcp/oauth/token`. Real flags: `--bind` (default `127.0.0.1`), `--port`
  (default 8080), `--tls-cert/--tls-key/--tls-ca`, `--agent`, `--stdio`,
  `--allow-locked`.
- Consent is a browser page only when **stdin is not a terminal**. With a
  terminal on stdin the server asks `... Approve? [y/N]` on stderr instead. So
  start the server with `</dev/null` (vault unlocks from the scratch env
  passphrase in `sv-mem`).
- With no cert configured and no `allow_insecure_bind`, the server generates a
  self-signed certificate: the URL is `https://127.0.0.1:<port>` and the
  browser will show a certificate warning. Accepting it is part of the check.
- The consent page asks for the **vault passphrase** and has Approve and Deny.
- The authorization code is delivered by redirect to the registered redirect
  URI. A tiny local listener on `127.0.0.1:4321` catches it.
- Doc caveat: `docs/mcp-api.md` describes the consent as a TTY prompt only; the
  browser consent is the non-TTY behaviour in the code.

### S4.1 Start the server and the callback catcher

```sh
S=/private/tmp/symvault-acceptance
"$S/sv-mem" mcp --port 8765 </dev/null 2>"$S/mcp-http.log" &
echo $! > "$S/mcp.pid"
python3 -m http.server 4321 --bind 127.0.0.1 --directory "$S/empty" >"$S/callback.log" 2>&1 &
echo $! > "$S/callback.pid"
sleep 3
cat "$S/mcp-http.log"
```

Expected in `mcp-http.log`: `MCP server listening on 127.0.0.1:8765`. If the
port is taken, pick another and adjust every `8765` below.

### S4.2 Register, build the PKCE challenge, open the browser

```sh
S=/private/tmp/symvault-acceptance
BASE=https://127.0.0.1:8765
curl -sk "$BASE/.well-known/oauth-authorization-server"; echo
CLIENT=$(curl -sk "$BASE/oauth/register" -H 'Content-Type: application/json' \
  -d '{"redirect_uris":["http://127.0.0.1:4321/callback"]}' \
  | python3 -I -c 'import sys,json; print(json.load(sys.stdin)["client_id"])')
echo "client_id=$CLIENT"
VERIFIER=$(openssl rand -base64 48 | tr '+/' '-_' | tr -d '=\n')
CHALLENGE=$(printf '%s' "$VERIFIER" | openssl dgst -sha256 -binary | openssl base64 | tr '+/' '-_' | tr -d '=\n')
printf '%s' "$VERIFIER" > "$S/verifier.txt"; echo "$CLIENT" > "$S/client_id.txt"
URL="$BASE/mcp/oauth/authorize?response_type=code&client_id=$CLIENT&redirect_uri=http%3A%2F%2F127.0.0.1%3A4321%2Fcallback&code_challenge=$CHALLENGE&code_challenge_method=S256&state=acceptance-state"
echo "$URL" > "$S/authorize-url.txt"
open "$URL"
```

Expected: the metadata JSON lists `authorization_endpoint`, `token_endpoint`,
`registration_endpoint`, `code_challenge_methods_supported: ["S256"]`; the
registration returns a 32-hex-character `client_id`; the browser opens.

### S4.3 In the browser

1. Certificate warning for `127.0.0.1`: proceed (Safari: Show Details, visit
   the website; Chrome: Advanced, Proceed). Screenshot it.
2. The page **Authorize MCP client** shows `Client: <client_id>`, `Redirect URI:
   http://127.0.0.1:4321/callback`, `Agent: ...`, "requests full access to this
   agent's tools", a password field `Vault passphrase`, and Approve / Deny.
   Screenshot it. Record the agent name shown.
3. Wrong-passphrase branch: type `wrong`, click **Approve**. Expected: the page
   reloads with `Incorrect passphrase.` and no redirect.
4. Type `acceptance-scratch-passphrase`, click **Approve**. Expected: the
   browser is redirected to `http://127.0.0.1:4321/callback?code=...&state=
   acceptance-state` (the page itself is a directory-listing or error page from
   the catcher; that is fine).

### S4.4 Exchange the code (and single-use check)

```sh
S=/private/tmp/symvault-acceptance
BASE=https://127.0.0.1:8765
grep 'GET /callback' "$S/callback.log"
CODE=$(grep -o 'code=[0-9a-f]*' "$S/callback.log" | head -1 | cut -d= -f2)
VERIFIER=$(cat "$S/verifier.txt")
echo "--- first exchange"
curl -sk "$BASE/mcp/oauth/token" -d grant_type=authorization_code -d "code=$CODE" -d "code_verifier=$VERIFIER" \
  | python3 -I -c 'import sys,json; d=json.load(sys.stdin); print({k:(v if k in ("token_type","expires_in","error") else "<redacted>") for k,v in d.items()})'
echo "--- replay of the same code"
curl -sk -w '\nHTTP %{http_code}\n' "$BASE/mcp/oauth/token" -d grant_type=authorization_code -d "code=$CODE" -d "code_verifier=$VERIFIER"
```

Expected: the callback log line carries `code=` and `state=acceptance-state`;
first exchange returns `token_type: Bearer`, an `expires_in` number and the
`access_token` and `refresh_token` keys (values redacted by the filter);
the replay is an error response (a 4xx with an OAuth error body; record the
body). Pass: tokens issued exactly once.

### S4.5 Deny branch

Open a fresh flow (run the S4.2 block again to get a new URL and verifier),
and in the browser click **Deny** (no passphrase needed). Expected redirect
to `http://127.0.0.1:4321/callback?error=access_denied&state=...`.
Check `grep 'error=access_denied' "$S/callback.log"`.

### S4.6 Stop

```sh
S=/private/tmp/symvault-acceptance
kill -INT "$(cat "$S/mcp.pid")"; kill "$(cat "$S/callback.pid")"
sleep 2; tail -5 "$S/mcp-http.log"
```

Expected: the MCP server exits 0 on SIGINT (HTTP signal shutdown, ADR 0034
item 16). Record the browser name and version.

---

## S5. iPhone: device slice, tests, backup flag, memory (FFI-001, FFI-002)

**Purpose.** FFI-001 residuals: the `ios-arm64` slice of
`SymvaultFFI.xcframework` running on a physical iPhone; launching the app;
`MobileVaultCoreTests` and `ApprovalSessionStoreTests` on a signed host;
whether iOS honours `isExcludedFromBackup` on the backup directory. FFI-002:
measured RSS and latency of read/decrypt/list on the device.

Coordinator preparation: see S0 (xcframework built, project generated, release
Xcode). Never run this against a vault you care about.

### S5.1 Connect and identify the phone

1. iPhone: Settings, Privacy & Security, Developer Mode on (restart), trust
   this Mac when asked.
2. Mac:

```sh
xcrun devicectl list devices
xcrun xctrace list devices
```

Note the device identifier (`devicectl`) / UDID (`xctrace`), iOS version, model.

### S5.2 Run the app built against the Rust XCFramework

In Xcode: open `client/Symvault.xcodeproj`, scheme **SymvaultIOSApp**, destination
your iPhone. Signing is automatic with team `M4744F3TAA` (`client/project.yml`),
bundle id `com.symaira.vault.ios`. Product, Run (⌘R). First launch: trust the
developer profile on the phone if asked (Settings, General, VPN & Device
Management).

Expected, in order (strings from `client/Sources/SymvaultIOS`):

1. The app launches (this alone is the first execution of the `ios-arm64`
   slice; the matrix says it was never run).
2. Enrol screen: text "Symaira Vault", button **Enrol this device**. Tap it.
   Expected: no error alert. (The core generates an age identity and the app
   stores it behind Face ID/Touch ID.)
3. Unlock screen: "Unlock with Face ID", button **Unlock**. Tap; the system
   biometric prompt shows the app's purpose string ("Symaira Vault uses Face ID
   to read your device identity."). Accept.
4. Entry list screen, or an error alert. The vault directory is
   `Documents/symaira-vault` in the app container when iCloud is not available
   (`VaultStore`). An empty or missing vault produces whatever the core says;
   record the alert text verbatim. It is not a failure of this step by itself:
   the FFI call completing and reporting an error from Rust proves the slice
   executes.

Record: iOS version, device model, whether each screen appeared, screenshots,
and the Xcode console lines. Cancel branch: cancel the biometric prompt in 3;
expected: the app stays on the Unlock screen with an error, no crash.

### S5.3 Tests on the device (signed host)

Verified route (simulator, from the matrix FFI-001 row and `resumption.md`):
move the generated `Symvault.xcodeproj` aside (otherwise `xcodebuild` picks the
project, which only has the app scheme), then run the package scheme with
`-only-testing:SymvaultIOSTests/MobileVaultCoreTests`:

```sh
REPO=/ABSOLUTE/PATH/TO/symaira-vault
E="$HOME/symvault-device-acceptance-evidence"
mv "$REPO/client/Symvault.xcodeproj" "$REPO/client/Symvault.xcodeproj.aside"
( cd "$REPO/client" && xcodebuild test -scheme SymvaultClient-Package \
    -destination 'platform=iOS,id=<DEVICE-IDENTIFIER-FROM-S5.1>' \
    -only-testing:SymvaultIOSTests/MobileVaultCoreTests \
    -allowProvisioningUpdates DEVELOPMENT_TEAM=M4744F3TAA ) 2>&1 \
  | tee "$E/s5-mobilevaultcore-device.log" | tail -40
mv "$REPO/client/Symvault.xcodeproj.aside" "$REPO/client/Symvault.xcodeproj"
```

The subshell `cd` does not persist. **This exact device invocation has never
been run** (blocker B6). The matrix verified the same command with a simulator
destination (`id=<iOS 18.6 Simulator>`, 3/3 on 2026-11-01; the class has
seven test functions at this revision, so expect seven). Expected on a device: the
`MobileVaultCoreTests` cases pass (`** TEST SUCCEEDED **`), including
`testBackupDirectoryIsExcludedFromBackupAndUsedByTheDataSafetyGate`.

`ApprovalSessionStoreTests` (round trip of a Keychain item,
`kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`): **BLOCKER for coordinator.**
Unsigned, the whole `SymvaultIOSTests` bundle fails them with `-34018`
(missing keychain entitlement; `resumption.md`). `client/project.yml` defines no
test target and no signed test host, and the package scheme runs the tests
unhosted. The coordinator must add a hosted, signed test target (or a
documented way to run the package tests inside `SymvaultIOSApp`) before this
line can be executed. Until then record "not run: no signed test host".

Pass: `MobileVaultCoreTests` green on the device. Fail: any failure, with the
log. The log must name the device, not a simulator.

### S5.4 `isExcludedFromBackup` on the backup directory

The client creates `Application Support/symaira-vault-backups` (mode 0700),
sets the flag, reads it back, and only then calls the core
(`MobileVaultBackup.prepare`); every call that opens or lists the vault does
this, so it exists after step 3 of S5.2. The unit test reads the flag back; the
open question is whether iOS **honours** it when it makes a backup.

1. Directory and attribute on the device. Xcode, Window, Devices and
   Simulators, select the iPhone, select **Symaira Vault** in Installed Apps,
   gear menu, **Download Container...**, save to `$E/container.xcappdata`.

```sh
xattr -l "$E/container.xcappdata/AppData/Library/Application Support/symaira-vault-backups"
```

Expected: the attribute `com.apple.metadata:com_apple_backup_excludeItem`
(the on-disk form of `isExcludedFromBackup`). If the container download strips
extended attributes, record that and rely on step 2.

2. What a backup contains. Finder, select the iPhone, **uncheck "Encrypt local
backup"** (Manifest.db is only readable unencrypted), Back Up Now to this Mac.
Then:

```sh
BK=$(ls -dt "$HOME/Library/Application Support/MobileSync/Backup/"*/ | head -1)
sqlite3 "$BK/Manifest.db" \
  "select domain, relativePath from Files where domain = 'AppDomain-com.symaira.vault.ios' and relativePath like '%symaira-vault%';"
```

Expected (flag honoured): rows for the vault under `Documents/symaira-vault`
(control: proves the app domain is in the backup) and **no row** whose
`relativePath` contains `symaira-vault-backups`. Re-enable "Encrypt local
backup" afterwards if you normally use it. This procedure is based on the
documented iOS backup layout and was not run while writing the runbook; if the
table or column names differ on your macOS, record `.schema Files`.

Pass: control rows present, `symaira-vault-backups` absent. Fail: the backup
directory appears in the manifest.

### S5.5 Memory and latency of read/decrypt/list (FFI-002)

**Threshold: none is defined.** The matrix row FFI-002 says "measured RSS and
latency on real device" with evidence type "device report" and status TODO;
ADR 0006 D5 and ADR 0031 say the figure "must be measured, not assumed";
#870 says "peak memory recorded on a real device, with the vault size stated";
#1251 says "within the documented budget" but no budget number exists in the
repository. Record the numbers; do not judge pass or fail against an invented
limit.

Three **BLOCKERS for coordinator** apply:

1. **No extension exists.** `client/project.yml` has only the `Symvault`
   (macOS) and `SymvaultIOSApp` targets. There is no AutoFill credential
   provider extension and no share extension (#870 is open). The measurement
   the matrix and ADR 0006 D5 mean (peak memory *inside the extension*) cannot
   be taken. Only the host app can be measured today, which is an upper-bound
   proxy at best (extensions get a smaller memory limit).
2. **No fixture vault and no way to put one on the phone.** The app reads
   `Documents/symaira-vault` in its container (or the iCloud container, which
   `SymvaultIOS.entitlements` does not enable). The phone's identity is
   generated on the device at enrolment and the app never shows its public
   key, so there is no documented way to create a vault encrypted to it, nor to
   state "vault size" (entry count, bytes). The coordinator must provide a
   fixture vault of stated size, a way to copy it into the app container
   (for a development build, `xcrun devicectl device copy to` with
   `--domain-type appDataContainer` is the likely route; not verified), and a
   recipient flow.
3. **No measurement harness.** There are no signposts and no timing code
   around `listEntries`/`readEntry`. Latency would have to be read from
   Instruments' Time Profiler call tree, or the coordinator adds an XCTest
   with `XCTMemoryMetric`/`XCTClockMetric`/`XCTCPUMetric` run on the device
   (needs the signed host from S5.3).

If those are resolved, the manual measurement is:

```sh
xcrun xctrace list templates
xcrun xctrace record --device '<UDID-FROM-S5.1>' --template 'Allocations' \
  --attach 'Symaira Vault' --time-limit 90s --output "$E/s5-allocations.trace"
```

While recording, on the phone: cold-launch the app, unlock (this runs
`listEntries` and one `readEntry` per entry), open one entry, back out. Repeat
with the `Activity Monitor` or `VM Tracker` template if `Allocations` does not
show the footprint. Also watch Xcode's Debug navigator Memory gauge. Record:
peak memory footprint (Xcode gauge or VM Tracker "Dirty Size" / Instruments
"Persistent" high-water mark), wall time of unlock (launch to list visible),
vault size (entries, total bytes on disk), iOS version, device model, build
SHA, and release vs debug configuration (use Release for numbers: Product,
Scheme, Edit Scheme, Run, Build Configuration Release).

The matrix row compares "Go and Rust frameworks". The gomobile framework is no
longer buildable from this repository (client README); record Rust numbers
only and say so.

---

## S6. TestFlight internal beta (#938)

**Purpose.** #938: archive, upload, process, install from TestFlight, smoke.
Also exercises FFI-001 end to end in a distribution-signed build.

Coordinator preparation (all **BLOCKERS for coordinator** unless done):

- **Privacy manifest (B10, resolved on local/device-runbook).**
  `client/Sources/SymvaultIOS/PrivacyInfo.xcprivacy` now exists (XcodeGen puts it
  into the app target's Resources; `plutil -lint` OK). It declares
  `UserDefaults` (`CA92.1`, `VaultStore` `deviceEnrolled`), file timestamp
  (`C617.1`, the Rust core's `stat` calls on vault files in the app container)
  and system boot time (`35F9.1`, Rust `Instant` -> `mach_absolute_time`). It was
  derived from source and std symbols, not from a built archive: still check
  the Xcode privacy report on the real archive and App Store Connect's App
  Privacy status in S6.2, and add any category the report flags.
- **Stale instructions (B11, resolved on local/device-runbook).**
  `docs/ios-testflight.md` now describes the Rust `SymvaultFFI.xcframework`
  flow (`scripts/build-vaultcore.sh` -> `client/.build/mobilecore`) and no
  longer pins `Xcode-26.6.app`; the script picks a non-beta
  `/Applications/Xcode*.app` itself. This Mac reports Xcode 27.2
  (`27B52`) at `/Applications/Xcode.app`; still confirm it is a release build,
  not a beta, before uploading.
- **Build number.** `client/project.yml` sets `MARKETING_VERSION: "1.0"` and
  `CURRENT_PROJECT_VERSION: "1"`. If build 1 was ever uploaded, bump it first
  (the TestFlight guide now says so too); App Store Connect rejects a repeated
  build number. This branch does not change the number.
- **App Store Connect record** points at `com.symaira.vault.ios`
  (Name `Symaira Vault`, SKU `symaira-vault-ios`), an Internal Testing group
  exists with the maintainer added (no public link).
- SymVault holds the Apple entries the script reads:
  `apple-developer/team-id`, `apple-developer/notary-api-key`,
  `apple-developer/notary-api-key-id`, `apple-developer/notary-api-issuer-id`.
  This is the one step that reads your **real** vault (read-only, secrets are
  injected into the child process and not printed).

### S6.1 Preflight, archive, upload

```sh
REPO=/ABSOLUTE/PATH/TO/symaira-vault
ls -d /Applications/Xcode*.app
xcodebuild -version
"$REPO/scripts/ios-testflight.sh" preflight
```

Expected: `Unsigned iPhone app ready: .../Symaira Vault.app`. The script verifies
bundle id `com.symaira.vault.ios` itself.

```sh
REPO=/ABSOLUTE/PATH/TO/symaira-vault
symvault run \
  --env TEAM_ID=apple-developer/team-id.password \
  --env ASC_API_KEY=apple-developer/notary-api-key.password \
  --env ASC_KEY_ID=apple-developer/notary-api-key-id.password \
  --env ASC_ISSUER_ID=apple-developer/notary-api-issuer-id.password \
  -- "$REPO/scripts/ios-testflight.sh" archive

symvault run \
  --env ASC_API_KEY=apple-developer/notary-api-key.password \
  --env ASC_KEY_ID=apple-developer/notary-api-key-id.password \
  --env ASC_ISSUER_ID=apple-developer/notary-api-issuer-id.password \
  -- "$REPO/scripts/ios-testflight.sh" upload
```

(`symvault` here is your installed one for your real vault, not BIN. These are
the commands from the corrected `docs/ios-testflight.md`; no `DEVELOPER_DIR` needed.)

Expected: `Signed iPhone archive ready: .../client/.build/testflight/
SymvaultIOSApp.xcarchive`, then `TestFlight upload submitted to App Store
Connect.` For a local IPA without upload, replace `upload` by `export`; the
IPA lands in `client/.build/testflight/export/`.
Never paste the key, Apple password or any 2FA code into chat or a file.
Negative branch: missing `TEAM_ID` prints `error: TEAM_ID is required; inject
it from SymVault`; a signing failure prints Xcode's error, record it.

### S6.2 App Store Connect

In App Store Connect, open the app, TestFlight tab, iOS builds. Wait for
processing (minutes to an hour; passive). Verify and record: bundle id,
version `1.0`, build number, no upload warnings (screenshot any), export
compliance status (answer truthfully; if prompted for each upload, note it),
App Privacy status, symbols uploaded. Add the build to the Internal Testing
group. Expected: status "Ready to Test" and the testing group sees it.

### S6.3 Install from TestFlight and smoke

On the iPhone: TestFlight app, accept the invitation, Install Symaira Vault,
open it. Smoke list from #938; record pass/fail/not-run for each, with a
screenshot:

1. Launch; enrolment (**Enrol this device**); Face ID unlock.
2. Camera permission prompt appears when opening the pairing scanner; allow.
3. Local-network permission prompt appears on first connection; allow.
4. QR pairing as an approval device (below).
5. An approval request reaches the phone and approve/deny works (below).
6. Logout / re-lock, then unlock again.
7. Failure and retry: pair against a stopped server (expect a visible error, no
   crash), then retry with the server up.

Mac side for 4 and 5 (uses the scratch vault so the real one is untouched).
`docs/approval-devices.md` (B12, resolved on local/device-runbook) now says to
bind the Mac's concrete LAN IP; the Rust server refuses wildcard binds (`MCP
HTTP wildcard binds are unavailable; choose a concrete IP`) and, off loopback,
requires TLS (it generates and reuses a self-signed vault certificate when no
`--tls-cert`/`--tls-key` is given, so none are needed here). The
`approval-pair` loopback error now points at `--bind <lan-ip>` too. Bind the
LAN address:

```sh
S=/private/tmp/symvault-acceptance
LAN=$(ipconfig getifaddr en0)
echo "LAN=$LAN"
"$S/sv-mem" mcp --bind "$LAN" --port 8443 </dev/null
```

(Terminal A; leave it running.) Terminal B:

```sh
S=/private/tmp/symvault-acceptance
LAN=$(ipconfig getifaddr en0)
"$S/sv-mem" device approval-pair --host "$LAN"
"$S/sv-mem" device approval-list
```

Expected: a QR code and the pairing values. Scan it in the app's pairing
screen (the app also has a manual entry field). After scanning,
`approval-list` shows the device as `active`. The phone pins the server
certificate by the fingerprint in the QR code.

Approval flow: needs an agent write that blocks on approval.
**BLOCKER for coordinator (B12, enqueue-script part, still open):** there is no CLI command that enqueues a test
approval request. The only way is an authenticated MCP HTTPS call from an agent
whose profile has `approvalMode: prompt` (`symvault approval list` and
`symvault approval decide <id> --approve|--deny` read and decide the same
queue from the Mac). The coordinator should provide a tested script (token via
`symvault agent token new`, then a `set_entry_field` tools/call over HTTPS with
the headers `Authorization: Bearer <token>`, `X-Symaira-Agent`,
`Content-Type: application/json`, `Accept: application/json, text/event-stream`,
`MCP-Protocol-Version: 2025-11-25`; the end-to-end test
`crates/symvault-cli/tests/approval_e2e.rs` is the reference). Until then
record step 5 as "not run" and pairing (step 4) as the achieved scope.

Stop the server with Ctrl-C when done.

---

## S9. Cleanup

Run in this order. Nothing here touches the real vault.

```sh
S=/private/tmp/symvault-acceptance
# Remove the Touch ID keychain item and cached session for the scratch vault
"$S/sv" auth set passphrase
"$S/sv" lock
# Verify nothing is left in the login keychain for the scratch vault
security find-generic-password -s "symvault-biometric:$S/vault" -a passphrase; echo "exit=$? (44 = not found, good)"
security dump-keychain "$HOME/Library/Keychains/login.keychain-db" 2>/dev/null | grep -c "$S" || true
# Stop anything still running
for f in "$S/mcp.pid" "$S/callback.pid"; do [ -f "$f" ] && kill "$(cat "$f")" 2>/dev/null; done
# Remove the scratch tree (the evidence folder $E is outside it and is kept)
rm -rf "$S"
printf '' | pbcopy
```

Expected: `auth set passphrase` prints `Auth method set to passphrase` (a warning
line is printed if the item could not be removed: record it); the
`find-generic-password` exit is 44; the `grep -c` count is `0`.
If the count is not 0, delete the leftover with `security
delete-generic-password -s '<service>' -a '<account>'` using the service and
account shown by `dump-keychain`.

S1.7 and S6 leave other state: remove the Go worktree with `git -C "$REPO"
worktree remove --force "$S/go-oracle"` **before** `rm -rf "$S"` if you made
one; on the phone delete the app or leave the TestFlight build installed; on
the Mac re-enable "Encrypt local backup" if you turned it off; turn clipboard
history and Universal Clipboard back on; revoke the Accessibility/Automation
grants you added for the terminal if you do not want them permanently
(System Settings, Privacy & Security).

---

## Blocker register for the coordinator

| ID | Step | Missing | Needed before the human runs it |
|---|---|---|---|
| B1 | S0 | Statement of BIN's code signature (ad-hoc, Developer ID, notarized) | `codesign -dv --verbose=4 BIN` output in the handover |
| B2 | S1.7 | Go cgo binary from `legacy/go-oracle`, Go-side command lines | Build (Go 1.26.6, `CGO_ENABLED=1`) and test the Go commands; otherwise record S1.7 as not run |
| B3 | S2.3 | Any shipped path to `Notifier`/`SecureUi` (ADR 0034 items 28/29) | Maintainer decision: implement (option B) or ratify fail-closed (option A) |
| B4 | S3.2 | The `config set agents.cli.*` key set was not executed | Run it once on a throwaway vault and fix the block if it fails |
| B5 | S5.3 | Signed test host for `ApprovalSessionStoreTests` (no test target in `client/project.yml`; unsigned = `-34018`) | Add a hosted test target or a documented device test route |
| B6 | S5.3 | Device-destination `xcodebuild test` for the package scheme never run | Run it on a connected phone once |
| B7 | S5.5 | No AutoFill or share extension target (#870 open) | Build the extension, or accept host-app-only numbers and say so in the matrix |
| B8 | S5.5 | No fixture vault encrypted to the on-device identity, no copy-in route, no harness or signposts | Provide the vault (size stated), the install route, and a measurement test |
| B9 | S5.5 | No numeric memory budget anywhere in the repo | Maintainer states a budget, or FFI-002 stays "measured, recorded" |
| B10 | S6 | `PrivacyInfo.xcprivacy` absent while `UserDefaults` is used | **resolved on local/device-runbook** (manifest added, `plutil -lint` OK); still verify with Xcode's privacy report on the real archive |
| B11 | S6 | `docs/ios-testflight.md` stale (Go-Mobile wording, `Xcode-26.6.app` path); build number / Xcode release status | **resolved on local/device-runbook** (doc updated, build-number note added); human still confirms Xcode is a release and bumps `CURRENT_PROJECT_VERSION` if build 1 was uploaded |
| B12 | S6.3 | `docs/approval-devices.md` says `--bind 0.0.0.0` (Rust refuses wildcard); no CLI to enqueue a test approval request | Doc fix **resolved on local/device-runbook**; the tested enqueue script is still open |

---

## Result record

The coordinator pastes the filled tables into the contract matrix as manual
acceptance. One table per step. Fill every column; write `not run` with the
reason instead of leaving blanks. Pass/fail is against the criteria in that
step; if the observation contradicts an issue acceptance line (for example the
Touch ID dialog naming `osascript` against #1243), write `FAIL` or `FINDING`
and the sentence, do not round up.

Header (once):

| Field | Value |
|---|---|
| Maintainer | |
| Date | |
| Build SHA (git) | |
| BIN path, version, sha256 | |
| BIN signature (`codesign -dv`) | |
| Mac model, macOS version, terminal app | |
| iPhone model, iOS version, Xcode version | |
| Evidence folder | `~/symvault-device-acceptance-evidence` |

S1, SESSION-003 (also #1243, #1034):

| Check | Date | Device/OS | Build SHA | Observation | Pass/fail | Screenshot |
|---|---|---|---|---|---|---|
| S1.1 `auth set touchid` | | | | | | |
| S1.2 item layout and ACL (trusted apps, accessibility attr) | | | | | | `s1-item-acl.txt` |
| S1.3 accept: dialog app name and text, no `security` dialog | | | | | | |
| S1.4 cancel: falls back to passphrase, no session | | | | | | |
| S1.5a wrong finger | | | | | | |
| S1.5b 30 s timeout | | | | | | |
| S1.6 `security -w` cross-binary dialog; copy-binary result | | | | | | |
| S1.7 Go/Rust item interop | | | | | | |

S2, PLATFORM-001 and PLATFORM-002:

| Check | Date | Device/OS | Build SHA | Observation | Pass/fail | Screenshot |
|---|---|---|---|---|---|---|
| S2.1 `get` copy, countdown, clear, Ctrl-C, `--print` | | | | | | |
| S2.2 Automation prompt, Accessibility prompt wording | | | | | | |
| S2.3 secure input and notification (capability probe only; shipped path = BLOCKER B3) | | | | | | |

S3, MCP-003:

| Check | Date | Device/OS | Build SHA | Observation | Pass/fail | Screenshot |
|---|---|---|---|---|---|---|
| S3.1 denied for default profile (both tools, exact messages) | | | | | | |
| S3.3 `copy_to_clipboard` response, T+3s, T+13s, audit row, SIGINT clear | | | | | | |
| S3.4 `autotype` without Accessibility (error text) | | | | | | |
| S3.4 `autotype` with Accessibility (typed text, response, audit) | | | | | | |

S4, HTTP-003:

| Check | Date | Device/OS | Build SHA | Observation | Pass/fail | Screenshot |
|---|---|---|---|---|---|---|
| S4.2 discovery and registration | | | | | | |
| S4.3 consent page content, wrong passphrase, approve | | | | | | |
| S4.4 token exchange and replay | | | | | | |
| S4.5 deny | | | | | | |
| Browser and version | | | | | | |

S5, FFI-001 and FFI-002:

| Check | Date | Device/OS | Build SHA | Observation | Pass/fail | Screenshot |
|---|---|---|---|---|---|---|
| S5.2 app launch, enrol, unlock on device (slice executes) | | | | | | |
| S5.3 `MobileVaultCoreTests` on device | | | | | | |
| S5.3 `ApprovalSessionStoreTests` (BLOCKER B5 if not run) | | | | | | |
| S5.4 xattr on backup dir | | | | | | |
| S5.4 Manifest.db: backup dir absent, control rows present | | | | | | |
| S5.5 peak footprint, unlock latency, vault size, config (Release), tool | | | | | | |

S6, #938:

| Check | Date | Device/OS | Build SHA | Observation | Pass/fail | Screenshot |
|---|---|---|---|---|---|---|
| S6.1 preflight, archive, upload output | | | | | | |
| S6.2 processed build: bundle id, version, build, warnings, compliance, privacy | | | | | | |
| S6.3 install from TestFlight, launch | | | | | | |
| S6.3 enrol, Face ID, camera, local network prompts | | | | | | |
| S6.3 QR pairing, `approval-list` active | | | | | | |
| S6.3 approval flow (BLOCKER B12 if not run) | | | | | | |
| S6.3 logout and failure/retry | | | | | | |

Matrix summary the coordinator writes per row:

| Row | Manual acceptance (date, build SHA, device) | Result | Residual still open |
|---|---|---|---|
| SESSION-003 | | | |
| PLATFORM-001 | | | |
| PLATFORM-002 | | | |
| MCP-003 | | | |
| HTTP-003 | | | |
| FFI-001 | | | |
| FFI-002 | | | |
