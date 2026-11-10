# Device acceptance result record, 2026-11-10

Runbook: `docs/rust-port/device-acceptance.md`. Driven by an automation agent
on the maintainer's MacBook; every touch, click and typed value in a
dialog or browser was done by the maintainer (Daniel Justus), and the
observations marked "maintainer" are his answers. Evidence files (screenshots, command
output) stay in the maintainer's evidence folder named below; this record is
the repository copy.

| Field | Value |
|---|---|
| Maintainer | Daniel Justus |
| Date | 2026-11-10 |
| Build SHA (git) | `9e28b01e620e8ce832c892618e8c9690e7a445b1` (tag `v0.24.0-rc.1`) |
| BIN path, version, sha256 | published release asset `symaira-vault_0.24.0-rc.1_darwin_arm64.tar.gz`, unpacked; `symvault 0.24.0-rc.1`; `d99d5a76893abcca6d848a2905322a5c2749a80c049d52eaefec757a65262e63` |
| BIN signature (`codesign -dv`) | Developer ID Application: Daniel Justus (M4744F3TAA), hardened runtime 15.5.0, CDHash `b996484728b87195ce17ad34b0d3b9c3cf2c6eaa`, notarized (`spctl`: Notarized Developer ID) (closes blocker B1) |
| Mac model, macOS version, terminal app | MacBook Pro Mac16,8 (M4 Pro), macOS 27.2.1 (26B131); responsible process: the automation agent's desktop app |
| iPhone model, iOS version, Xcode version | iPhone 17 (iPhone18,3), Xcode 27.2 (27B52) |
| Evidence folder | `/Volumes/1TB_NVMe_SN850X/Dev/evidence/symaira-vault/device-acceptance-20261110` |

## S1, SESSION-003 (also #1243, #1034)

| Check | Observation | Pass/fail | Evidence |
|---|---|---|---|
| S1.1 `auth set touchid` | `Auth method set to touchid`, no dialog | PASS | `s1.1-auth-set.txt` |
| S1.2 item layout and ACL | one `genp` item in the login keychain, svce/acct `symvault-biometric:/private/tmp/symvault-acceptance/vault` / `passphrase`; no `accessibility` attribute shown; `dump-keychain -a` printed no ACL section for the item (not readable this way) | PASS (finding: ACL not observable via dump-keychain) | `s1.2-item.txt`, `s1-item-acl.txt` |
| S1.3 accept | Touch ID dialog, app name `osascript` (maintainer), text per S1.4 screenshot; touch: `unlock` exit 0 in 2.4 s, no passphrase prompt, `Session active`, `list` = `scratch/login` without prompt; no keychain dialog (maintainer) | PASS; FINDING against #1243 wording: the biometric dialog names `osascript`, not SymVault | `s1.3-accept.json` |
| S1.4 cancel | dialog: „„osascript“ möchte Unlock Symaira Vault vault. Verwende Touch ID oder gib dein Passwort ein, um mit „osascript“ fortzufahren.“, buttons „Passwort verwenden …“ / „Abbrechen“; Abbrechen: passphrase prompt after 4.3 s, no session (`unlock --check` exit 4) | PASS | `s1.4-cancel.json`, `s1.4-cancel.png` |
| S1.5a wrong finger | dialog closed itself after a few failures (maintainer); passphrase prompt after 4.5 s, no session | PASS | `s1.5a-wrong-finger.json` |
| S1.5b 30 s timeout | passphrase prompt after 30.2 s, dialog disappeared (maintainer), no session | PASS | `s1.5b-timeout.json` |
| S1.6 `security -w` cross-binary | keychain dialog: „security möchte deine vertraulichen Informationen verwenden, die in „symvault-biometric:/private/tmp/symvault-acceptance/vault“ … gesichert sind“, denied; exit 128 after 3.7 s, no secret printed. Copy-binary branch not run | PASS | `s1.6-security-read.png`, `s1.6-result.txt` |
| #1243 fix, native `LAContext` (local build of branch `local/device-acceptance-20261110`, ad-hoc signed, separate scratch vault) | dialog: „„symvault“ möchte Unlock Symaira Vault vault. Verwende Touch ID oder gib dein Passwort ein, um mit „symvault“ fortzufahren.“; accept: exit 0 in 3.9 s, `Session active`, no keychain dialog noticed (maintainer); cancel: passphrase prompt after 3.3 s, no session; timeout: prompt dismissed by `invalidate`, passphrase prompt after 30.4 s, dialog gone (screenshot) | PASS, FINDING resolved | `native-accept.png`, `native-*.json`, `native-timeout-after.png` |
| S1.7 Go/Rust item interop | not run: Go removed (#1257, ADR 0036), B2 | not run | |
| #1034 MCP stdio after repair | one Touch ID unlock, then two `mcp --stdio` starts with the real keychain wrapper: `list_entries` answered in <= 1 s each, no keychain or Touch ID dialog (maintainer) | PASS | `s1034-mcp.txt` |

## S2, PLATFORM-001 and PLATFORM-002

| Check | Observation | Pass/fail | Evidence |
|---|---|---|---|
| S2.1 `get` copy, countdown, clear | `[copied to clipboard]`, `[clearing clipboard in 10s]` .. `0s`, `[clipboard cleared]`, exit 0; pasteboard `before` → T+3s/T+6s `Sx-Test-Pw-4711` → empty; no clipboard-history warning (Pure Paste running, no effect) | PASS | `s2.1-get-autoclear.json` |
| S2.1 Ctrl-C | SIGINT at 4 s: `[clipboard cleared]` at once, exit 0, pasteboard empty | PASS | `s2.1-ctrl-c.json` |
| S2.1 `--print` | prints the value, pasteboard still `before` | PASS | `s2.1-print.txt` |
| S2.2 Automation prompt | no prompt (already granted to the agent's desktop app); System Events answered `alfaview` | PASS (prompt not observable, grant pre-existing) | `s2.2-automation.txt` |
| S2.3 secure input and notification | host capability probe only: notification from Script Editor/osascript delivered (maintainer); masked dialog, typed `probe` returned `probe`, exit 0. Shipped path: ADR 0034 item 28/29 ratified fail closed (B3 resolved as option A) | not applicable through the binary; probe PASS | `s2.3-dialog.txt` |

## S3, MCP-003

| Check | Observation | Pass/fail | Evidence |
|---|---|---|---|
| S3.1 denied for default profile | JSON-RPC error -32603 `autotype operations not permitted for this agent` / `clipboard operations not permitted for this agent`, nothing typed | PASS | `s3.1-*-denied.json` |
| S3.2 enable | `config set agents.cli.canUseClipboard/canUseAutotype true`, get `true`/`true`, validate clean (closes B4) | PASS | |
| S3.3 `copy_to_clipboard` | response `{"success": true}`, password in 0 response lines; T+3s `Sx-Test-Pw-4711`, T+13s empty; audit rows present; SIGINT at T+3s clears, exit 0 | PASS | `s3.3.stdout`, `s3.3.stderr`, `s3.3-sigint.txt`, `s3-audit.txt` |
| S3.4 without Accessibility | not observable: Accessibility already granted to the responsible process (no prompt) | not run | |
| S3.4 with Accessibility | TextEdit document `autotype-target.txt` shows exactly `Sx-Test-Pw-4711` once; response `{"success": true}` without the password; audit row. Finding: run 1 with no TextEdit window open (the coordinator lacked Apple Events access to TextEdit) also answered `success` while nothing visible received the text | PASS (finding noted) | `s3.4-autotype-run2.json/.png`, `s3.4-autotype-run1.json` |
| Audit log | 6 rows (`autotype`/`copy_to_clipboard`), test password absent from the log | PASS | `s3-audit.txt` |

## S4, HTTP-003

| Check | Observation | Pass/fail | Evidence |
|---|---|---|---|
| S4.2 discovery and registration | metadata lists authorization/token/registration endpoints, `code_challenge_methods_supported: ["S256"]`; 32-hex `client_id` | PASS | `s4.2-metadata.json` |
| S4.3 consent page | Safari „Nicht sicher — 127.0.0.1“ (self-signed, accepted by maintainer); page "Authorize MCP client", `Client: ba5f…3558`, `Redirect URI: http://127.0.0.1:4321/callback`, `Agent: cli`, "This client requests full access to this agent's tools.", field "Vault passphrase", Approve/Deny; `wrong` → "Incorrect passphrase.", no redirect; scratch passphrase → redirect with `code` and `state=acceptance-state` | PASS | `s4.3-consent.png`, `s4.3-wrong-passphrase.png`, `s4.4-callback.txt` |
| S4.4 token exchange and replay | first exchange: `token_type: Bearer`, `expires_in: 86400`, access and refresh token keys; replay: HTTP 400 `{"error":"invalid_grant"}` | PASS | `s4.4-exchange.txt` |
| S4.5 deny | redirect `error=access_denied&state=deny-state` | PASS | `s4.5-deny.txt` |
| S4.6 stop | server exits 0 on SIGINT | PASS | `s4.6-stop.txt` |
| Browser and version | Safari 27.2 | | |
| Side observation | a freshly initialised vault prints `WARNING: legacy MCP token migrated to scoped registry with wildcard (*) tool access` on the first HTTP start | FINDING | `s4.6-stop.txt` |

## Matrix summary

| Row | Manual acceptance | Result | Residual still open |
|---|---|---|---|
| SESSION-003 | 2026-11-10, v0.24.0-rc.1 (9e28b01e) plus native LAContext fix, MacBook Pro M4 Pro macOS 27.2.1 | PASS | S1.7 not run (Go removed); re-check the dialog name on the next notarized release |
| PLATFORM-001 | same | PASS | autotype "denied Accessibility" branch not observable on this Mac |
| PLATFORM-002 | same | PASS for the ratified scope (ADR 0034 item 28/29 fail closed) | none for the binary |
| MCP-003 | same | PASS | |
| HTTP-003 | same, Safari 27.2 | PASS | |
| FFI-001 | 2026-11-10, branch build, iPhone 17 (iPhone18,3), Xcode 27.2 | PASS after fix (vault open EPERM on device, store fix) | S5.4 backup manifest, S6 TestFlight |
| FFI-002 | | not run | S5.5 blockers B7 to B9 |

## S5, FFI-001 (2026-11-10)

| Check | Observation | Pass/fail | Evidence |
|---|---|---|---|
| S5.2 launch, enrol, unlock | Release build of 88b4749d signed for team M4744F3TAA installed via devicectl; app launches, Enrol ok (`deviceEnrolled = true` in the container), Face ID prompt names Symaira Vault, empty entry list without error (maintainer) | PASS (the empty list hid the open bug below) | `s5-install.txt`, `s5-launch.txt`, `s5-container/prefs.plist` |
| S5.3 tests on device | package scheme refuses device destinations (tool-hosted); new hosted target `SymvaultIOSAppTests`. On 88b4749d: 26/28, `testInitOpenReadListVerify` and `testBackupDirectoryIsExcludedFromBackupAndUsedByTheDataSafetyGate` fail with `failed to read <vault>: Operation not permitted (os error 1)`. Cause: per-component `openat` walk from `/` needs read access on container ancestors. After the store fix: 28/28 (7 XCTest incl. all MobileVaultCoreTests, 21 Swift Testing incl. ApprovalSessionStoreTests with the real keychain) | PASS after fix (closes B5, B6) | `s5-iostests-device.log`, `s5-iostests-device-fixed.log`, `s5-probe2.log` |
| S5.4 backup exclusion | not run by maintainer decision (2026-11-10): the on-device test `testBackupDirectoryIsExcludedFromBackupAndUsedByTheDataSafetyGate` sets and reads back `isExcludedFromBackup` (pass, 28/28); whether iOS honours it in a real backup stays unverified | waived | `s5-iostests-device-fixed.log` |
| S5.5 memory | not run: B7 to B9 | not run | |
