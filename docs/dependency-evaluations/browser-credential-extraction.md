# Dependency Evaluation: Direct Browser Credential Extraction (Chrome/Firefox) as Import Source

**Work Item:** #737
**Date:** 2026-08-05
**Evaluator:** Sisyphus-Junior (autonomous)
**Scope:** Feasibility of `symvault import chrome` / `symvault import firefox` reading a locally installed browser's credential store directly, under the repo's no-CGO build constraint.

---

## Executive Summary

**Recommendation: DEFER — keep CSV-export import (#735) as the supported path; re-evaluate when Chrome ships app-bound encryption to macOS or the import-quarantine backlog lands.**

Direct extraction is technically feasible on current macOS without CGO for both browsers, but it is not advisable to ship today: the Keychain-prompt UX for an unsigned CLI is a real user-facing defect (the OS does not persist "Always Allow" for unsigned binaries, so every run re-prompts), and `docs/threat-model.md` classes imported data as an untrusted prompt-injection vector while the quarantine/provenance backlog (O-9, F-4) is still open. Both browsers already ship a CSV export that is now supported by #735, so the one-command benefit is convenience, not capability.

---

## Chrome / Chromium (macOS)

### Store location and format

- **Database:** `~/Library/Application Support/Google/Chrome/<Profile>/Login Data` (SQLite), table `logins` with `origin_url`, `username_value`, `password_value`.
- **Key:** macOS Keychain item service `Chrome Safe Storage`, account `Chrome` (Chromium: `Chromium Safe Storage` / `Chromium`).
- **Encryption scheme (verified against current Chromium `main`):** AES-128-CBC; key = PBKDF2-HMAC-SHA1(password = Keychain value, salt = `saltysalt`, 1003 iterations, 16-byte key); ciphertext carries the `v10` version prefix.
  - Source: `components/os_crypt/async/browser/keychain_key_provider.mm` and `keychain_password_mac.mm` via googlesource API.
- **App-bound encryption (v20):** introduced in Chrome 127+ as a **Windows-only** DPAPI replacement (`elevation_service.exe`). It does **not** apply to macOS as of current builds — macOS extraction remains possible with the v10 scheme.

### Feasibility under no-CGO

- **Yes.** Reading the SQLite file requires a pure-Go driver (`modernc.org/sqlite`, BSD-3-Clause — already the pattern used elsewhere) and the Keychain item is read via `security find-generic-password`, which `go-keyring` (already a repo dependency, Apache-2.0) wraps. Decryption uses stdlib `crypto/aes` + `crypto/pbkdf2`-equivalent from `golang.org/x/crypto` (already a dependency).
- No CGO, no GPL code involved.

### User-facing prompt UX (critical finding)

- Users see a native macOS modal: *"Google Chrome wants to use your confidential information stored in 'Chrome Safe Storage' in your keychain. Do you want to allow access to this item?"* with **Always Allow / Allow Once / Deny**.
- **Verified defect for unsigned CLIs:** invoking `/usr/bin/security find-generic-password -s "Chrome Safe Storage"` from an unsigned binary does **not** persist "Always Allow" (reported against macOS 26, e.g. xiufengsun/TokenTracker#369) — the prompt returns on **every run**. `go-keyring` uses exactly this invocation, so symvault would hit this directly.
- Chrome itself never prompts because Chrome is properly code-signed. A signed symvault build (notarized, per `docs/macos-notarization.md`) would likely persist the grant — but the current development builds are unsigned.

---

## Firefox (macOS)

### Store location and format

- **Database:** `~/Library/Application Support/Firefox/Profiles/<profile>/logins.json` + `key4.db` (NSS SQLite).
  - `key4.db` `metadata` table: global salt.
  - `nssPrivate.a11`: encrypted master key.
- **Encryption scheme (cross-verified against gecko-dev and MIT reference implementations):** PBES2 ASN.1 (OID 1.2.840.113549.1.5.13), PBKDF2-HMAC-SHA256 → AES-256-CBC for the master key; login fields base64 with `v10` magic (16-byte keyID + 12-byte IV + AES-GCM) in modern Firefox, legacy ASN.1 3DES-CBC for old entries.
- **Primary password:** if set, it gates `key4.db` and requires a CLI prompt (plain hidden-input prompt, not an OS dialog).

### Feasibility under no-CGO

- **Yes, but only via a fresh pure-Go reimplementation.**
  - `github.com/rusq/gonss3` (the canonical pure-Go NSS subset) is **LGPL-3.0** and depends on CGO sqlite (`mattn/go-sqlite3`) — **double-blocked**: LGPL static-linking into an Apache-2.0 binary forces LGPL on the whole binary, and CGO breaks the no-CGO constraint.
  - A license-clean path exists: `modernc.org/sqlite` (BSD-3-Clause, pure Go) + an MIT-licensed reference (e.g. Sohimaster/Firefox-Passwords-Decryptor) ⇒ ~300 LOC reimplementation.
  - Maintenance cost is non-trivial: NSS format changes across Firefox releases must be tracked.

### User-facing prompt UX

- **Primary password set:** plain hidden-input CLI prompt (no OS dialog). Acceptable UX.
- **No primary password:** silent decryption, no prompt.

---

## Threat-model fit

`docs/threat-model.md` §2 classes imported data as an **untrusted prompt-injection vector**; the import pipeline is expected to quarantine/annotate provenance before agent-visible data enters the vault. Direct browser import lands whole untrusted profiles into the vault with **one command** while the quarantine (O-9) and provenance (F-3/F-4) backlog items remain open. The existing file-based importers at least require the user to consciously produce an export file; direct reads lower that friction to near zero.

---

## Recommendation

**DEFER** for both browsers:

1. **Keychain prompt-loop UX** for unsigned CLIs makes Chrome extraction a poor experience today. Would need signed/notarized builds (see `docs/macos-notarization.md`) or a `security` invocation that persists grants — neither is a quick fix.
2. **Threat-model tension:** importing untrusted browser stores wholesale conflicts with the still-open quarantine/provenance work; land O-9/F-4 first.
3. **Convenience, not capability:** Chrome and Firefox both ship CSV export, already supported via #735 (profiles for both, header-sniffed). Users lose the plaintext-CSV-on-disk downside, but the security trade-off of direct reads (full untrusted profile ingested in one command, unsigned-CLI keychain prompts) does not justify it yet.
4. **Firefox licensing:** the only viable pure-Go NSS implementation requires a fresh LGPL-clean reimplementation (~300 LOC) with ongoing maintenance against Firefox format changes — a real cost for a deferred convenience feature.

**Revisit triggers:**
- Chrome ships app-bound encryption (v20-style) to macOS, which would make extraction infeasible or brittle and should be re-checked before any implementation starts.
- O-9 import quarantine lands, making wholesale untrusted ingestion safe by default.
- A signed/notarized distribution makes the Keychain "Always Allow" grant persist.

**License compatibility note:** no GPL/LGPL code is proposed for bundling; the pure-Go path (modernc.org/sqlite BSD-3-Clause, MIT reference implementation) is Apache-2.0-compatible.

---

## Follow-up

None scheduled. #735 (CSV profiles incl. Chrome and Firefox) covers the migration path for both browsers today. `docs/migration.md` now states plainly that direct browser import is unsupported.
