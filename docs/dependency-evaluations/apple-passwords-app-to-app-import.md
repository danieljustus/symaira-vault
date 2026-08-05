# Dependency Evaluation: Apple Passwords App-to-App Import & Passkey Portability (macOS 26 Credential Exchange)

**Work Item:** #738
**Date:** 2026-08-05
**Evaluator:** Sisyphus-Junior (autonomous)
**Scope:** Feasibility of `symvault` becoming a **destination** in Apple Passwords' "Export Data to Another App" flow on macOS 26, and of making imported **passkeys** usable rather than inert blobs.

---

## Executive Summary

**Recommendation (a) — import target: DEFER.** The current `client/` shell cannot host the flow today (single app target, no extension, ad-hoc signing, macOS 14.0 deployment target, empty entitlements), and third-party macOS destination maturity is still unproven — as of May 2026, 1Password's CXF support remains iOS/Android-only. Re-evaluate when a major vendor ships macOS import and the client targets macOS 26.

**Recommendation (b) — passkey provider: REJECT.** Poor threat-model fit (serving secrets at rest outside the MCP/LLM surface the model is built around), a new secret-at-rest crypto domain (WebAuthn private keys, ES256 signing, counters, challenge flow), extension signing/passphrase-sharing blockers, and low utility (Apple Account passkeys are not portable). Neither recommendation is "implement", so no follow-up issue is filed; a conditional trigger for (a) is documented below.

---

## Current State of the Client Shell

- `client/Symvault.entitlements` is an **empty `<dict/>`** — no AutoFill or credential-provider capability is declared today.
- `client/` is a single xcodegen app target (`project.yml`); no checked-in `.xcodeproj`; `GENERATE_INFOPLIST_FILE: YES`; **ad-hoc signing** (`CODE_SIGN_IDENTITY: "-"`); hardened runtime; **macOS 14.0 deployment target**; SwiftUI `@main` lifecycle.
- The Go core is embedded and driven via a subprocess contract (`SymairaCLIRunner`).

## What the App-To-App Flow Requires (verified against current Apple docs)

To appear as an export destination in Apple Passwords ("Export Data to Another App"), the app must implement **Credential Exchange**:

- **Entitlement:** `com.apple.developer.authentication-services.autofill-credential-provider` on **both** the host app and a new **AutoFill Credential Provider extension target**.
- **Extension Info.plist:** `ASCredentialProviderExtensionCapabilities` with `SupportsCredentialExchange` = YES and `SupportedCredentialExchangeVersions` = ["1.0"] (the current exchange-specific keys per Apple's documentation).
- **API surface:** `ASCredentialImportManager` (macOS 26.0+), `importCredentials(token:) → ASExportedCredentialData`, `ASCredentialExchangeActivityType` / `ASCredentialImportToken` NSUserActivity handoff (`onContinueUserActivity`).
- **Payload model:** `ASExportedCredentialData` wraps `ASImportableAccount` objects (with `ASImportableScope` and `ASImportableFIDO2*` variants) — the OS performs the CXP/HPKE transport work; the app receives **decrypted, typed** credential data.
- **Real Apple Developer signing** (ad-hoc identity is incompatible — the entitlement cannot be exercised with ad-hoc signatures).
- **macOS 26 deployment minimum.**

### Hand-off to the Go core

Because the OS hands the app typed, decrypted accounts, the bridge into the Go core is a **JSON-serialized account payload** piped into the embedded `symvault` binary via the existing `SymairaCLIRunner` subprocess contract (a new `symvault import` subcommand consuming the CXF-shaped JSON). No CXP/HPKE implementation is needed for the import path (that is #736's file-based path, and it is out of scope here).

## Maturity of the macOS Import Target (as of the spike)

- Apple's "Export Data to Another App" shipped with iOS 26 / macOS 26 (Six Colors, 2025-09-29); it replaces the old CSV export in Apple's own framing.
- Bitwarden (Sept 2025) and Dashlane support the flow; **1Password's May 2026 announcement still describes CXF as "on both iOS and Android" — no macOS destination**, supporting the concern that the macOS third-party import target remains unreliable or under-supported. Apple Developer Forums threads from the planning phase reported the macOS import target not appearing for third-party managers; the spike could not re-verify the forums directly (bot-blocked), so maturity is assessed from vendor/market evidence above.
- `docs/threat-model.md` treats imported data as untrusted (importer hardening, open items O-9 quarantine, F-3/F-4 provenance). An import target fits by extending the existing importer defenses: the new `symvault import` subcommand must route through the same quarantine/provenance pipeline as file-based imports.

## Passkey Portability ("Usable Passkeys")

Storing a passkey as an inert blob (what #736 would do) is the easy half. Making it **usable** means becoming a passkey **provider**:

- A full `ASCredentialProviderViewController` extension (API exists since macOS 11) that serves WebAuthn assertions on demand.
- Storing WebAuthn private keys in the age-vault — a **new crypto domain**: ES256 signing keys, credential counters, challenge/assertion flow, and re-signing considerations.
- An **extension-process passphrase/Keychain-sharing problem**: the credential-provider extension runs in a separate process and would need a way to unlock the vault (Keychain-shared item or a passphrase handshake) — a materially new security surface.
- **Utility caveat:** Apple Account passkeys are **not portable** (Six Colors), limiting the value of the passkeys that can actually be transferred.
- Threat-model fit is poor: `docs/threat-model.md` is built around keeping secrets away from agent surfaces; a passkey provider must *serve* secrets at rest on demand, in a new process, outside the MCP/LLM surface the model governs.

## Recommendation Details

### (a) Import-only target — DEFER

Required before any implementation: macOS 26 deployment bump, a new credential-provider extension target, the autofill entitlement on both targets, real Apple Developer signing, `onContinueUserActivity` handling in `SymvaultApp`, a new Go import subcommand with quarantine/provenance, and **proof that the macOS import target reliably appears for third-party apps on a current build**.

**Revisit trigger:** a major password manager ships macOS Credential Exchange import AND the client moves to macOS 26 with real signing. When that happens, file a scoped implementation issue (extension target + entitlement + `symvault import` CXF-JSON subcommand reusing #736's parsing).

### (b) Full passkey provider — REJECT

Poor threat-model fit, new secret-at-rest crypto surface, extension signing/passphrase blockers, low utility. Do not schedule.

---

## Out of Scope (confirmed)

- CXP transport / HPKE internals beyond what the OS hands the extension.
- iOS (the shell is macOS-only today).
- File-based CXF parsing — that is #736 and needs no Apple entitlement.
