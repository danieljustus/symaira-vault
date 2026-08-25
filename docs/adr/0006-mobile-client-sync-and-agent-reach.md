# ADR 0006: Mobile Client, Sync Substrate, and Agent Reach

**Date:** 2026-08-25
**Status:** Proposed
**Author:** Symaira Vault Team

## Context

Symaira Vault today is a CLI plus a native macOS client. The macOS client
embeds the `symvault` binary in its app bundle and shells out to it
(`client/project.yml`, `postBuildScripts`). Vault identity is an age X25519
keypair in `identity.age`, protected by a passphrase at the argon2id layer.
There are no user accounts and no hosted service; `docs/commercial-boundary.md`
records that none is planned.

Three goals motivate this ADR:

1. Symaira Vault should work as an ordinary credential manager on iPhone,
   including system AutoFill, with Mac↔iPhone sync — comparable in reach to
   Apple's Passwords app.
2. The consumer-facing LLM apps (Claude, ChatGPT, Gemini) on iOS should be able
   to reach the vault in some safe form.
3. The project should have a defensible long-term shape for non-developer users
   and for organisations, without contradicting the local-first positioning that
   `docs/research-handoff-eu-commercialization.md` names as its strongest
   differentiator.

This ADR records the architecture decisions and, equally important, the
constraints that were verified against the codebase rather than assumed.

## Verified Findings

These were checked against the repository and toolchain on 2026-08-25. They
constrain every decision below.

### F1 — `internal/crypto` is already mobile-portable

`GOWORK=off go list -deps ./internal/crypto` yields only `filippo.io/age`,
`filippo.io/hpke`, `corekit/fsutil`, `internal/fsutil`, and
`golang.org/x/sys/unix`. No `os/exec`, no terminal, no keyring. Both
`./internal/crypto` and `./internal/vault` cross-compile cleanly under
`CGO_ENABLED=0 GOOS=ios GOARCH=arm64`.

### F2 — `internal/vault` is entangled with desktop-only packages, but only in five files

The dependency tail of `internal/vault` includes `os/exec`,
`golang.org/x/term`, the charmbracelet/lipgloss stack, the Prometheus client
stack, and go-git with `ProtonMail/go-crypto` and `cloudflare/circl`. None of
that belongs in an iOS app, and `os/exec` is unusable on iOS at all. The
entanglement is narrow and localised:

| Unwanted dependency | Reached via | Files |
|---|---|---|
| `os/exec` | `internal/git` | `internal/git/git_push.go`, `internal/git/git_util.go` |
| `internal/git` | `internal/vault` | `internal/vault/vault.go` |
| `internal/metrics` | `internal/vault` | `internal/vault/entry_readwrite.go`, `internal/vault/search.go` |
| `internal/ui/cliout`, `internal/ui/theme` | `internal/config` | `internal/config/config_load.go`, `internal/config/config_merge.go` |

No non-test file in `internal/vault` imports `internal/ui/*` directly. The
mobile-relevant subset of `internal/vault` (`entry.go`, `entry_readwrite.go`,
`entry_validate.go`, `recipients.go`, `manifest.go`, `devices.go`,
`search_index.go`) is ~2,900 of the package's ~6,600 non-test lines.

### F3 — Device enrolment already exists and already has the right shape

`cmd/device.go` implements `pair` / `join` / `accept` / `revoke`.
`device join` calls `cryptopkg.GenerateIdentity()`, so **a joining device gets
its own keypair and its own passphrase**; the master identity never leaves the
originating device. `device accept` adds the joining public key to the
recipients and re-encrypts; `device revoke` removes it and re-encrypts.
`internal/vault/devices.go` keeps a registry of `Name`, `PublicKey`, `AddedAt`,
`LastSeen`.

The handshake is currently git-transport-bound: `device join` takes a
`<remote-url>` and performs `gogit.PlainClone`.

### F4 — Manifest integrity already covers the "user touched the folder" case

`internal/vault/manifest.go` provides `VerifyManifestIntegrity` and
`DetectOutOfBandEntries`. This is directly relevant to choosing a sync
substrate whose files are visible and mutable by the user.

### F5 — Hosted LLM connectors dial in from vendor cloud, not from the phone

Claude for iOS and Android support remote MCP servers, but servers cannot be
added from the mobile app — they are configured on claude.ai and synced to the
mobile clients. Critically, Claude connects to a custom connector **from
Anthropic's cloud infrastructure, not from the user's device**, on every client
including mobile. Claude supports the MCP auth specs of 2025-03-26 and
2025-06-18 (OAuth), not a bare bearer token.

Consequence: an MCP endpoint intended for the Claude iOS app must be reachable
from the public internet. A private Tailscale tailnet is insufficient; it would
require Tailscale Funnel, a Cloudflare Tunnel, or equivalent public exposure.
ChatGPT's connector model is believed to work the same way, but was not
verified for this ADR. Gemini's consumer app does not accept arbitrary MCP
endpoints.

### F6 — Toolchain gap

`gomobile` is not installed and only Xcode Command Line Tools are present, so
no iOS SDK is available on this machine. The `gomobile bind` feasibility test
therefore remains open (see Open Questions). Independent of that,
`gomobile bind` supports a restricted type set at the language boundary and
does not bridge `map[string]any` — and `vault.Entry.Data` is exactly that
(`internal/vault/entry.go:18`).

### F7 — Existing documentation is stale or self-contradictory

- `docs/macos-notarization.md` states "Status: BLOCKED — Apple Developer ID
  Required". A paid Apple Developer account exists; team `M4744F3TAA` is
  already wired into `symaira-terminal/project.yml:49`. The blocker is gone.
- `docs/research-handoff-eu-commercialization.md` states both "there is no Pro
  edition and no hosted counterpart" and, further down, "hosted MFA enforcement
  belongs to Pro" and "Pro has its own private service layer". These are
  pre-decision leftovers and must not be used as planning input.

## Decisions

### D1 — Identity stays cryptographic; the Apple account is transport only

Vault has no user accounts and will not gain any. Identity is possession of an
age keypair. The iPhone is enrolled as a **device with its own keypair** via
the existing `pair` / `join` / `accept` flow (F3), not by copying the master
identity.

Two layers are kept strictly separate:

| Layer | Bound to | Sees plaintext |
|---|---|---|
| Identity — who can decrypt | age keypair + per-device passphrase | — |
| Transport — where ciphertext travels | Apple account (iCloud) | No |

Consequences:

- Losing the Apple account loses the sync channel, not the vault. The Mac copy
  and the git history are unaffected.
- Compromising the Apple account yields `.age` blobs without keys, and does not
  by itself enrol a device, because `device accept` runs on the Mac.
- Losing the phone is handled by `device revoke <name>` plus re-encryption.
  This protects future state only; anything the device already decrypted is
  already out. Real loss requires rotation, not just revocation.

**Rejected:** shipping `identity.age` through the same iCloud container so the
app can unlock with the master passphrase alone. It is the shortest path to a
working app, and it collapses the security model to a single factor — key
material and ciphertext would sit in one Apple account. The device model makes
this shortcut unnecessary.

**Required work:** a non-git handshake. `device join` currently clones a git
remote (F3), which the iOS app will not do. The pairing response (the joining
device's public key) must travel over the iCloud container or a QR exchange
instead. `device accept` must display the fingerprint of the joining key so it
can be compared against what the phone shows — this is the human gate that
prevents an attacker holding the Apple account from enrolling a device.

### D2 — Extract a mobile core rather than wrapping `internal/vault`

F2 makes the shape clear: `internal/crypto` can be used as-is; `internal/vault`
cannot, because it transitively requires `os/exec`. The mobile core is an
extraction of the entry, recipient, manifest, and device logic with the git,
metrics, and terminal-UI dependencies made injectable or excluded. Per F2 this
is five files to decouple, not a rewrite.

The bridge between Go and Swift uses JSON, not native types, because
`gomobile bind` cannot express `Entry.Data` (F6).

**Explicitly out of the mobile core:** go-git. On iOS, sync is D3, so go-git has
no caller there, and dropping it also drops `ProtonMail/go-crypto` and
`cloudflare/circl` from the mobile binary.

### D3 — iCloud for sync; `.git` stays on the Mac

The `entries/` layout is a good fit: each `.age` file is self-contained, so
conflicts are per-entry rather than per-vault, and `EntryMetadata.Version`
gives a last-writer-wins rule with conflict copies. `identity.age` may sync —
it is passphrase-protected — but under D1 the phone does not need it.

iCloud Drive is chosen over CloudKit for one decisive reason: the Go CLI can
write to an iCloud Drive path with no Apple framework integration at all,
keeping the CLI as the source of truth. CloudKit would require a Swift helper
process on the Mac purely to act as a sync agent. The cost of iCloud Drive is
that the files are user-visible and user-mutable — which is precisely what F4's
`VerifyManifestIntegrity` and `DetectOutOfBandEntries` already detect.

**`.git` must not live inside the iCloud folder.** A git repository inside
iCloud Drive is a known failure mode. The working tree can be in iCloud while
the git directory is not, via a separate-git-dir layout; whether go-git
supports that cleanly is an open question below.

### D4 — AutoFill requires an entry-level URL convention

`ASCredentialIdentityStore` is populated by the app or extension while it has
access, and the system then offers matches above the keyboard. This requires a
service identifier per credential. `vault.Entry` has no URL field; `Data` is a
free-form `map[string]any` (`internal/vault/entry.go:18`), so a documented
`url` key convention is the least invasive route, with the identity store
populated after unlock.

An unencrypted metadata sidecar to speed up lookup is **rejected**: it would
disclose which services the user holds accounts with, which is exactly the
metadata the file-level encryption is meant to protect. If the extension needs
its own fast index, it must be an encrypted blob decrypted after unlock.

Passkeys are **out of scope** for the first release. They are a separate and
substantially larger surface.

### D5 — One crypto implementation, chosen after measurement

An earlier draft of this design proposed a Go core for the app plus a
Swift/CryptoKit decrypt-only path for the AutoFill extension, on the assumption
that a Go runtime would not fit the extension's memory budget.

**That recommendation is withdrawn as the default.** Two independent
implementations of the same crypto format, in a product whose entire value is
credential security, is a bad trade: it doubles the audit surface and invites
silent format drift. iOS app extensions do run under a materially tighter
memory budget than the host app, but the actual figure for a credential
provider extension must be measured, not assumed.

The decision is therefore sequenced: build the Go core, measure the extension,
and only introduce a second implementation if the measurement forces it. If it
does, the two implementations must be pinned to a shared test-vector corpus
checked into this repository.

### D6 — The phone is an approval device before it is an agent gateway

`internal/policy/authorizer.go` has `RequiresApproval()`, and approval mode
`prompt` currently degrades to `deny` because no stdin is available to an MCP
server (`ARCHITECTURE.md`, MCP Security). The iOS app closes that gap: an agent
requests a credential, the phone prompts, Face ID approves, and the broker
attaches the secret to the outbound request server-side without the value
entering the model's context.

Push via APNs works for a self-built install (the Mac can talk to
`api.push.apple.com` directly with a JWT, requiring no server and violating no
boundary), but the APNs auth key cannot be committed to an Apache-2.0
repository, so it does not generalise to other users of this project. Push is
therefore an enhancement, not a prerequisite: when the user initiated the agent
run, a pull model — open the app, see pending requests — is adequate.

### D7 — Exposing an MCP endpoint to hosted LLM apps is deferred, and constrained if built

F5 changes the character of this feature. Because Anthropic's cloud dials the
connector, the endpoint cannot be kept inside a private tailnet: it must be
publicly reachable, and it must speak OAuth rather than the vault's bearer
token. For a password manager, putting a vault-backed endpoint on the public
internet is a significant posture change and is not justified by the current
benefit.

This is deferred. If it is built, it is constrained to:

- read-only, with `CanWrite: false`;
- metadata and handles only, never secret values — the existing redaction
  contract in `docs/agent-integration.md`;
- its own agent scope with a narrow `allowedPaths`, never the default agent;
- D6 approval as a precondition for anything beyond metadata.

Gemini is out of reach and no work should be planned for it.

### D8 — No hosted sync service; commercial work, if any, is BYO-infrastructure

D3 already answers the reach question for non-developer users: Apple operates
the sync, the project operates nothing. A hosted service would buy
cross-platform sync, web access, and account recovery, at the cost of becoming
custodian of third-party secrets — GDPR controller duties, breach notification,
availability expectations, key management, and on-call — and it would directly
contradict the local-first, zero-telemetry positioning that the project's own
research names as its primary differentiator.

For organisations, the primitives already exist: `RecipientsManager.AddRecipient`
and `RemoveRecipient`, `internal/vault/reencrypt.go`, `cmd/share.go` with
`policy.ShareStore`, the authorizer, and `cmd/sync.go` / `cmd/remote.go`. A team
can run Vault against a private git remote today. The honest limits are that
age plus git distributes secrets but cannot retract them (offboarding means
rotation), that policy is client-side and therefore advisory against a
determined insider, and that there is no cross-member audit aggregation.

If those gaps are ever closed commercially, it must be **without hosting**: the
customer runs the git remote they already have, and the product is a licence,
not an operation.

**Boundary conflict to resolve first.** `docs/commercial-boundary.md` forbids
billing and tenant code in this repository and requires that it never become a
feature-limited client. A licensed team layer therefore cannot live here as a
gated feature; it would have to be a separate product with the public core
remaining complete. Any such move must revise `commercial-boundary.md`
deliberately rather than arriving as drift.

## Consequences

Positive:

- No accounts, no hosted service, no new custodial risk.
- Device revocation, team membership, and phone enrolment collapse into one
  concept: an age recipient.
- Apple sees only ciphertext; the failure modes of a lost or compromised Apple
  account are bounded and stated.
- The mobile core extraction (D2) also improves the desktop codebase by
  decoupling `internal/vault` and `internal/config` from terminal UI, metrics,
  and git.

Negative or accepted:

- A second client platform to maintain, with a Go/Swift bridge and its JSON
  boundary.
- iCloud Drive files are user-mutable; integrity depends on manifest
  verification actually being run on load.
- Sync is Apple-only. Android, Windows, and Linux users keep the git path.
- Revocation remains rotation-based.
- iOS AutoFill and the app cannot ship the CLI's execution surface — `run`,
  `broker`, and command policy have no iOS counterpart.

## Implementation Order

1. Decouple the five files in F2; add a headless build target for the core.
2. Add the `url` key convention (D4) and the encrypted AutoFill index.
3. iOS app, read-only first, mirroring the SymBrainMobile precedent.
4. Non-git pairing handshake plus fingerprint display in `device accept` (D1).
5. iCloud Drive sync with manifest verification on load (D3).
6. AutoFill credential provider extension; measure memory, then settle D5.
7. Approval device (D6).
8. Everything else only on concrete demand.

Note that symaira-appkit declares no iOS platform
(`symaira-vibecoder/client/project.yml`: "appkit declares no iOS platform yet;
do NOT add appkit products to the iOS targets"), while the workspace `AGENTS.md`
forbids hand-rolled per-tool client apps. Step 3 therefore depends on extending
symaira-appkit to iOS. A second consumer for that work already exists in
`Symvibe-iOS`.

## Open Questions

1. **`gomobile bind` against this dependency set.** Untestable here (F6): no
   iOS SDK. Must be run before step 1 is scheduled, because a negative result
   changes D2 and D5 together.
2. **Credential provider extension memory budget.** Settles D5. Must be
   measured on a real device, not inferred.
3. **Separate-git-dir support in go-git.** Determines whether D3's "working
   tree in iCloud, git directory outside" layout is achievable without shelling
   out to git — which iOS cannot do anyway, but the Mac can.
4. **ChatGPT connector reachability.** Assumed to match F5, not verified.

## Follow-up Documentation Fixes

- Clear the stale blocker in `docs/macos-notarization.md` (F7). Vault releases
  can be notarised now, independently of anything in this ADR.
- Remove the Pro-edition contradictions from
  `docs/research-handoff-eu-commercialization.md` (F7) so the file cannot be
  read as endorsing a strategy that was abandoned.

## Related

- `docs/commercial-boundary.md` — the boundary D8 must not cross silently
- `docs/agent-integration.md` — the handle/redaction contract D7 relies on
- `docs/threat-model.md`, `SECURITY.md`
- `docs/adr/0005-post-quantum-transition-plan.md` — recipient-format evolution
  interacts with D1's per-device keypairs
