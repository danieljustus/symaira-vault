# Next slice — `device approval-list` + `device approval-revoke`

Scope spec, measured on `09961118` (after PR #1100). Repo
`danieljustus/symaira-vault`. Two of the 37 remaining missing oracle CLI paths.

## Why these two and not all three

- `approval-list` and `approval-revoke` (`cmd/device_approval.go:192-292`) are
  file-backed, offline and byte-comparable.
- `approval-pair` (`cmd/device_approval.go:41-119`) is **not** merely a QR
  rendering question, as was first assumed here: measured, it calls the
  already-running `symvault serve` over `https://127.0.0.1:<port>` with the
  enrollment secret from `serverbootstrap.EnsureEnrollSecret(vaultDir)`
  (`mintApprovalEnrollCode`) **and** renders a QR code
  (`ui.RenderQRCodeForWidth`) with the LAN addresses. Both are their own
  dependency/platform decision. Deliberately **not** part of this slice; track it
  as its own blocked row.

## Core gap: `internal/pairing/devicesession.go` (385 lines) has no Rust counterpart

`grep -rln "DeviceSession" crates/` finds only `symvault-sync/devices.rs`, which
is the *other*, destructive sync registry (`device list` / `device revoke`) — not
this store. Contract:

- File `<vaultDir>/.symvault/device-sessions.json`; directory `0700`, file `0600`.
- Key = `sha256hex(raw_token)` (same scheme as the agent-token registry). The raw
  token is never persisted; only `prefix` (first 4 characters) is kept for display.
- Fields: `prefix`, `device_id`, `name` (`omitempty`), `public_key`, `created_at`,
  `expires_at`, `revoked`.
- `DefaultSessionTTL = 90 * 24h`; `Enroll` sets `CreatedAt = now UTC`,
  `ExpiresAt = now + TTL`.
- Persistence: `MarshalIndent(..., "", "  ")`, write `.tmp`, then `os.Rename`.
- `load()` migrates legacy keys: a key that does not look like 64 hex characters
  is the raw base32 token, so it is re-keyed under `sha256hex(key)` with `prefix`
  derived from the raw token, then saved.
- `mergeRevocationsFromDisk()` deliberately has **no mtime guard** (coarse
  filesystem timestamps): it re-reads the file and only ever moves `false -> true`,
  so a second store instance — precisely the `approval-revoke` CLI — cannot have
  its revocation undone by this instance's next save.
- `Revoke(deviceID)` saves only when something changed and marks **every** session
  of that device; `List()` returns revoked and expired sessions too.
- **Not a contract:** `List()` iterates a Go map, so order is non-deterministic.
  As with `share revoke`, compare as a set; Rust may sort, but the test must
  record that as a deliberate difference.

## CLI contract (`cmd/device_approval.go`)

`device approval-list`
- Empty store: `No approval devices enrolled.\n`.
- Otherwise a header `%-24s %-6s %-24s %-20s %-20s %s\n` with `DEVICE ID`,
  `TOKEN`, `NAME`, `ENROLLED`, `EXPIRES`, `STATUS`; rows use the same format with
  `DeviceID`, `Prefix + "…"` (U+2026), `Name` (empty becomes `(unnamed)`),
  `CreatedAt.Format("2006-01-02 15:04")`, same for `ExpiresAt`, and status
  `active` / `revoked` / `expired` (revoked wins over expired).
- Every line goes through `printQuietAware`, so `--quiet` suppresses it.

`device approval-revoke <device-id>`
- `Args: cobra.ExactArgs(1)`; unknown device → error `approval device %q not found`.
- Without `-y/--yes`: prompt on **stderr**
  `This will revoke approval device %q. Continue? [y/N]: `, answer read with
  `Fscanln`; anything other than `y` prints `Canceled` on stderr and exits **0**.
- Success: `Approval device %q revoked.\n`.
- Store failures surface as `load approval device store: …` /
  `save approval device store: …`.

## Acceptance for the slice

1. Rust module (placed alongside the existing pairing / `device.rs` structure)
   with unit tests for: enroll→validate, revoked and expired validate as invalid,
   `Revoke` marking all of a device's sessions, `mergeRevocationsFromDisk` with two
   instances (A must not clobber B's revocation), legacy-key migration, file modes.
2. A non-ignored contract test that runs `approval-list` against a hand-written
   `device-sessions.json` (active / revoked / expired) and compares exact bytes,
   plus the prompt and `-y` paths of `approval-revoke` (diff the file before/after).
3. Differential against the pinned oracle binary with throwaway HOME/XDG roots for:
   empty store, one active device, revoked, expired, `-y`, abort (`n`), unknown id.
   Timestamps must be fixed in the fixture (seconds, not `time.Now`); otherwise
   nothing is byte-exact.
4. `cargo fmt --all --check`,
   `cargo clippy -p symvault-cli --all-targets -- -D warnings`,
   `cargo test -p symvault-cli`; `cligap` must report missing paths **37 → 35**,
   alias gaps 0, rust-only 1.
5. Tests use `tempfile::TempDir`, never `as_nanos()` temp names (#1085).

## Must not be claimed

- `approval-pair` stays open (QR rendering, LAN address discovery).
- `APPROVAL-001` (HTTP/broker approval decisions) stays with RUST-011; this slice
  proves only the file-backed device registry plus these two CLI paths.
