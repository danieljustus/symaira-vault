# Approval Devices

An approval device is a phone paired with `symvault serve`/`symvault mcp`
that can approve or deny an agent's write requests in real time. It is the
human-in-the-loop control behind `approvalMode: prompt`: with no approval
device enrolled, `prompt` degrades to `deny` (see
[Configuration reference](configuration.md#agent-profile-options)); once a
device is paired, an agent write blocks until the device approves or denies
it, or the request expires after 5 minutes.

This is a different feature from `symvault device pair` (which pairs a
second computer for vault-content sync and re-encrypts every entry). An
approval device can approve or deny agent requests, but it never decrypts
vault entries and never touches vault content.

## How it works

1. `symvault device approval-pair` asks the already-running server, over its
   own loopback listener, to mint a short-lived pairing code. The server only
   answers this request when it also carries proof that the caller can read
   the vault directory — see [Security model](#security-model) below.
2. The command renders that code, the server's host/port, and the SHA-256
   fingerprint of the server's current TLS certificate as a QR code (and
   prints the values for manual entry).
3. The phone scans the QR code and calls the server's public enrollment
   endpoint, redeeming the code for a long-lived (90-day) bearer token. The
   phone pins its TLS connection to the exact fingerprint from the QR
   payload — it does **not** trust the system certificate authority store,
   since the server's certificate is self-signed. Any fingerprint mismatch
   must fail closed.
4. From then on, the phone polls the server's approvals endpoint using that
   bearer token, and can approve or deny each pending request.

## Pairing a phone

```bash
# Server must already be running with TLS (the default):
symvault mcp --bind 0.0.0.0 --port 8443

# In a separate terminal:
symvault device approval-pair
```

- `approval-pair` auto-detects a LAN IPv4 address to embed in the QR payload.
  If more than one is found, or the wrong one is picked, pass `--host
  <ip>` explicitly.
- The server must be reachable from the phone's network. If it is bound to
  `127.0.0.1` (the default — see `--bind` on `symvault mcp`), `approval-pair`
  refuses with an actionable error instead of producing a QR code the phone
  can never reach:

  ```text
  Error: 'symvault serve' is bound to 127.0.0.1 (loopback-only) — a phone on
  the LAN cannot reach it. Restart the server with --bind 0.0.0.0 (all
  interfaces) or --bind <lan-ip>, then run 'approval-pair' again
  ```

  Restart the server with `--bind 0.0.0.0` (all interfaces) or `--bind
  <lan-ip>` (a specific interface), then run `approval-pair` again.

## Listing and revoking

```bash
symvault device approval-list
```

Shows every enrolled approval device: device ID, a short non-secret token
prefix (for telling devices apart — the full bearer token is never
displayed or stored on disk, see [Security model](#security-model)), name,
enrollment/expiry dates, and status (`active`, `revoked`, `expired`).

```bash
symvault device approval-revoke <device-id>
```

Revokes one device's ability to approve or deny requests. This does **not**
re-encrypt or otherwise touch vault entries — it only invalidates that
device's bearer token. Revocation takes effect against an already-running
server immediately (not just after a restart or the next periodic cleanup
tick), and a concurrent write from the server (e.g. its own periodic
session cleanup) cannot silently un-revoke a device behind an operator's
back.

`symvault device revoke <name>` is a different, more destructive command
for the unrelated vault-content sync device registry — it re-encrypts every
vault entry. Don't confuse the two.

## Security model

- **Enrollment requires proof of vault ownership.** Minting a pairing code
  is gated on loopback *and* an HMAC proof over a secret cached at
  `<vault>/mcp-server.enroll-secret` (0600, generated on first use — the
  same trust domain as the TLS private key and age identities). A local
  process that cannot read the vault directory cannot self-enroll as an
  approval device, even from loopback.
- **Bearer tokens are hashed at rest.** `<vault>/device-sessions.json`
  stores only `sha256(token)` plus a short display prefix, matching the
  pattern the MCP scoped-token registry already uses — a vault backup, a
  git sync of the vault directory, or any read of the 0600 file yields no
  usable credential.
- **TLS is pinned by fingerprint, not a CA.** The server presents a
  self-signed certificate; the phone trusts only the exact SHA-256
  fingerprint from the pairing QR code. There is no certificate authority
  to compromise.
- **Tokens expire after 90 days** and can be revoked at any time via
  `approval-revoke`.

## LAN exposure implications

Binding with `--bind 0.0.0.0` or a specific LAN IP does not expose only the
approval endpoints — it exposes the **entire** MCP HTTP server to that
network, including the bearer-authenticated `/mcp` endpoint. Only bind
beyond loopback on a network you trust (e.g. a home LAN, not a shared
coworking or conference network), and prefer a specific `--bind <lan-ip>`
over `0.0.0.0` when the machine has more than one network interface.
