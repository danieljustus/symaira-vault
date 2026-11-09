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
# Server must already be running with TLS. Bind a concrete LAN IP -- wildcard
# binds (0.0.0.0, ::) are refused. Find the Mac's Wi-Fi/Ethernet address first
# (en0 is Wi-Fi on most Macs; try en1 if it prints nothing):
LAN=$(ipconfig getifaddr en0)
symvault mcp --bind "$LAN" --port 8443

# In a separate terminal:
symvault device approval-pair
```

- `approval-pair` auto-detects a LAN IPv4 address to embed in the QR payload.
  If more than one is found, or the wrong one is picked, pass `--host
  <ip>` explicitly.
- Off loopback the server requires TLS. With no TLS flags it generates and
  reuses a self-signed vault certificate (the one whose fingerprint goes into
  the QR code), so the command above is enough. To serve your own certificate
  instead, add `--tls-cert <file> --tls-key <file>` (both are required
  together); `--tls-ca <file>` additionally enables client-certificate (mTLS)
  verification when `MCP.mtls_enabled` is set.
- The server must be reachable from the phone's network. If it is bound to
  `127.0.0.1` (the default — see `--bind` on `symvault mcp`), `approval-pair`
  refuses with an actionable error instead of producing a QR code the phone
  can never reach:

  ```text
  Error: 'symvault serve' is bound to 127.0.0.1 (loopback-only) — a phone on
  the LAN cannot reach it. Restart the server with --bind <lan-ip> (wildcard
  binds such as 0.0.0.0 are refused), then run 'approval-pair' again
  ```

  Restart it with `--bind "$(ipconfig getifaddr en0)"` (the Mac's concrete LAN
  IP), then run `approval-pair` again.

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

Binding to a LAN IP (wildcard binds such as `0.0.0.0` are refused) does not
expose only the approval endpoints — it exposes the **entire** MCP HTTP server to that
network, including the bearer-authenticated `/mcp` endpoint. Only bind
beyond loopback on a network you trust (e.g. a home LAN, not a shared
coworking or conference network). Because a concrete `--bind <lan-ip>` is
mandatory, only the chosen interface is exposed, even when the machine has
more than one network interface.
