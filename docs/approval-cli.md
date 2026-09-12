# Pending approval CLI

The `symvault approval` commands operate on the queue owned by the running
local MCP server. They do not read a queue file and do not create or emulate
an enrolled approval device.

```sh
symvault approval list
symvault approval list --output json
symvault approval decide <request-id> --approve
symvault approval decide <request-id> --deny
```

`--json` is equivalent to `--output json`. JSON list responses have this
stable shape:

```json
{"requests":[{"id":"apr-...","agent_name":"agent","path":"work/file","write":true,"reason":"agent write requires approval","created_at":"...","expires_at":"...","status":"pending"}]}
```

Decision responses have the shape `{"outcome":{...}}` and include the request
ID, resulting status, decision timestamp, and server-side attribution. No
secret values are returned. The CLI endpoint is reachable only over a
loopback connection and requires proof of ownership of the local vault
directory. The server remains authoritative for queue state and decisions.

## mTLS

The local CLI never downgrades MCP mTLS. Configure a dedicated approval client
identity, signed by the existing server client CA, alongside the server TLS
files:

```yaml
mcp:
  mtls_enabled: true
  tls_cert_file: /path/server.crt
  tls_key_file: /path/server.key
  tls_client_ca_file: /path/client-ca.crt
  approval_tls_cert_file: /path/approval-client.crt
  approval_tls_key_file: /path/approval-client.key
```

The approval certificate/key are client-only and must not reuse the server key.
Missing, malformed, or revoked identities fail closed. Rotate or revoke the
client certificate in the existing CA and restart `symvault serve`; the server
loads the CA at startup and does not hot-reload it. `allow_insecure_bind` cannot
be combined with mTLS. Runtime TLS metadata is authoritative for CLI flag
overrides and is path-only; it contains no key material.
