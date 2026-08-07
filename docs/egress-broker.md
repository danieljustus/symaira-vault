# Egress Credential Broker

`symvault broker` is an opt-in loopback MITM forward proxy that attaches
vault credentials to an agent's outbound HTTPS/HTTP requests **server-side**.
A brokered secret never enters the agent's process environment, argv or
process listing — the child process only receives the proxy URL and the path
to the broker's CA certificate.

## Why

`symvault run --env` and the `execute_with_secret` tool place decrypted
values inside a process the agent controls. For most workflows that is the
right trade. But when an agent runs `gh`, `git push`, `npm publish`,
`docker login` or its own harness LLM call, the credential ends up in that
process's environment. The broker moves the injection point from the child
process to the network edge: the child talks to a loopback proxy, and the
proxy — inside `symvault`, which holds the vault — attaches the credential
to each outbound request.

## How it works

- One loopback listener handles `CONNECT` for `https://` upstreams and
  absolute-form forward-proxy requests for `http://`.
- For matched hosts (see below) the proxy terminates TLS with a leaf
  certificate minted by an **ephemeral local CA** (bounded 24 h leaf TTL,
  per-host LRU cache) and re-issues the request upstream with credentials
  injected per the host's API template: auth header/query param or
  path/query/header/body substitutions.
- The upstream connection is made through the same SSRF-hardened dialer as
  `execute_api_request` — DNS is re-resolved at dial time and private/local
  targets are blocked, so a rebinding attack cannot redirect injected
  credentials.
- Every brokered request produces a tamper-evident audit record
  (`broker_request`); audit entries and logs carry host, template name and
  status only — never paths, query strings or credential values.
- Response bodies are sanitized (pattern detection + known credential
  values) before being returned to the agent.
- **Unmatched hosts** (no template covers the host) are forwarded untouched
  by default. In `--strict` mode they are rejected with **403**.
- **Passthrough hosts** (`--passthrough`) are tunneled without any TLS
  interception — the escape hatch for clients that pin certificates.

## Usage

```text
# Start the broker on an ephemeral loopback port (prints env exports)
symvault broker

# Fixed port, strict mode
symvault broker --addr 127.0.0.1:8080 --strict

# Passthrough for certificate-pinning clients
symvault broker --passthrough corporate.internal,legacy.example.com

# One-shot: run a child command with the broker in-process
symvault run --broker -- gh pr create
```

At startup the broker prints the environment to export into the agent's
session:

```text
HTTPS_PROXY=http://127.0.0.1:PORT
HTTP_PROXY=http://127.0.0.1:PORT
SSL_CERT_FILE=<vault>/broker-ca.pem
NODE_EXTRA_CA_CERTS=<vault>/broker-ca.pem
REQUESTS_CA_BUNDLE=<vault>/broker-ca.pem
NO_PROXY=127.0.0.1,localhost
```

The CA certificate is written to `<vault>/broker-ca.pem` (mode 0600) so Go,
Node, Python and curl clients trust the interception without per-tool
configuration.

## Which hosts get credentials

Host resolution reuses the API template catalog (`docs/api-templates.md`):
a request host is matched exactly against the `base_url` host of every
built-in template and every vault-local template in `<vault>/templates/`.
The matched template's `auth_type` and `substitutions` are applied using the
vault entry named by `entry_ref`. To broker a host that has no built-in,
add a vault-local template:

```yaml
# <vault>/templates/example.yaml
base_url: https://api.example.com
auth_type: bearer
entry_ref: work/example
allowed_endpoints: [ /v1/* ]
allowed_methods: [ GET, POST ]
```

Hosts not covered by any template are forwarded without injection (or
rejected in strict mode).

## Honest limitation — same-machine guarantee only

On a single machine the broker removes the plaintext from the child
environment, argv and process listing, **but a determined agent with the
user's own filesystem access can still reach the vault**. The strong
guarantee requires the broker on a separate host, or the agent in a
container with no access to the vault — the same deployment precondition
the reference implementation (Infisical agent-vault) documents. Do not
claim the agent "cannot" reach the credential on one host; the broker
closes the environment/argv/process-listing channels, not the filesystem
channel.

## Security notes

- The CA is ephemeral (generated per broker start) and its key never leaves
  the broker process. Leaf certificates are valid for 24 h.
- The broker binds to loopback only. Do not expose the broker address to
  other hosts without additional access control.
- `--env` behavior is byte-identical to today when the broker is disabled;
  the broker is purely additive.
