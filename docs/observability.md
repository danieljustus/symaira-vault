# Observability

Symaira Vault provides opt-in observability through Prometheus metrics and OpenTelemetry traces.

## Metrics

Prometheus metrics are exposed by the HTTP MCP server on `/metrics` only
when built with `-tags metrics` (for example, `go build -tags metrics -o symvault .`
from the repository root). Default builds return HTTP 501 at this endpoint.
Loopback binds do not require metrics authentication; non-loopback binds require
bearer authentication by default (`mcp.metrics_auth_required: true`).

### MCP Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `symvault_mcp_requests_total` | Counter | `tool`, `agent`, `status` | Total MCP tool requests |
| `symvault_mcp_request_duration_seconds` | Histogram | `tool`, `agent` | Request duration |
| `symvault_mcp_auth_denials_total` | Counter | `reason`, `agent` | Auth denials |
| `symvault_mcp_approvals_total` | Counter | `agent`, `outcome` | Approval outcomes |

### Vault Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `symvault_vault_operations_total` | Counter | `operation`, `status` | Vault operations |
| `symvault_vault_entries_total` | Gauge | `vault` | Number of entries |
| `symvault_vault_operation_duration_seconds` | Histogram | `op` | Operation duration |

### Session Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `symvault_session_cache_events_total` | Counter | `event` | Cache events |

Event types: `hit`, `miss`, `refresh`, `evict`, `keyring_unavailable`

### Update Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `symvault_update_check_total` | Counter | `result` | Update check results |

Result types: `up_to_date`, `update_available`, `error`, `cache_hit`

## Local Debugging

Use the metrics-enabled HTTP server's `/metrics` endpoint to inspect current
values. The executable does not register a `diag metrics` command.

## Tracing

OpenTelemetry tracing requires the same `metrics` build tag; without it,
tracing initialization is a no-op.

### Configuration

Set the OTLP endpoint via environment variable:

```bash
export SYMVAULT_OTLP_ENDPOINT=http://localhost:4318
symvault mcp --port 8080
```

Or use a custom endpoint programmatically via `metrics.InitTracing(endpoint, serviceName)`.

### Spans

The following spans are emitted when tracing is enabled:

- `executeTool` — Top-level MCP tool execution with attributes:
  - `tool.name` — Tool name
  - `agent.name` — Agent name
  - `transport` — `stdio` or `http`
  - `entry.path` — SHA-256 hash prefix of the entry path (privacy-preserving)
  - `status` — `success` or `error`

- Sub-spans for vault operations:
  - `vault.GetEntry`
  - `vault.SetEntry`
  - `vault.List`
  - `vault.Find`
  - `vault.Delete`

### Privacy

Entry paths are hashed before being added as span attributes. Only the first 8 bytes of the SHA-256 hash are used. This obscures paths but does not prevent offline dictionary guessing: candidate paths can be hashed and compared.

### Performance

When `SYMVAULT_OTLP_ENDPOINT` is not set, a no-op tracer is used with zero overhead.

## Security

- Telemetry is strictly opt-in
- No telemetry is collected by default
- No external dependencies on SaaS telemetry providers
- The "No telemetry" promise in SECURITY.md remains unchanged
