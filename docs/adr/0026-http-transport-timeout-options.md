# ADR 0026: Route configured HTTP timeouts through one server options boundary

Status: accepted design; native acceptance pending, 2026-10-04.

## Decisions and rationale

Pass the owning CLI's configured transport budgets to the actual server workers.
Rust already parses MCP timeout settings but previously selected fresh fixed
5/10-second defaults in its accept loop. Actual production Go closes progressing
input at configured 1/3-second limits; before this change Rust still closes at
5/10 seconds. Configuration must affect the running listener, rather than
only its parsed model.

Introduce one explicit `HttpServerOptions` entry point for MCP/OAuth/approval
with optional TLS, token TTLs and header/read/write budgets. Compute these
options before moving configuration into the agent factory. Existing public
entry points and their defaults remain compatible. Use the configured budgets
during initial socket setup, overflow-response setup and each connection
worker. Keep Go's separate 120-second keep-alive idle allowance; shortening
header admission must not shorten idle reuse.

Apply only positive network timeout overrides. Actual Go accepts zero and
negative network timeout settings and resolves them to built-in server defaults.
Rust's unsigned Duration model uses zero for a valid negative value; zero/null
also select defaults at the transport boundary. Persisting that model writes
zero rather than the original negative scalar. This is an explicit model
normalization for a value the server ignores, not a way to disable input limits.
Approval/session-duration validation stays with its existing policy.

Parse network duration strings with the existing exact signed Go duration
parser. Invalid syntax and values outside Go's signed nanosecond range fail
during config loading, before the listener setup. Do not allow a larger parsed
integer to wrap into a short duration. The public options boundary independently
rejects budgets outside that range, so direct library callers cannot silently
remove an absolute deadline with an unrepresentable budget.

Continue ADR 0024's absolute input deadlines and earlier header/overall-read
bound, rather than restarting a full timeout on every received byte. Socket
write-timeout plumbing is included, but this slice does not implement Go's
cumulative write deadline or handler-execution deadline. Shutdown remains owned
by lifecycle code; parsing shutdown_timeout does not establish CLI signal/drain
acceptance.

## Actual evidence and boundaries

`http_timeout_contract.py` rebuilds immutable production Go
`d1cd0f97ac550bc3020bc86b0514989f8d28d95c` and uses the actual Go vault/config/token
APIs. Its recorded helper transformation adds explicit header/read duration
flags. Three profiles use 1s/3s, zero and negative configuration, with identical
encrypted fixture clones and the same sequential native loopback port for
Go/Rust. Each profile executes initialization, ping before/after two progressing
input controls, and two complete discovery responses around a real six-second
idle pause.

Independently require actual peer EOF/reset, at least four progress bytes,
joined control threads, no forced client close and fixed timing ranges.
Configured header input must terminate in 0.6..2 seconds and entity input in
2..4 seconds; zero/negative settings retain the measured 3.5..7.5 and
8..12.5-second default ranges. Preserve all actual bytes. Go's optional complete
JSON body-timeout error is individually checked as in ADR 0024; other output
does not qualify. Ordinary and idle responses compare entire status/header/
entity values with only Date excluded.

The before receipt records Go's 1/3 seconds, Rust's 5/10 seconds and Rust's
negative-config startup failure. A development mutation restores fixed
budgets at the CLI options assignment. Both actual CLIs finish their observations
but the independent configured-time assertion rejects Rust's 5/10-second
positive profile. Restore exact original source bytes and rebuild.

Invalid-syntax and signed-duration-overflow controls use byte-identical copies
of the actual Go-generated configuration and both actual CLIs. They require
prompt failure, nonzero exit, complete bounded output capture, the actual bad
duration diagnostic and no forced cleanup. Go's invalid-config repair dialog
is explicitly declined with n; Rust fails directly. Both full actual diagnostics
remain recorded, including Go's configuration exit code 6 and Rust's current
runtime exit code 1. Broader diagnostic/exit taxonomy remains #1241; this
transport proof does not claim equality of those exit codes. An initial probe incorrectly sent the regular startup y to
that repair dialog, opened the owned fixture editor and failed its forced-
cleanup/output-completeness assertions. Stop that owned editor, retain the
failed receipt and correct the probe input; never classify that run as acceptance. Inventory all candidate/immutable
sources, embedded assets, fixtures and executables; scan output for fixture
secret/token canaries. Forced disposal of live fixture servers is explicitly
separate from graceful shutdown evidence.

The changed Core/MCP runtime passes 401 owning tests locally (172 Core and
229 MCP, no ignored tests), strict Clippy and formatting. Required native
Linux/macOS-arm64/Windows gates run the same nonzero process corpus and owning
tests. Full TLS/default HTTP/OAuth/HEAD/Origin/framing preservation is checked
at the clean publication candidate. Native acceptance remains pending.

More header/body budget combinations, configurable TLS handshake sequencing,
cumulative writes, shutdown signal routing, identity lifecycle and the remaining
parser/overhead/HTTP transport cases remain open. HTTP-001..004 and #1249 stay
in progress until complete applicable-platform acceptance.
