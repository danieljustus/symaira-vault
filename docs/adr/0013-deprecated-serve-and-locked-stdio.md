# ADR 0013: Shared serve dispatch and locked stdio ownership

## Status

Accepted maintainer-delegated decision, 2026-10-04. Implementation and native
acceptance for #1236 are in progress; no complete CLI/MCP/platform row is
promoted by this decision alone.

## Decision and rationale

Keep the hidden `serve` compatibility command and route it through the same
argument type, MCP launcher and service installer as `mcp`. Both expose all
eight Go launch flags, valued/repeated Boolean forms and signed integer ports.
The historical bare `serve` warning goes to stderr even under quiet mode.
Service and token children retain Go's own behavior and do not receive the
parent's server-start warning. This makes subsequent transport and permission
fixes apply to both entry points without maintaining two server runtimes.

Use one explicit interactive/noninteractive unlock boundary. Stdio launch may
reuse a valid identity or passphrase cache, or an explicitly allowed environment
passphrase. It must never consume the MCP input stream as password input.
The existing GUI biometric policy remains owned by the session/platform layer;
this slice does not establish real biometric-device acceptance.

When unlock specifically reports a locked vault and `--allow-locked --stdio`
was requested, start the existing ProtocolHandler without a vault/tool-call
runtime. Actual Go has the same nil-vault bootstrap: initialize and tool-list
metadata remain available, and every tool call returns the standard locked
error. It does not construct an unlocked store with an empty/synthetic identity,
write audit/grant keys, validate an unavailable agent against a vault, or acquire
credentials after startup. Invalid credentials, malformed configuration and
storage failures remain errors rather than silently selecting locked mode.

Service operations use Go's home-directory contract: HOME on Unix and
USERPROFILE on Windows. Preserve quiet status output, config-derived install
parameters, unit/plist contents and permissions, native helper invocation
order, typed failure codes and Go's explicit unsupported Windows service result.
No new Windows service implementation is inferred from the word “equivalent”.

## Evidence and boundaries

Live development comparisons already match Go's missing-vault/argument guards,
arbitrary arguments, deprecation warnings, and complete locked stdio responses
with both configured and unknown agents. Unlocked stdio executes the real
encrypted-store runtime; default-agent initialize/catalog/denied reads match Go.
The remaining unknown-agent diagnostic prefix was identified through actual
execution and repaired.

Acceptance will bind an immutable Go source inventory, real Go/Rust binaries,
driver, clean candidate sources and native OS. Mandatory Linux/macOS/Windows
jobs must execute nonzero named launch, protocol and service cases. Disposable
HOME/XDG fixtures and synthetic public credentials avoid operator state.
Injected service-process outcomes establish rendered files and invocation
contracts; they do not establish desktop permissions or installed-service
operation on a user's machine. Full callback shutdown, signal behavior, TLS/
OAuth edge cases, whole-CLI diagnostics and GUI delivery retain their separate
#1249, #1242, #1241 and #1245 acceptance requirements.
