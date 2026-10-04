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

The extended Linux development driver now executes 29 real Go/Rust cases:
argument/vault guards, seven-response locked/unlocked stdio exchanges, service
installation/status/removal/failing helper, and actual default/custom TLS and
mTLS startup. Newly created service-directory ancestors use 0700, generated
unit/plist files use 0600, and pre-existing operator directories retain their
mode, matching Go's MkdirAll contract. Linux and macOS helper failures retain
their real exit status. The absent-config/default-service case also matches
actual Go output and generated defaults. These development results do not replace clean
candidate receipts or the three native operating-system jobs.

Retain the existing Rust HTTPS discovery URL when serving TLS. Actual Go
advertises an HTTP resource URL over that TLS listener; reproducing that
scheme would direct clients to the wrong transport. The driver records both
actual URLs and compares every other discovery/startup property unchanged.
Also retain Rust's current rejection of an anonymous mTLS peer without Go's
timestamped handshake log; record the full actual Go log and the empty Rust
transport log. Logging policy and remaining HTTP equivalence stay under
#1241/#1249. Neither difference is silently normalized into byte-parity proof.

Keep Rust's shared atomic publication mode 0600 for the generated public TLS
certificate, as well as for its private key. Actual Go uses 0644 for the
certificate and 0600 for the key. Broader filesystem certificate readability is
unnecessary for the same-user local approval CLI and remote clients receive
the public certificate during TLS. The driver fixes its Unix umask at 0022 and
records both actual file modes; an inherited 0077 initially concealed this
measured difference. Custom fixture certificates are explicitly 0600 in both
implementations. Exact HTTP file-mode equivalence remains part of #1249.

TLS startup uses a real scoped fixture token created by the public Go CLI.
An empty registry would trigger Go's legacy wildcard-token creation/migration;
that separate migration behavior is not part of these launch observations.
Startup stderr, including the listening address under --quiet, follows the
actual Go launch result. HTTP children are force-stopped by the test after
readiness: their exit status/drain is not counted as graceful signal evidence.

Acceptance will bind an immutable Go source inventory, real Go/Rust binaries,
driver, clean candidate sources and native OS. Mandatory Linux/macOS/Windows
jobs must execute nonzero named launch, protocol and service cases. Disposable
HOME/XDG fixtures and synthetic public credentials avoid operator state.
Injected service-process outcomes establish rendered files and invocation
contracts; they do not establish desktop permissions or installed-service
operation on a user's machine. Full callback shutdown, signal behavior, TLS/
OAuth edge cases, whole-CLI diagnostics and GUI delivery retain their separate
#1249, #1242, #1241 and #1245 acceptance requirements.

The final unlocked stdio bootstrap corpus uses metadata plus unknown method/tool
responses. A real Go tool-read denial also launches clock-dependent asynchronous
anomaly callbacks, which can emit off-hours logs and desktop notifications
before process exit; earlier development runs observed that denial but cannot
turn nondeterministic missing logs into stderr parity. Locked bootstrap still
executes the real get_entry call and proves its locked rejection. Full unlocked
store-tool, anomaly and notification behavior remains #1248/#1241/#1245.
TLS flag-path assertions use filesystem identity: Windows extended paths and
macOS resolved temporary-directory aliases must identify the actual configured
certificate/CA file. Exact runtime-metadata path spelling and omission rules
remain #1249; this startup slice does not declare those JSON bytes equivalent.

The native Windows run at candidate 768e802f measured Go listing
request_credential in locked mode when powershell.exe is discoverable, while
Rust's default catalog omitted it. Locked bootstrap now reproduces Go's host
backend metadata detection (TTY or the platform GUI executable, honoring
SYMVAULT_SECUREUI) without constructing a tool runtime or launching a helper.
The driver explicitly sets secure UI to none for the ordinary headless bootstrap
cases in both implementations. A separate lookup-only GUI fixture lists
request_credential and actually calls it: both must return the locked error and
leave the vault untouched. This brings the corpus to 30 Unix / 29 Windows cases.
Listing while locked does not establish delivery of an unlocked GUI prompt;
that runtime remains #1245. The original failed native observation is retained
as the reason for this repair, not normalized out of a claimed parity result.

The subsequent Windows run measured a rejected anonymous mTLS client with no
Go handshake log before the fixture stopped the HTTP child. The transport
rejection is independently required through the actual TLS exchange. Retain
all observed log lines (and their strict known-source validation), including
an empty log, rather than treating an asynchronous log's timing as delivery
evidence. Forced test termination and whole-runtime logging remain outside
this launch acceptance and are explicitly recorded in the receipt.

The first native macOS process run at ddcf190 fails service-install byte parity:
Rust appends a final LF to its launchd plist, whereas the actual pinned Go CLI
ends at </plist>. Remove that LF from production rendering. Preserve the old
unit-test literal and explicitly remove its one appended LF in the expectation;
the literal's previous provenance claim did not establish this wire byte.
Do not trim or normalize service bytes in the native driver. All permissions,
helper invocations and CLI outputs already agree in the failed observation;
the repaired commit must still pass the complete native process gate.
