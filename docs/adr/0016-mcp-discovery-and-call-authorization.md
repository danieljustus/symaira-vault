# ADR 0016: MCP runtime discovery and call-time authorization

## Status

Accepted maintainer-delegated direction, 2026-10-04. The user delegated the
long-term choices and requested their rationale in docs. #1248 and MCP-001..004
remain in progress. This slice supplies the headless profile/process gates;
complete native acceptance and the remaining provider/tool contracts are open.

## Decision and rationale

Use the production tool registry for discovery and call-time profile checks.
A tool hidden by a tier restriction cannot become callable merely because a
capability override is true or a client learned its name through search. Check
the explicit operator allowlist, actual host availability, then the profile's tier/exposure restrictions before
dispatch. Keep entry/action authorization, quotas, approvals and scoped tokens
as additional checks, not substitutes for the tool restriction.

Separate discovery metadata from the dispatch allowlist. A human/operator
explicit allowed_tools restriction remains authoritative in Rust. The actual
Go registry ignores that restriction for much of its list and call surface;
any narrower Rust behavior must be recorded with actual process observations
rather than described as Go byte parity. Metadata errors and handler errors
also retain their actual protocol classifications.

`tools/list` and `symaira_whoami` use one catalog/profile filter, keeping the
actual Go registry order, schemas, annotations and available/unavailable
classification. The dispatch set stays separate: metadata is not permission
to invoke an unimplemented handler. Fixture runtimes may supply their own
metadata without installing a production registry.

Preserve the JSON-RPC `-32603` envelope of command-capability denials. Go emits
that envelope from its command handlers; Rust rejects before dispatch and
explicitly carries the classification to the protocol layer. Tier, exposure,
provider and operator-allowlist denials remain tool-result errors. API and TOTP
availability errors precede tier/capability errors, matching the actual complete
Go dispatcher. An isolated handler fixture does not establish that ordering.

`fetch` projects native creation/update times to RFC3339 whole seconds, as Go
does. Other entry responses retain their fractional timestamps. Fix the
projection rather than masking dates in the comparison.

## Deliberate narrower behavior

| Boundary | Actual Go observation | Rust decision and rationale |
| --- | --- | --- |
| Explicit `allowed_tools` | A health-only profile still lists the ordinary registry and returns both fixture credential canaries from `get_entry_value`. | Apply the explicit restriction to listing, whoami metadata and direct calls. A configured operator restriction must remain effective even when a client knows a tool name. |
| Deprecated `symaira_delete` | Tier filtering checks only `delete_entry`; the alias reaches the write/approval/missing-entry handler. | Authorize the alias against its canonical tier restriction. Deprecation cannot provide an alternate route around a permission boundary. Retain the already frozen catalog alias metadata for compatibility. |
| Legacy missing value authorization | With no tier, `canReadValues=false` and no explicit approval mode, Go returns the disposable entry values. | Retain Rust's denial when neither value capability nor an explicit `none`/`auto` approval policy authorizes the read. Operators migrating that legacy profile can explicitly configure the intended value capability or approval policy. Empty configuration does not imply consent to expose values. |
| Frame size | Go accepts an initialization frame one byte larger than 8 MiB and responds as it does to ordinary initialization. | Limit frames to 8 MiB before LF. Drain oversized input without further buffer growth, emit `-32600` without trusting a truncated id, then recover for the next complete request. Eight MiB retains the measured five-megabyte compatibility input while bounding a single client's retained frame. |

The frame limit bounds the retained input buffer, not process RSS, parser output,
decrypted entry memory or total stream bytes. An exactly 8 MiB frame remains
accepted. An unterminated final fragment remains silently discarded, including
an oversized fragment, matching Go's EOF rule. Existing duplicate-envelope and
invalid-UTF8 rejection decisions remain in force; this slice does not silently
relax them. The old Go corpus is retained unchanged.

## Initial observations

The initial Linux driver starts the actual immutable Go CLI at
d1cd0f97ac550bc3020bc86b0514989f8d28d95c and the integrated Rust CLI for twelve
profiles, retaining every stdout frame and stderr byte. The initial `public/*`
scope measures 74 differences; the corrected allowing `public` scope measures
88. This includes standard/read-only profiles with canRunCommands=true:
Go denies run_command, execute_with_secret and execute_api_request at the tier
boundary, while Rust reaches their missing-argument handlers. Restoring the
boundary must deny before entry access, executor invocation or network work.

Both implementations already deny get_entry_value when exposeValueTools=false;
Rust's diagnostic names the current tier whereas actual Go consistently names
the required standard tier. This is a diagnostic difference, not an observed
value disclosure. Runtime discovery also reports different available/unavailable
sets from the actual profile-aware Go registry. Do not hide those differences
by filling expected values from Rust or comparing only a handful of tool names.

The initial fixture used `public/*` as scope. Actual Go treats scope entries as
literal roots/prefixes, so that spelling rejects public/fixture. The real
allowing fixture is `public`. The final harness includes successful encrypted
entry controls before accepting call-time authorization coverage. Both sides
start from byte-identical copies of a vault initialized/written by actual Go;
timestamps and encrypted artifacts are not reconstructed from Rust results.

The complete CLI regression suite also exposed an old success test configured
with standard tier plus command capability. Change that positive control to
admin tier and add read-only/standard counterfactuals using the same encrypted
credential fixture: both must return the tier denial with zero upstream hits.
The frozen API fixture still records the isolated Go handler's capability
error. The assembled CLI test separately asserts the actual registry's earlier
not-available error, without rewriting the handler observation.

## Process evidence and limits

`scripts/rust-port/mcp_process_contract.py` compiles the actual pinned Go CLI and
a fixture-seeding helper that calls Go vault/config APIs. It measures 22 profiles:
legacy, all three tiers, exposure/capability counterfactuals, three explicit
operator allowlists, all six actual built-in profiles, and three real-executor
controls. Built-in profiles come from actual Go defaults; only the disposable
scope is overlaid. Retain the loaded Go profiles and hashes of every seeded
vault file; assert byte-identical copies before either implementation runs.

Each profile executes 22 responses. Both implementations receive the actual
same public credential entry. The admin executor control writes two independent
completion markers after confirming that the real child received the credential.
The child prints the credential on stdout and stderr; neither response may
contain it. Read-only/standard controls must write no marker. Separate protocol
tests deny before handler/storage access, and the assembled API test counts
upstream requests. These are positive controls plus zero-side-effect denials,
not a test that merely checks a chosen error string.

Twelve additional real process cases cover EOF, CRLF, blank/null/NUL inputs,
two objects per line, duplicate envelope ids, exact/oversized 8 MiB frames,
oversized EOF, and both sides of the measured 10000-level nesting boundary.
Require protocol-only stdout and recovery after rejection. Keep every input
hash and stdout/stderr byte, including failed observations.

The Linux development run passes 1022 actual Go/Rust response frames, with zero
unexpected differences and 67 individually asserted declared differences.
An actual-process mutation removes only the shared tier guard: the read-only
executor control then writes both completion markers and the driver fails at
that control. The original source is restored before building the publication
candidate. This establishes that the native denial is caused by the tier
boundary, not an unrelated missing executable or rejected fixture reference.
The full owning suites pass 229 MCP tests (zero ignored) and 487 CLI tests
(five existing dedicated acceptance helpers ignored), plus strict Clippy.
Native CI executes the same driver on Linux, macOS and Windows and requires
clean commit/source/executable receipts; Windows has two fewer pre-existing
Unix-only MCP tests, while every new regression must execute on all three OSes.
No CI/native acceptance is claimed by the development result.

The first native Windows run at 8c0e764 fails the complete process comparison,
despite passing all 227 owning runtime tests and the assembled CLI API test.
Its retained actual Go/Rust observations expose Windows verbatim canonical paths
in Rust's whoami vault directory. Project ordinary drive/UNC paths for metadata
while retaining verbatim paths for store I/O; do not normalize away the defect
in the driver.

That same native run records five headless approval diagnostic differences:
Go attempts terminal reads and reports "file type does not support deadline";
Rust rejects with "no TTY or GUI dialog available" before prompting. Retain
the earlier fail-closed Rust behavior and its useful diagnostic. Assert the
complete actual Go and Rust envelopes individually for the two delete names and
execute_with_secret, including their distinct tool-result/RPC classifications.
Only Windows may declare these five differences. The total declared difference
gate is 72 on Windows and 67 on Unix; this is not a general error exemption.

The next Windows run at a4dd27a fails an older encrypted-store fixture test,
before the process corpus executes. That test normalizes only the verbatim
canonical path; corrected metadata now uses the ordinary path. Update its
Windows expectation to the ordinary canonical root and assert the exact reported
path before normalization. Preserve canonical expectations on Unix and leave
the frozen Go fixture unchanged. The process driver still accepts only its
ordinary HOME-prefix normalization. Integrate the separately measured launchd
final-byte correction from ADR 0013 into dependent broker/MCP branches so their
native serve gates test the repaired dependency.

The subsequent native Windows runs at c655d9d and a5fd217 identify a second
fixture-path distinction: the runner's temporary directory contains the short
name `RUNNER~1`, while canonicalization expands it to `runneradmin`. Using the
caller spelling therefore rejects correct metadata. Resolve the synthetic root
with the filesystem first and remove only the Windows drive verbatim prefix in
the existing test expectation. Still assert both exact whoami paths before
normalizing the frozen fixture. Runtime source, Go observations and process
driver normalization are unchanged; short names must not become an arbitrary
case-folding or path-equivalence exemption.

Normalize JSON object order/nested JSON text, actual fixture HOME prefixes,
validated paired random 16-hex data-marker ids, and nonnegative measured command
durations only. Keep labels, wrapped content, full schemas, error classes,
timestamps and array order. Preserve raw values in the receipt. Go's supported
`SYMVAULT_NO_NOTIFY=1` suppresses desktop UI, not security logs. Retain and
strictly validate actual off-hours alerts using the real UTC clock; any other
unexpected stderr fails. Rust stderr must be empty. Credential canaries may
occur only in the explicitly authorized value/fetch responses.

Headless observations do not prove GUI prompt availability, physical clipboard
or autotype, remaining MCP handlers, HTTP/token authorization, signal behavior
for every service, or the complete hostile-byte corpus on every native OS.
Those contracts and their owning issues stay open. Catalog metadata alone must
never be used to mark them complete.

## Required evidence

Bind code, embedded assets, profiles, probes, drivers and real executable hashes
to a clean commit. Execute every named tier, legacy/built-in profile and
capability/exposure/allowlist counterfactual on native Linux, macOS and Windows.
Require successful controls as well as zero-side-effect denials. Verify every
stdout byte belongs to a protocol frame; retain actual stderr, and never allow
credential canaries there. Prompt/device, clipboard/autotype and HTTP/token
contracts keep their owning acceptance gates.
