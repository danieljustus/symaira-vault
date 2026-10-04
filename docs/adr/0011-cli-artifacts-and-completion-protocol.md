# ADR 0011: Stable CLI artifacts and standalone completion

## Status

Accepted maintainer-delegated decision, 2026-10-04. Implementation and native
acceptance are in progress; issue #1240 and CLI-004 remain open.

Merging main's accepted intake slice at 8b79c477 creates conflicts only in
line-ending attributes and CLI lockfile edges. Retain this slice's LF rules and
removal of clap_complete/clap_mangen: the source-bound Go artifact renderers
replace those dependencies. Locked offline metadata validates the resolved
graph without updating package versions. The runtime/test tree is unchanged by
this ancestry merge; native gates bind the resulting new commit.

## Decision and rationale

Keep the existing public Go help, completion scripts and manuals as the v1
compatibility interface. Generate them from real immutable Go and embed the
result as data in the Rust executable. Running the Rust CLI does not require
Go. Replacing their spelling and shell protocol with Clap defaults would break
installed completion scripts and change published command documentation during
the migration. Future public interface changes require a separately reviewed
artifact regeneration and a versioned compatibility decision.

Help text and all eight script variants use byte parity. The manual tree also
preserves filenames and content, with its date rendered at runtime from
SOURCE_DATE_EPOCH or the current local time, as in Go. The advertised MCP/serve
configuration path is an environment-derived value; freeze a named placeholder
and render the actual shared path resolver's result. Never embed the capture
machine's HOME in a user's help or manual. These are the declared substitutions,
not permission to discard other differences.

Implement Cobra's hidden __complete / __completeNoDesc response protocol in
Rust. Generate command/flag metadata from the actual Go command tree and
execute completion against that metadata. Preserve descriptions, directives,
aliases, required-flag precedence, config-key suggestions and first-argument
vault-entry suggestions. A completion request only loads an already cached
identity; it never selects a passphrase environment variable, prompts, invokes
biometrics or initializes a vault. Missing, malformed and expired sessions
return no entry suggestions. Listing uses the shared bounded ReadSession.

The standalone process validates the cached identity for every request. It does
not replicate Go's five-second in-process path cache: fresh validation keeps
session expiry authoritative, while normal shell completion already launches
a new process for each request. Profile suggestion order is semantic because
Go iterates a map; candidates and the directive must agree.

The artifact contains the full legacy command documentation. Some runtime
surfaces are still separate open issues, including serve, broker and TUI. A
reachable help page or command suggestion does not establish their behavior,
and does not close #1236, #1237 or #1239.

## Evidence and acceptance

The generator rebuilds retained Go source
55da4ca13ead39d4000cf6f866ac8671ca86d8f2 and executes its actual CLI and production
completion callbacks in disposable HOME/XDG roots with a memory session backend.
It binds the full production Go inventory and the injected generator-only probe.
The probe refuses undeclared completion callbacks. Data is never inferred from
Rust output or supplied as hand-written expected results.

The captured surface contains 140 help pages, eight scripts, 119 manuals and
455 protocol observations. Thirty-five observations exercise actual cached,
locked, absent, malformed and expired session/store states; 420 exercise the
command and flag surface. The Rust replay uses its actual memory SessionManager
and encrypted Store, and passes all 455 observations locally. The full owning
CLI test suite passes. Actual Linux Go/Rust binary comparison passes 140 help
pages, eight scripts, 119 manuals and 421 absent-session CLI requests, including
their stderr. Completion creates no vault. Real sourced Bash and Zsh scripts
also return the same candidates and descriptions through Tab completion in
actual PTYs. Terminal prompt/echo timing is excluded from that comparison;
candidate rows are compared, and both raw screens are retained in the receipt.

All corpus and script file I/O is explicit UTF-8 with stable LF bytes. The
first native Windows capture exposed Python's implicit ANSI-codepage decoding:
the stored native artifact proved that Go emitted the same Unicode help and
scripts as Linux, while the driver misread the golden file and manuals. Keep
the real UTF-8 data; do not freeze that mojibake as Windows behavior. The live
config path inside a manual uses md2man's doubled-backslash roff encoding;
ordinary help prints the unescaped path. Both capture normalization and Rust
rendering preserve that declared format-specific substitution.

The native workflow repeats actual immutable Go regeneration and Rust binary
comparison on macOS/Linux/Windows. Unix jobs require Bash, Zsh and Fish; Windows
requires Git Bash and real PowerShell TabExpansion2. Bash's official library
and compatibility adapter are test prerequisites fetched at upstream commit
79d225bad8939a3833314b5af93509131c03f2f8 (2.16.0), with separate SHA-256 checks.
They are not shipped in the Rust executable. Cobra's generated templates retain
their upstream attribution and Apache-2.0 license in third_party/cobra-completion.
The workflow refuses dirty candidates, missing shell cases and zero completion
results. Native macOS/Linux/Windows receipts remain pending; CLI-004 remains
in_progress and no broader CLI or release row is promoted by this evidence.

Hosted Zsh images may contain insecure global completion directories. The
disposable test shell uses compinit -i to exclude those directories rather than
trust their functions or wait for an interactive approval. It sources the
generated script from its own private test directory and still requires real
nonempty Tab results. This is test-host isolation, not a product shell setting.

The cligap walker now recognizes the published Go command group headings as
well as Clap's Commands section. Its previous Rust path count became one when
fed grouped Go-compatible help, although all 134 direct oracle-path probes
succeeded. A regression test reads the actual generated Go root help, and
native acceptance requires a nontrivial discovered tree. The report measures
documentation/flag reachability; it still does not certify runtime behavior.

The current native macOS job failed while cleaning up its interactive Bash:
both the ordinary exit and SIGTERM wait timed out, obscuring the original Tab
failure. The test now kills the owned session group after the bounded ordinary
exit wait and reaps its shell. Preserve any original completion failure; never
turn a cleanup timeout into acceptance or omit Bash from the native job. The
next macOS receipt must establish the actual candidate rows independently.

The subsequent native macOS receipt exposes the original failure: both actual
Go/Rust Bash screens contain the same bare names on one horizontal row,
`generate  get  git`, whereas the driver expects separate descriptive rows.
Fix readline's completion-display-width to one in each disposable Bash shell,
and recognize a complete bare name as a candidate row. Compare every resulting
row, require both get and generate, and retain both raw screens. Sourced-script
candidate byte comparison remains required. Do not omit Bash or classify the
failed native receipt as acceptance; the new commit requires fresh native gates.
