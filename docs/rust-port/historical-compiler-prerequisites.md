# Historical compiler prerequisites v1

`mcp-historical-compiler-prerequisites-v1` is separately recorded execution
preparation for the immutable MCP fixture lanes. It is not a new oracle, product
capture, accepted native matrix or change to `mcp-anomaly-ordered-v1`.

## Actual path and boundary

The archived `TestGenerateMCPExecuteWithSecretFixture` invokes the real
`handleExecuteWithSecret` -> `secrets.RunCommand` -> unchanged runtime filter ->
`go run <absolute execute_secret_child/main.go>` path. That filter deliberately
removes compiler/cache variables. Windows Go 1.26.6 needs an explicit `GOCACHE`
or `LocalAppData`; `HOME` alone does not supply its build cache.

The wrapper compiles the original server tests using the resolved, hash-bound
Go 1.26.6 compiler (`go test -c`) and executes the test binary in its package
working directory. This is necessary because `go test` itself prepends
`GOROOT/bin` to the test's PATH and would bypass a PATH adapter. The binary run
requires every selected named test and its actual `PASS` terminator; it does
not manufacture the `go test` package-summary line.

A private native Go adapter on this test's PATH delegates to the absolute pinned
compiler. Only the exact two arguments `run` and the lane's absolute fixture
child source activate preparation. All other invocations pass through without
environment changes. On the filtered invocation it restores resolved
`GOCACHE`, `GOMODCACHE`, `GOPATH`, `GOROOT`, plus `GOTOOLCHAIN=local`, `GOENV=off`,
`GOWORK=off`, `GOFLAGS=-p=2`, and `GOMAXPROCS=2`. It does not restore ambient
credentials, proxies, operator HOME, `USERPROFILE` or `LocalAppData`. Existing
intentional synthetic secret injection and the original stdin/stdout/stderr
remain with the real compiler/child. The original canonical request is not
modified, including its `env_vars` and timeout.

The adapter is fixture-only, not a general process/signal/timeout shim. It does
not wrap the fixture's timeout-child executable or change the separate ten-second
API serving budget. Isolated directories are not an OS security sandbox.

## Evidence and fail-closed checks

Each lane retains `compiler-adapter/preparation.json`, the exact generated
`main.go`/`config.go`, build command/environment and raw build/build-info logs,
compiled adapter and generator binary hashes, and `toolchain-inputs.json` for
ALL files under the resolved GOROOT. The adapter build uses only those two
sources and the standard library, with modules and cgo disabled. Historical
compiler inputs remain separately inventoried in full by the fixture wrapper.

The adapter validates the real compiler executable hash before delegation. Its
`invocations.jsonl` records the real command, compiler hash, pre-adapter environment
NAMES (never secret values), and compiler exit. Acceptance requires exactly one
matching successful filtered invocation, intentional fixture injection present,
and no unexpected ambient or compiler prerequisite names before the adapter.
Binary, generated sources and complete compiler-tree inputs are rechecked.
The receipt also records the effective lane build and generator environments.

The independently anchored original generators/captures remain byte-identical.
The historical lane still compares literal capture bytes; the corrected lane
still compares all canonical request/response/state/type/case fields with only
its existing explicit provenance changes. Neither historical source pin moves.
The current product replay is separate and never uses this adapter.

## Checks

Use the repository's controlled external build runner and resolved Go 1.26.6:

    make mcp-ordered-fixtures-check MCP_FIXTURE_EVIDENCE=<new-evidence-root>
    MCP_COMPILER_ADAPTER_EVIDENCE=<new-directory> GOTOOLCHAIN=go1.26.6 python3 -B scripts/rust-port/test_mcp_compiler_adapter.py -v

The focused check invokes the actual wrapper with `--generator execute-with-secret`
for both immutable source lanes (one fixture / 13 cases each). Synthetic ambient
credentials/proxies and malicious compiler overrides must not reach the real
filtered child. Its negative control recompiles ONLY the adapter configuration
with a relative invalid GOCACHE, then reruns the unchanged historical generator
through the real handler. The real compiler must fail and literal fixture
acceptance must turn red; failure receipts/logs are retained, not relabeled PASS.
Without the explicit evidence destination this expensive test is an opt-in SKIP.

The full wrapper must still execute 26 fixtures / 248 cases per lane. Darwin
execution, unit-level Windows-shaped cache controls, Windows cross-compilation
and real Windows runtime are separate evidence classes. None of the first three
clears the required exact-head native Windows integration gate. Independent
SPEC/parity and QUALITY/security review is required before promotion/publication.
