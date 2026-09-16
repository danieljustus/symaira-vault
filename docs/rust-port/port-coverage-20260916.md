# What the contract matrix does not say: how much is actually ported

Measured at `cda6b496` on 2026-09-16. Every number here is reproducible from
the commands in the last section.

The contract matrix tracks **rows**, and by row count the port looks well
advanced: 25 of 57 rows are `PASS`. That is a true statement about contracts
and a misleading one about the migration, because the rows are not equal in
size and they are concentrated in the library layer. This page states the other
half of the picture so that neither number is read alone.

## The headline

| | lines of Go production code | share |
|---|---|---|
| Go subsystems with a Rust counterpart | 23,459 | **30 %** |
| Go subsystems with none | 39,043 | 50 % |
| `cmd/` — the CLI itself | 14,426 | 19 % |
| **total (`internal/` + `cmd/`, tests excluded)** | **76,928** | |

The Rust workspace is 20,396 lines across six crates, **27 %** of the Go
production line count.

Line counts are a crude proxy and are offered as one: a Rust port of a Go
package is rarely the same size. They are used here only to show orders of
magnitude, and the structural facts below are what actually matter.

## The structural facts

**`internal/mcp` is the largest subsystem in the repository — 15,054 lines —
and almost none of it is ported.** Rows MCP-001 through MCP-004 were all `TODO`
because the implementation did not exist, not because a contract was missing.

MCP-001 and MCP-004 have since been ported: the `symvault-mcp` crate implements
the JSON-RPC envelope, the `initialize` handshake, the line-framed stdio
dispatch loop and its hygiene behavior under hostile input, against 45 cases
generated from the pinned oracle. That is the handshake and the frame loop only. **There is still no tool surface** — no `tools/list`,
no `tools/call`, no tool registry — and `internal/mcp/server/tool_registry.go`
alone is 837 lines against the 35 tool definitions MCP-002 enumerates. Reading
"MCP has started" as "MCP is close" would repeat exactly the error this page
exists to correct.

**There is no HTTP server in the Rust workspace at all.** No `axum`, no
`hyper`, no listener. Rows HTTP-001 through HTTP-004 likewise.

**The Rust CLI implements two command groups out of 135 command paths**:
`version` and `device`. `device` additionally requires an explicit `--vault`,
because config and profile resolution is not wired into it — the binary says so
itself when you omit the flag. CLI-001 is `PASS` because the version surface is
genuinely pinned; CLI-002 through CLI-007 cover the other 133.

**These subsystems have no Rust counterpart of any kind**: `ui`,
`health`, `cli`, `importer`, `intake`, `secureui`, `dynamicsecret`, `approval`,
`broker`, `agentskill`, `daemon`, `secrets`, `update`. `mcp` has left this list
as of MCP-001, but only by its handshake and transport; the count of *fully*
ported subsystems among them is still zero.

## What this means for the remaining rows

The 25 `TODO` rows split into two kinds, and they are not comparable work:

- **Contract rows waiting on a contract.** The Go behaviour and the Rust
  implementation both exist; what is missing is a pinned, differentially tested
  fixture. The `in_progress` rows are mostly here — SESSION-001/003,
  PLATFORM-001/002, GIT-002/003, IO-003, PAIRING-001. These are the rows this
  workstream can close.
- **Rows waiting on a port.** MCP-001..004, HTTP-001..004, CLI-002..007,
  APPROVAL-001, BROKER-001/002, FFI-001/002, DIST-001..005, VALUE-001. No
  amount of contract work closes these: the Rust side has nothing to test.
  Together they are the majority of the remaining Go code.

Writing a fixture for a subsystem that has no Rust implementation is possible —
the Go oracle can be frozen — but it pins one side of a contract and proves
nothing about parity. Where that is worth doing as preparation, it should be
recorded as an oracle-only row and not as evidence of a port.

## Why this page exists

The matrix's evidence column is rigorous about *what was verified*. It is
silent about *what has not been attempted*, and a reader counting `PASS` rows
will overestimate how close a cutover is. `docs/product-boundaries.md` already
warns that "an accepted target is not a shipped cutover"; this is the concrete
version of that warning for this repository.

Nothing here changes any row's status. No row is downgraded: every `PASS` in
the matrix is backed by the evidence it claims. The claim being corrected is
one the matrix never made explicitly and a reader could easily infer.

## Reproducing the numbers

```
# Go production lines, tests excluded
find internal cmd -name '*.go' ! -name '*_test.go' | xargs wc -l | tail -1

# Rust production lines
find crates -path '*/src/*' -name '*.rs' | xargs wc -l | tail -1

# Go command paths in the pinned CLI fixture
python3 -c "import json;print(len(json.load(open('testdata/port/cli/command-tree.json'))['commands']))"

# MCP and HTTP in the Rust workspace
grep -rn 'jsonrpc\|tools/call' crates/*/src/          # no matches
grep -rn 'axum\|hyper\|TcpListener' crates/*/Cargo.toml  # no matches
```
