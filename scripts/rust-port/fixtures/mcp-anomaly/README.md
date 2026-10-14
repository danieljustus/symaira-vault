# Retained native anomaly counterexample

`darwin-tool-chain.stderr` is the unchanged UTF-8 stderr field of the real Go
`admin-tools-self-only` observation in native macOS arm64 job 113917479909,
run 37959220488, artifact 11632180629 (`mcp-process-macos-latest`).

- Downloaded `native-mcp-process.json` SHA-256:
  `6a07b8dbbb130b9982986d31d943ec0005e544ecb0b6fd62ed664ba20f5b2a15`.
- Candidate: `f083c9c4f33e0526a44c18fbd43afb47eb499f8f`.
- Historical oracle: `d1cd0f97ac550bc3020bc86b0514989f8d28d95c`.
- Go process exit: 0. This does not make the failed stderr verdict pass.
- Extracted field: 816 bytes, SHA-256
  `5fba1c4d2a6cd7e175173ea2f5e4346e9218fafaccbdb8b77f33640a282f38bb`.

Privacy review: the retained field contains only UTC test timestamps, synthetic
agent name `fixture`, tool names, synthetic field lengths and request-correlation
IDs. The IDs do not authorize any operation or identify an operator session.
There are no credential values, bearer tokens, device identities, user paths or
network addresses. No field was redacted or synthesized. The full original
artifact is retained separately in the package evidence, not published here.
The test uses the real stderr validator and still rejects this observation.

## Immutable generator inputs versus patched product captures

`historical-inputs.json` and its independent SHA-256 anchor are unchanged.
The explicitly listed `historical/**/*.txt` files are byte-for-byte originals
from that anchor, relocated only because their product/test counterparts now
use patched dependencies or the two-reference test entrypoint. The `.txt`
suffix prevents archived Go packages from entering `go test ./...`.

The fixture wrapper still builds historical `d1cd0f97` and ordered `24acdb08`
with their own complete immutable module/source inputs and actual Go 1.26.6.
It never overlays current product captures onto either historical lane.
All 26 historical fixtures and 248 cases per lane remain checked. Altering an
archived byte fails the original anchor; altering a current response, request,
state, case count or JSON type fails the payload comparison.

Clipboard, secure input and secret execution additionally have a separate
product replay. Their current captures are generated with the composed ordered
source and patched module files, and retain their actual full source/generator
digests. This is not a retrospective rewrite of historical observations.
The ordinary `mcpcallgen` and `http001initgen` Go tests invoke the same wrapper
with `--generator`, requiring both immutable lanes, exact payloads and the
actual historical compiler rather than calling a historical generator against
the current product tree. Product builds continue to use Go 1.26.9.

The separately named `mcp-historical-compiler-prerequisites-v1` adapter supplies
resolved compiler/cache prerequisites after the unchanged historical runtime
filter. It neither edits these originals nor changes the canonical request.
See [execution boundary and retained proof](../../../../docs/rust-port/historical-compiler-prerequisites.md).
Local execution and Windows cross-compilation do not clear native Windows
acceptance; that exact-head integration gate remains separate.
