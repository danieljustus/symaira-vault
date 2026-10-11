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
