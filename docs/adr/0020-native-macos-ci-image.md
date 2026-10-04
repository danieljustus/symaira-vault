# ADR 0020: Explicit native macOS CI image

Status: accepted routing decision; fresh native results required.

## Decision and rationale

Route logical `macos-latest` acceptance rows to the repository's existing
`xcode-27` hosted image. Keep matrix row names, required check identities,
test commands, corpus sizes, assertions and failure behavior. Require the real
runner OS to be macOS, kernel to be Darwin and architecture to be arm64 before
any native test. Print `sw_vers` in the retained job log.

On 2026-10-04 the current artifact, Serve, CONNECT, broker, MCP and HTTP macOS
jobs remain queued while Linux and Windows execute. The existing Vaultcore
job at https://github.com/danieljustus/symaira-vault/actions/runs/37192475166
proves that `xcode-27` actually provisions macOS 27.0 (26A428) on the
`xcode-27-arm64` image, version 20260928.0222.1. Its job is 111407387010.
This is evidence of an available native image, not proof of any Rust or CLI
acceptance case: Vaultcore's path check can skip unrelated client work.

Using an explicit image family reduces moving-label drift and reuses the Mac
toolchain image already selected by this repository. Hosted-image patch updates
remain possible; every fresh source-bound receipt and runner log identifies the
actual environment. Do not infer the cause of a queue from its status alone.

Declare the already used `windows-11-arm` image in the workflow linter's
recognized-label list alongside `xcode-27`. The first pinned actionlint run
rejects that existing Windows label; the routing syntax and macOS assertions
are valid. Adding the exact real label keeps checks for accidental unknown
labels active and allows whole-repository workflow validation.

## Acceptance boundaries

Every routed job must execute its complete original native corpus on the new
source head. A platform assertion, checkout, skipped step, cross compilation or
prior-head artifact cannot promote a contract. Existing ordinary review/CI and
merge gates remain required, including expected-head checks when merging.

This image proves macOS arm64 only. Darwin/amd64 release coverage and physical
keychain, biometry, TCC, signed-app and device acceptance remain separate work.
Route follow-up native workflows through the same image and platform assertion
when integrating their PRs. Retain failed and queued prior-head evidence rather
than relabeling it as passed.
