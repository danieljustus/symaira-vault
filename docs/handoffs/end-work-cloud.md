# Code continuation: symaira-vault

> Historical checkpoint from 2026-09-30, retained for reproducibility. For
> current work, start from `main` and read
> [the 2026-10-03 continuation](../rust-port/continuation-20261003.md).
> PR #1228 and the later source/fixture corrections are already integrated.
> The branch-selection and draft instructions below describe the original
> checkpoint, not the current integration state. No release or migration
> acceptance claim is added by preserving this record.

## Goal and immutable starting point

Continue the code and integration work from the published repository, without needing a local chat, private reports or installed agent skills.

- GitHub repository: `danieljustus/symaira-vault`.
- Branch: `handoff/20260930-cloud`.
- Base code commit before this document/checkpoint: `d7d937c070831a803a9b34464315c9ba772c68d0`.
- Working directory for every command below: the checked-out repository root.
- Publication does not authorize a merge, release, tag, destructive cleanup or paid service.
- Continuation draft PR: #1235. Keep it draft until its code/acceptance gates are independently satisfied.

Retain the candidate of PR #1228. Older PR #1227 failed its Windows saturated HTTP shutdown test. #1228 had a successful exact-head CI snapshot; do not treat that as a merge decision while pinned Oracle durability remains unresolved.

## Requirements, decisions and next task

Review PR #1228 rather than assuming older PR #1227 is fixed. Establish durable reachability of pinned Oracle code before squash/linear-history integration. Do not create a tag, alter the retained Oracle clone, or access a real credential store.

Keep products and their optional modules standalone. Preserve exact dependency pins, snake_case contracts, data integrity, authorization and MCP stdout discipline. Keep frozen fixture evidence and original Oracle ancestry unchanged until an explicit preservation design is accepted. Do not rewrite history, force-push, bypass branch protection, delete unique work, close unproven issues or reinterpret a passing subset as complete acceptance.

- Existing PR #1228: OPEN, recorded code head `d7d937c070831a803a9b34464315c9ba772c68d0`. Re-read the current PR before integration.
- Existing PR #1227: OPEN, recorded code head `0018445a982f63a0562469cf94eab6a95d08fb4d`. Re-read the current PR before integration.
- Existing PR #1221: MERGED, recorded code head `9932abdce2ad8a046d2f2d7cf887aa75a6f7bc5a`. Re-read the current PR before integration.

## Setup and scoped verification

Clone the existing public repository, checkout `handoff/20260930-cloud`, verify its current remote HEAD, and read this file before making changes. Never substitute another branch or silently mix the alternatives.

```sh
git clone --branch handoff/20260930-cloud https://github.com/danieljustus/symaira-vault.git
cd symaira-vault
git rev-parse HEAD
git ls-remote --exit-code origin refs/heads/handoff/20260930-cloud
git status --porcelain=v1 -uall
```

Locally observed toolchains: Git 2.54.0, gh 2.102.0, Rust/Cargo 1.98.0, Go 1.27.1, Node 22.22.3, Ruby 2.6.10, Swift 6.4, regular Xcode. Rust repositories pin their toolchain in `rust-toolchain.toml`; honor the checked-in manifests. Go Oracle regeneration must use the exact Go version required by its own manifest/generator, not this observed machine version. Native Swift requires full Xcode. Package-manager caches are rebuildable, not required private inputs.

Scoped reproduction commands, not a claim of the complete product suite:

```sh
cargo test --locked -p symvault-mcp --lib http::shutdown
```

Build command (not claimed executed unless listed in verification):

```sh
cargo build --locked --workspace
```

Start/help command (not executed for live services/devices):

```sh
cargo run --locked -p symvault-cli -- --help
```

For Rust, optional resource limits are `CARGO_BUILD_JOBS=2`, `CARGO_PROFILE_TEST_DEBUG=0`, `CARGO_PROFILE_DEV_DEBUG=0`. `CARGO_TARGET_DIR` may name a fresh build-output directory on stable storage; it is never a source, fixture or configuration input. Do not reuse a build-target directory between code variants when validating changed tests. Each fresh verification uses its own build output. No provider/API secret is required for these scoped mock/unit checks. Do not use real credential, document, broker or router state. Do not enable paid model fallback.

## Dependencies and exclusions

Tracked lockfiles, manifests, generators and fixtures are the reproducible input. Build outputs (`target`, `.build`, `node_modules`, `dist`), dependency caches, coverage output and generated binaries are deliberately excluded and rebuilt. Older unrelated branches, private audit/planning reports, harness settings, personal records, real credential contents, local stores and original unrelated credential-store WIP are excluded, not hidden dependencies of the checks above. No raw chat or private memory is published.

Pinned Git dependency commits found in the selected top-level manifest: `27177f25f551cecefa7bd6c4524abf175b3a75c7`. Package managers must resolve these through public repositories; a fresh-checkout failure to fetch any is a concrete reproducibility blocker, not permission to alter a pin.

Native GUI/Keychain/Touch ID, signing, notarization, and real user-permission behavior need macOS/hardware and remain unverified by generic cloud execution. Network access to GitHub and applicable package registries is required for dependency setup. Production access, signing credentials and live-service secrets must be separately supplied through approved secret management, never this repository. No cloud job is launched by this document.



## Verification record

Prepublication secret-pattern/outgoing-history scans succeeded for the selected base. Exact WIP path/byte comparison is required for checkpoint variants. Product-acceptance and target-cloud runtime are **not checked** by these records.

No new source code was changed on this branch; the fresh remote-clone command results will be recorded below.

Fresh remote-clone verification was executed locally on macOS at published checkpoint `49925c531695956886df4210b1193c01b2dbe516`. The repository was cloned directly from GitHub, without copied worktree files, stashes or source/configuration overrides. The following scoped command chain exited **0**:

```sh
cargo test --locked -p symvault-mcp --lib http::shutdown
```

Rust compilation used two jobs, disabled dev/test debug info and a distinct build-output directory for each variant. Those output directories contained no required source or fixture inputs. Package manager dependency caches were allowed; application state and credentials were not supplied. This verifies repository-contained inputs and these scoped checks, not every product test or native acceptance criterion. Final documentation changes do not change the tested source; the published final HEAD must still be verified before continuation. Target cloud runtime, permissions, secrets and network gates: **not checked**.

## Copyable continuation request

Work in `danieljustus/symaira-vault` on `handoff/20260930-cloud`. Verify the exact remote HEAD given by the final publication record, read `docs/handoffs/end-work-cloud.md`, run the setup and scoped checks, then: Review PR #1228 rather than assuming older PR #1227 is fixed. Establish durable reachability of pinned Oracle code before squash/linear-history integration. Do not create a tag, alter the retained Oracle clone, or access a real credential store. Respect all preservation and integration gates above.
