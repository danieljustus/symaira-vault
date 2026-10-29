# MacBook macOS routing pilot

The CI workflow selects a trusted idle `macbook-symaira` ARM64 runner using a small
Ubuntu decision job, otherwise a GitHub-hosted macOS image. Fork PRs and unknown
events always stay hosted; API failures also fail safely to hosted. No PAT or new
secret is exposed to either the decision job or the native jobs.

This pilot deliberately changes **CI only**. Job names, test commands, acceptance
conditions and Intel matrix entries stay unchanged. Release/signing jobs stay on
their existing selectors. Other native workflows are inventoried below and are
not yet migrated; expand only after the CI pilot has run on the actual MacBook.
The routing smoke workflow proves that `fromJSON(needs.decide.outputs.runs_on)`
creates a real native job. Do not arm auto-merge until a real MacBook job passes.
Desktop additionally waits for the Vault pilot to be verified on main.

## Security and capacity limits

Only push, workflow_dispatch, schedule and same-repository pull_request events
are eligible. The router tests fork, busy, offline, missing-label, denied-API and
unknown-event fallback. Run `python3 -B scripts/test_macos_runner_routing.py` and
`actionlint -oneline` locally. Synthetic controls are policy evidence, not actual
native execution. Repository fork approval is separately set to
`all_external_contributors`.

Capacity is a **snapshot, not a reservation**. Concurrent workflows or multiple
native jobs can see the same free runner and then queue locally; a machine that
disconnects after selection does not live-fail-over. One runner per repository is
intentional on this 24 GB development machine. The two repository runners can
still execute concurrently. Start with four Cargo build workers per listener.
GitHub may deny the runner-inventory endpoint to GITHUB_TOKEN despite actions:read;
that case routes hosted rather than adding elevated credentials.

Each runner has its own workspace, Go/Cargo/tool caches, temporary directories,
regular Xcode DEVELOPER_DIR and 60 GiB external-volume job-start reserve. Checkout
retains local files only on self-hosted runners and Go's remote cache restoration
is disabled there; hosted checkout/cache behavior is unchanged. Persistent state
is not VM isolation and must never be trusted with arbitrary external code.

## Complete native workflow inventory at pilot creation

| Workflow / job | Original selector | Pilot treatment |
| --- | --- | --- |
| `ci.yml / rust-native` | `${{ matrix.os == 'macos-latest' && 'xcode-27' || matrix.os }}` | CI pilot |
| `ci.yml / macos-vaultcore` | `xcode-27` | CI pilot |
| `ci.yml / test` | `${{ matrix.os == 'macos-latest' && 'xcode-27' || matrix.os }}` | CI pilot |
| `codeql.yml / analyze` | `${{ matrix.language == 'swift' && 'macos-latest' || 'ubuntu-latest' }}` | Unchanged: expand after pilot acceptance |
| `kdf-resource-policy.yml / native-policy` | `${{ matrix.os == 'macos-latest' && 'xcode-27' || matrix.os }}` | Unchanged: expand after pilot acceptance |
| `mcp-http-shutdown.yml / lifecycle` | `${{ matrix.os == 'macos-latest' && 'xcode-27' || matrix.os }}` | Unchanged: expand after pilot acceptance |
| `release.yml / release` | `macos-15` | Unchanged: release/signing excluded |
| `release.yml / gui-release` | `xcode-27` | Unchanged: release/signing excluded |
| `release.yml / smoke-test-macos` | `macos-latest` | Unchanged: release/signing excluded |
| `release.yml / smoke-test-homebrew` | `macos-latest` | Unchanged: release/signing excluded |
| `rust-api-transport.yml / api-transport` | `${{ matrix.os == 'macos-latest' && 'xcode-27' || matrix.os }}` | Unchanged: expand after pilot acceptance |
| `rust-audit.yml / audit-native` | `${{ matrix.os == 'macos-latest' && 'xcode-27' || matrix.os }}` | Unchanged: expand after pilot acceptance |
| `rust-broker-connect.yml / connect` | `${{ matrix.os == 'macos-latest' && 'xcode-27' || matrix.os }}` | Unchanged: expand after pilot acceptance |
| `rust-broker-egress.yml / egress` | `${{ matrix.os == 'macos-latest' && 'xcode-27' || matrix.os }}` | Unchanged: expand after pilot acceptance |
| `rust-cli-artifacts.yml / artifacts` | `${{ matrix.os == 'macos-latest' && 'xcode-27' || matrix.os }}` | Unchanged: expand after pilot acceptance |
| `rust-http-macos.yml / macos-http` | `xcode-27` | Unchanged: expand after pilot acceptance |
| `rust-intake-cli.yml / intake` | `${{ matrix.os == 'macos-latest' && 'xcode-27' || matrix.os }}` | Unchanged: expand after pilot acceptance |
| `rust-macos-satellites.yml / macos-mcp` | `xcode-27` | Unchanged: expand after pilot acceptance |
| `rust-macos-satellites.yml / macos-broker` | `xcode-27` | Unchanged: expand after pilot acceptance |
| `rust-macos-satellites.yml / macos-rest` | `xcode-27` | Unchanged: expand after pilot acceptance |
| `rust-mcp-http-process.yml / http-process` | `${{ matrix.os == 'macos-latest' && 'xcode-27' || matrix.os }}` | Unchanged: expand after pilot acceptance |
| `rust-mcp-process.yml / mcp-process` | `${{ matrix.os == 'macos-latest' && 'xcode-27' || matrix.os }}` | Unchanged: expand after pilot acceptance |
| `rust-pairing.yml / pairing-native` | `${{ matrix.os == 'macos-latest' && 'xcode-27' || matrix.os }}` | Unchanged: expand after pilot acceptance |
| `rust-serve-cli.yml / serve` | `${{ matrix.os == 'macos-latest' && 'xcode-27' || matrix.os }}` | Unchanged: expand after pilot acceptance |
| `rust-store-observations.yml / observations` | `${{ matrix.os == 'macos-latest' && 'xcode-27' || matrix.os }}` | Unchanged: expand after pilot acceptance |
| `rust-store.yml / storage-native` | `${{ matrix.os == 'macos-latest' && 'xcode-27' || matrix.os }}` | Unchanged: expand after pilot acceptance |
| `rust-sync-observations.yml / observations` | `${{ matrix.os == 'macos-latest' && 'xcode-27' || matrix.os }}` | Unchanged: expand after pilot acceptance |
| `rust-tui.yml / browser` | `${{ matrix.os == 'macos-latest' && 'xcode-27' || matrix.os }}` | Unchanged: expand after pilot acceptance |
| `vault-read-resource-policy.yml / policy` | `${{ matrix.os == 'macos-latest' && 'xcode-27' || matrix.os }}` | Unchanged: expand after pilot acceptance |

Default CodeQL setup is not configured. Advanced CodeQL Swift analysis remains unchanged until pilot acceptance.
