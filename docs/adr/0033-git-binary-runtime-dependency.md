# ADR 0033: The `git` executable is a hard runtime dependency of the Rust CLI

Status: accepted by the maintainer, 2026-11-02.
Affects the Rust `symvault` CLI (`crates/symvault-sync`), release packaging
(nfpm deb/rpm/apk, `scripts/install.sh`, Docker image), and the install
documentation. Follows the DIST-001/DIST-002 release work.

## Context

Vault history, auto-commit and sync are built on git. The two implementations
differ in how they talk to it:

- **Go (oracle):** embedded [go-git](https://github.com/go-git/go-git), a pure-Go
  reimplementation. The Go binary needed no external `git`; the nfpm packages
  only listed `git` under `recommends`.
- **Rust (port):** `symvault-sync` runs the `git` executable
  (`Command::new("git")`) for `init`, `add`, `commit`, `pull`, `push`,
  `status`, `log` and friends, with a pinned C locale, a per-command timeout
  and process-group cleanup. This was chosen for behavioral parity with what
  users' own `git` does (config, credential helpers, SSH, hooks-off defaults)
  and because no mature pure-Rust implementation covers the same surface.

So the port silently turned an optional convenience into a requirement: without
`git` on `PATH`, every command that touches vault history fails. Before this
decision the failure surfaced as the low-level diagnostic
`Git process init git init failed: kind=NotFound, os=Some(2)` and packages only
*recommended* git.

## Decision

`git` is a **hard runtime dependency** of the Rust CLI, stated everywhere it
matters:

- **Packages:** nfpm `dependencies: [git]` for deb, rpm and apk (previously
  `recommends`). The package manager installs it.
- **`scripts/install.sh`:** checks `git --version` before downloading anything,
  and exits with per-OS install instructions when it is missing (dry runs only
  warn). `git --version` is used instead of `command -v git` because on macOS
  `/usr/bin/git` exists as a stub even before the developer tools are installed.
- **Homebrew:** the generated formula declares `depends_on "git"`.
- **Docker image:** the runtime image installs `git` and `ca-certificates`.
- **CLI error:** a missing executable is reported as
  `git is required but was not found in PATH; install git and retry`
  (`GitError::GitNotFound`). It travels the same path as every other
  `GitError` (stringified by the callers, same non-zero exit class); a missing
  *working directory* is still reported as the ordinary I/O error, not as a
  missing git.
- **Docs:** README and `docs/distribution.md` list the requirement and the
  install commands per platform; the README's `go install` is replaced by the
  `cargo install --locked --git ... symvault-cli` path used in the release
  footer.

## Consequences

- Archive, install-script and `cargo install` users must have `git`
  themselves; the Linux packages, the Homebrew formula and the container image
  bring it along.
- **macOS:** `/usr/bin/git` is an Xcode Command Line Tools stub. On a machine
  without the tools, the first `git` invocation (including the installer's
  `git --version`) opens the system "install developer tools" prompt and fails
  until the user completes it. This is acceptable for a developer-oriented CLI,
  is documented in the README, and can be avoided with `brew install git`.
- The Rust binary is no longer self-contained for history operations, unlike
  the Go binary. Static musl builds remain static; the dependency is a runtime
  program, not a linked library.
- Behavior now depends on the host's git version and configuration. The sync
  code already pins locale, disables terminal prompts and supplies a commit
  identity itself, which bounds this. The supported floor is whatever the
  distribution ships (Debian/Ubuntu/Alpine/Fedora/macOS CLT all provide a git
  new enough for the commands used).
- Minimal containers must add `git` to the image; the project image does.

## Alternatives considered

- **gitoxide (`gix`):** closest to go-git in spirit, pure Rust, no external
  program. Rejected for now: its write-side coverage (merge, rebase-style pull,
  push over SSH with the user's agent and credential helpers) is incomplete for
  the sync paths, and matching Go's observable behavior would mean re-proving
  every sync fixture against a new engine, mid-migration. Revisit when `gix`
  covers fetch/push/merge with credential helpers and the port-contract
  fixtures pass on it unchanged.
- **libgit2 (`git2`):** mature and widely used, but it links a C library (build
  complexity for the static musl/zig cross-compiles, another supply-chain
  surface in a secrets tool), has its own SSH/credential stack that differs from
  the user's `git`, and still lacks features such as full `git pull` semantics.
  Rejected for now.
- **Keep `recommends` and degrade gracefully:** rejected. Vault history and
  sync are core behavior; a silent downgrade would produce vaults without
  history rather than an actionable error.
- **Vendor/bundle a `git` binary in the archives:** rejected; it multiplies
  release size and security-patch duty for a tool every target platform already
  ships or packages.
