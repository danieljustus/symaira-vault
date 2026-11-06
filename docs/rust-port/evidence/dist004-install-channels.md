# DIST-004 — local install channels (Docker, Homebrew, Nix)

Base `77865a8e`, branch `local/dist004`, host macOS arm64 (Docker Desktop VM aarch64).
Status of the matrix row stays `TODO`: this is local evidence only. Nothing was
published (no registry, tap, GitHub); Scoop is Windows and out of scope.

## Docker

- `Dockerfile` already built the Rust CLI (cargo-zigbuild static musl, `-p symvault-cli --bin symvault`);
  no Go in the image. No change needed.
- `docker build -t symvault-dist004:local --build-arg SYMVAULT_VERSION=0.0.0-dist004 .` → exit 0.
- `sh scripts/docker-smoke.sh symvault-dist004:local 0.0.0-dist004` → exit 0:
  `version: symvault 0.0.0-dist004`, `git version 2.47.3`, `docker-smoke: init/set/get round trip ok`.
- Binary is an ELF (`\177ELF`), arch `arm64`, entrypoint `symvault`, volume `/home/symvault/.symvault`.
- Persisted paths (named volume, two separate containers): `init` + `set persist.pw --stdin-value`
  in container A wrote `/home/symvault/.symvault/{identity.age,manifest.age,config.yaml,entries/persist.age,.git}`;
  container B (same volume) `get persist.pw` → `persisted-Value-1`.

## Homebrew

- Replaced the stale Go source-build template `homebrew/Formula/symvault.rb` with the output of
  `scripts/homebrew-formula.sh X.Y.Z <placeholder checksums>` (Rust release archives
  `symaira-vault_<v>_<os>_<arch>.tar.gz`, prebuilt binary, completions, man pages, `depends_on "git"`).
- `scripts/homebrew-formula.sh`: new `SYMVAULT_RELEASE_BASE_URL` override (for `file://` archives) and
  a stronger `test do` (version match + init/set/get round trip in `SYMVAULT_VAULT=testpath/vault`,
  asserting `vault/identity.age` and `vault/entries/brew.age`). The default vault location is
  platform specific (`~/.local/share/symaira-vault` on macOS without an existing `~/.symvault`),
  hence the pinned `SYMVAULT_VAULT`.
- Local archive: `SYMVAULT_VERSION=0.0.0-dist004 cargo build --release --locked -p symvault-cli --bin symvault`
  (Mach-O arm64) + `completion {bash,zsh,fish}` + `generate manpages` → `symaira-vault_0.0.0-dist004_darwin_arm64.tar.gz`
  with the GoReleaser layout (wrapping dir, `symvault`, `LICENSE`, `README.md`, `completions/`, `docs/man/`).
- `brew tap-new local/symvault-dist004`; `brew install --formula local/symvault-dist004/symvault-dist004` → exit 0;
  installed `symvault version` → `symvault 0.0.0-dist004`; 119 man pages, zsh + fish completions installed;
  `brew test …` → exit 0. `brew uninstall` + `brew untap local/symvault-dist004` done.
- Wall/deviation: `danieljustus/tap/symvault 0.23.2` (the Go build) was already installed on the host, so
  the throwaway formula was renamed `symvault-dist004` (class `SymvaultDist004`) with `keg_only`, otherwise
  identical to the rendered formula. The existing install was not touched (still `symvault 0.23.2`).
  `brew audit` on the throwaway tap could not run (untrusted tap), not retried with `brew trust`.

## Nix

- `flake.nix` rewritten from `buildGoModule` to `rustPlatform.buildRustPackage`
  (`cargoLock.lockFile = ./Cargo.lock`, `allowBuiltinFetchGit` for the corekit git dependency,
  `-p symvault-cli --bin symvault`, `SYMVAULT_VERSION` stamp = `0.0.0-<flake rev>`, `doCheck = false`,
  git added to the wrapper PATH, completions + man pages installed, Rust dev shell).
  The source fileset must include `testdata/port` — `crates/symvault-cli` `include_str!`s
  `testdata/port/cli/{artifacts,command-tree}.json` (first build failed without it).
- `flake.lock`: the pinned nixpkgs (2026-09-02) had rustc 1.97.1 and the workspace needs 1.98
  (`requires rustc 1.98`); `nix flake update nixpkgs` → 2026-11-01 rev `0bb2eedc…` with rustc 1.99.0.
- Container `nixos/nix:latest` (aarch64, nix 2.35.4, `sandbox = false`, named volume `dist004-nix`):
  `nix build .#default` → exit 0 (3m22s cargo build), `nix run .#default -- version` → `symvault 0.0.0-63ec17e`.
  Round trip with `SYMVAULT_VAULT=$HOME/vault`: init rc 0, set rc 0, `identity.age` + `entries/nixtest.age`
  present, `get` → `Xk9-nix-Battery`. With `env -i` (no PATH) `init` still created `.git`, so the wrapper's git works.
  Installed 119 gzip man pages, bash/zsh/fish completions.
- `.github/workflows/ci.yml` job `flake-vendorhash` (name kept: required check): removed the Go setup and
  `vendorHash` verification, kept `nix build` + `nix run .# -- version`.
- Not exercised: x86_64-linux or darwin Nix builds (only aarch64-linux in the container); the flake.lock
  bump is part of this commit.

## Cleanup

Removed: image `symvault-dist004:local`, `nixos/nix:latest` (pulled by this task), containers `dist004-*`,
volumes `dist004-nix`, `dist004-vault`; brew formula uninstalled and tap removed. `symvault-local-gate:*`
images and `symvault-gate-*` volumes untouched. Logs: `~/.hermes/cache/scratch/dist004/`.
