{
  description = "Symaira Vault — modern CLI password manager with age encryption";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs =
    { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = import nixpkgs { inherit system; };
        lib = pkgs.lib;

        # `symvault version` prints this string. SYMVAULT_VERSION is the only
        # stamp the Rust CLI reads (option_env! in crates/symvault-cli/src/main.rs).
        # Tagged releases are built by GoReleaser/cargo, not through this flake, so
        # the flake build is identified by the flake revision.
        version = "0.0.0-${self.shortRev or self.dirtyShortRev or "unknown"}";

        # Only what the Cargo workspace needs: keeps the derivation hash stable
        # across docs/client/Go changes. testdata/port is a real build input:
        # crates/symvault-cli embeds testdata/port/cli/{artifacts,command-tree}.json
        # (the Go-compatible completions/man-page/command-tree data) via include_str!.
        src = lib.fileset.toSource {
          root = ./.;
          fileset = lib.fileset.unions [
            ./Cargo.toml
            ./Cargo.lock
            ./rust-toolchain.toml
            ./crates
            ./third_party/argon2
            ./testdata/port
          ];
        };
      in
      {
        packages.default = pkgs.rustPlatform.buildRustPackage {
          pname = "symvault";
          inherit version src;

          # Cargo.lock pins every crate. The one git dependency
          # (symaira-core-version @ symaira-corekit) is fetched by rev from the
          # lock file, so no per-crate outputHashes are needed.
          cargoLock = {
            lockFile = ./Cargo.lock;
            allowBuiltinFetchGit = true;
          };

          # Same selection as the release builds (.goreleaser.yml): only the CLI.
          cargoBuildFlags = [
            "-p"
            "symvault-cli"
            "--bin"
            "symvault"
          ];

          env.SYMVAULT_VERSION = version;

          # The canonical CI suite runs before this package gate. The tests are
          # host-oriented (Git/SSH, TTYs, keyrings) and cannot run in Nix's pure
          # build sandbox.
          doCheck = false;

          nativeBuildInputs = [
            pkgs.installShellFiles
            pkgs.makeWrapper
          ];

          # git is a hard runtime dependency
          # (docs/adr/0033-git-binary-runtime-dependency.md).
          postInstall =
            lib.optionalString (pkgs.stdenv.buildPlatform.canExecute pkgs.stdenv.hostPlatform) ''
              installShellCompletion --cmd symvault \
                --bash <($out/bin/symvault completion bash) \
                --zsh <($out/bin/symvault completion zsh) \
                --fish <($out/bin/symvault completion fish)
              mkdir -p manpages
              $out/bin/symvault generate manpages manpages
              installManPage manpages/*.1
            ''
            + ''
              wrapProgram "$out/bin/symvault" --prefix PATH : ${lib.makeBinPath [ pkgs.git ]}
            '';

          meta = with lib; {
            description = "Modern CLI password manager with age encryption";
            homepage = "https://github.com/danieljustus/symaira-vault";
            license = licenses.asl20;
            maintainers = [ ];
            platforms = platforms.linux ++ platforms.darwin;
            mainProgram = "symvault";
          };
        };

        apps.default = flake-utils.lib.mkApp {
          drv = self.packages.${system}.default;
        };

        devShells.default = pkgs.mkShell {
          packages = with pkgs; [
            cargo
            rustc
            clippy
            rustfmt
            rust-analyzer
            git
          ];
        };
      }
    );
}
