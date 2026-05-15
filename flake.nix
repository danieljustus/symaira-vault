{
  description = "OpenPass — modern CLI password manager with age encryption";

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
      in
      {
        packages.default = pkgs.buildGoModule {
          pname = "openpass";
          version = self.version or "dev";

          src = ./.;

          # Placeholder hash — update after first `nix build`.
          # Run `nix build` once; the build will fail with:
          #   hash mismatch in fixed-output derivation
          #     wanted: …AAAAA…
          #     got:    …<real-hash>…
          # Copy the real SRI hash here to pin Go module dependencies.
          vendorHash = "";

          # Disable CGO for Linux — reduces distributability and is not needed
          # (keyring integration requires CGO only on darwin).
          CGO_ENABLED = 0;

          ldflags = [
            "-s"
            "-w"
            "-X main.version=${self.version or "dev"}"
            "-X main.commit=${self.rev or "unknown"}"
            "-X main.date=unknown"
          ];

          meta = with pkgs.lib; {
            description = "Modern CLI password manager with age encryption";
            homepage = "https://github.com/danieljustus/OpenPass";
            license = licenses.mit;
            maintainers = [ ];
            platforms = platforms.linux ++ platforms.darwin;
            mainProgram = "openpass";
          };
        };

        apps.default = flake-utils.lib.mkApp {
          drv = self.packages.${system}.default;
        };

        devShells.default = pkgs.mkShell {
          packages = with pkgs; [
            go
            gopls
            gotools
            go-tools
          ];
        };
      }
    );
}
