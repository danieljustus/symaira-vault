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
      in
      {
        packages.default = pkgs.buildGoModule {
          pname = "symaira";
          version = self.version or "dev";

          src = ./.;

          # Resolved via `go mod vendor; nix hash path --sri vendor/`
          vendorHash = "sha256-LSRQECBwC+POvZIlTm/mQUnyv/4X28Z3g1RJKp9OQ24=";

          # Disable CGO for Linux — reduces distributability and is not needed
          # (keyring integration requires CGO only on darwin).
          env.CGO_ENABLED = "0";

          ldflags = [
            "-s"
            "-w"
            "-X main.version=${self.version or "dev"}"
            "-X main.commit=${self.rev or "unknown"}"
            "-X main.date=unknown"
          ];

          meta = with pkgs.lib; {
            description = "Modern CLI password manager with age encryption";
            homepage = "https://github.com/danieljustus/symaira-vault";
            license = licenses.mit;
            maintainers = [ ];
            platforms = platforms.linux ++ platforms.darwin;
            mainProgram = "symaira";
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
