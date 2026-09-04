# This formula is a reference template. GoReleaser generates the actual
# formula with correct version/SHA at release time (see .goreleaser.yml brews).
# To test locally, use the instructions in homebrew/README.md.

class Symvault < Formula
  desc "Modern CLI password manager with age encryption"
  homepage "https://github.com/danieljustus/symaira-vault"
  # GoReleaser replaces these at release time:
  url "https://github.com/danieljustus/symaira-vault/archive/refs/tags/v{{ .Tag }}.tar.gz"
  version "{{ .Version }}"
  sha256 "{{ .Checksum }}"

  license "Apache-2.0"

  depends_on "go" => :build

  def install
    ldflags = %W[
      -s -w
      -X main.version=#{version}
      -X main.commit={{ .FullCommit }}
      -X main.date={{ .Date }}
      -X main.builtBy=homebrew
    ]

    system "go", "build", "-ldflags", ldflags.join(" "), "-o", bin/"symvault", "."
    generate_completions_from_executable(bin/"symvault", "completion")

    man_dir = buildpath/"docs/man"
    system bin/"symvault", "generate", "manpages", man_dir
    man1.install Dir[man_dir/"*.1"]
  end

  def caveats
    <<~EOS
      Symaira Vault has been installed!

      To get started:
        symvault init                    # Initialize a new vault
        symvault set github.com/username # Add your first entry
        symvault get github.com/username # Retrieve it

      For MCP server setup:
        symvault agent install <name> --config-only

      Documentation: https://github.com/danieljustus/symaira-vault#readme
    EOS
  end

  test do
    system "#{bin}/symvault", "version"
  end
end
