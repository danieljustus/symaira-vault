# Transitional OpenPass formula.
#
# Keep this formula for existing Homebrew users who installed the old package
# name. `brew upgrade openpass` only checks the installed formula name, so
# removing this file would strand those installations on the last OpenPass
# release instead of moving them to Symaira Vault.

class Openpass < Formula
  desc "Transitional package for Symaira Vault"
  homepage "https://github.com/danieljustus/symaira-vault"
  # GoReleaser replaces these at release time:
  url "https://github.com/danieljustus/symaira-vault/archive/refs/tags/v{{ .Tag }}.tar.gz"
  version "{{ .Version }}"
  sha256 "{{ .Checksum }}"

  license "MIT"

  depends_on "go" => :build

  conflicts_with "symvault", because: "openpass is a transitional package for symvault"

  def install
    ldflags = %W[
      -s -w
      -X main.version=#{version}
      -X main.commit={{ .FullCommit }}
      -X main.date={{ .Date }}
      -X main.builtBy=homebrew
    ]

    system "go", "build", "-ldflags", ldflags.join(" "), "-o", bin/"symvault", "."
    bin.install_symlink "symvault" => "openpass"
    generate_completions_from_executable(bin/"symvault", "completion")

    man_dir = buildpath/"docs/man"
    system bin/"symvault", "generate", "manpages", man_dir
    man1.install Dir[man_dir/"*.1"]
  end

  def caveats
    <<~EOS
      OpenPass has been renamed to Symaira Vault.

      This transitional formula installed the new command:
        symvault

      The old command remains available as an alias:
        openpass

      To move to the new formula name:
        brew uninstall openpass
        brew install symvault
    EOS
  end

  test do
    system "#{bin}/symvault", "version"
    system "#{bin}/openpass", "version"
  end
end
