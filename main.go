// Symaira Vault is a command-line password manager with age encryption and MCP server support.
package main

import "github.com/danieljustus/symaira-vault/cmd"

// Set via ldflags by goreleaser.
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	// Sniff and clear SYMVAULT_PASSPHRASE from the environment before any
	// child process can inherit it. The cached value is consumed by the
	// unlock flow in internal/cli.
	cmd.SniffAndClearEnvPassphrase()

	cmd.SetVersionInfo(version, commit, date)
	cmd.Execute()
}
