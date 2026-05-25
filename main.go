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
	cmd.SetVersionInfo(version, commit, date)
	cmd.Execute()
}
