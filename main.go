// Symaira Vault is a command-line password manager with age encryption and MCP server support.
package main

import (
	"time"

	"github.com/danieljustus/symaira-vault/cmd"
)

// Set via ldflags by goreleaser.
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

// startTime is the earliest timestamp captured in the main package, after
// Go runtime init but before any application code runs. It powers the
// startup-profile command's startup time measurements.
var startTime = time.Now()

func main() {
	cmd.SetStartTime(startTime)

	cmd.SniffAndClearEnvPassphrase()

	cmd.SetVersionInfo(version, commit, date)
	cmd.Execute()
}
