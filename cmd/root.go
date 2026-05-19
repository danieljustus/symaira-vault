// Package cmd is the entry point for the OpenPass CLI.
// It imports sub-packages so their init() functions register commands
// with the shared RootCmd from internal/cli.
package cmd

import (
	// Register sub-package commands via init() side effects.
	_ "github.com/danieljustus/OpenPass/cmd/admin"
	_ "github.com/danieljustus/OpenPass/cmd/auth"
	_ "github.com/danieljustus/OpenPass/cmd/crud"
	_ "github.com/danieljustus/OpenPass/cmd/mcp"
	cli "github.com/danieljustus/OpenPass/internal/cli"
)

// These are set via ldflags by goreleaser in main.go's var block.
// We re-export them from cli for the main entry point.

const requiresVaultAnnotation = cli.RequiresVaultAnnotation

var (
	readPasswordFunc = cli.ReadPasswordFunc
	isTerminalFunc   = cli.IsTerminalFunc
)

var (
	vault     = cli.Vault
	vaultFlag = cli.VaultFlag
	quietMode = cli.QuietMode
)

var rootCmd = cli.RootCmd

// Aliases for functions that moved to internal/cli/ but are still used by staying cmd/ files
var (
	vaultPath         = cli.VaultPath
	unlockVault       = cli.UnlockVault
	readHiddenInput   = cli.ReadHiddenInput
	expandVaultDir    = cli.ExpandVaultDir
	defaultSessionTTL = cli.DefaultSessionTTL
	withVault         = cli.WithVault
	withVaultRaw      = cli.WithVaultRaw
	Version           = cli.AppVersion
)

func Execute() {
	cli.Execute()
}

func SetVersionInfo(version, commit, date string) {
	cli.SetVersionInfo(version, commit, date)
}

func AppVersion() string { return cli.AppVersionStr() }

// printQuietAware prints to stdout unless quiet mode is enabled
func printQuietAware(format string, args ...interface{}) {
	cli.PrintQuietAware(format, args...)
}

// printlnQuietAware prints a line to stdout unless quiet mode is enabled
func printlnQuietAware(args ...interface{}) {
	cli.PrintlnQuietAware(args...)
}
