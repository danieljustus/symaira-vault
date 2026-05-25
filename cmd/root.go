// Package cmd is the entry point for the Symaira Vault CLI.
// It imports sub-packages so their init() functions register commands
// with the shared RootCmd from internal/cli.
package cmd

import (
	// Register sub-package commands via init() side effects.
	_ "github.com/danieljustus/symaira-vault/cmd/admin"
	_ "github.com/danieljustus/symaira-vault/cmd/auth"
	_ "github.com/danieljustus/symaira-vault/cmd/crud"
	_ "github.com/danieljustus/symaira-vault/cmd/mcp"
	cli "github.com/danieljustus/symaira-vault/internal/cli"
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
)

var rootCmd = cli.RootCmd

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
