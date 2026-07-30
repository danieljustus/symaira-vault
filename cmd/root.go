// Package cmd is the entry point for the Symaira Vault CLI.
package cmd

import (
	"time"

	"github.com/spf13/cobra"

	"github.com/danieljustus/symaira-vault/cmd/admin"
	"github.com/danieljustus/symaira-vault/cmd/auth"
	"github.com/danieljustus/symaira-vault/cmd/crud"
	"github.com/danieljustus/symaira-vault/cmd/file"
	"github.com/danieljustus/symaira-vault/cmd/mcp"
	cli "github.com/danieljustus/symaira-vault/internal/cli"
)

const requiresVaultAnnotation = cli.RequiresVaultAnnotation

var (
	readPasswordFunc = cli.ReadPasswordFunc
	isTerminalFunc   = cli.IsTerminalFunc
)

var (
	vault     = cli.Vault
)

var rootCmd = NewRootCmd()

// NewRootCmd returns a fully assembled root command tree containing all
// subpackages and top-level commands without relying on init() side effects.
func NewRootCmd() *cobra.Command {
	root := cli.NewRootCmd()

	// Add subpackage commands
	root.AddCommand(admin.NewCommands()...)
	root.AddCommand(auth.NewCommands()...)
	root.AddCommand(crud.NewCommands()...)
	root.AddCommand(file.NewCommands()...)
	root.AddCommand(mcp.NewCommands()...)

	// Add top-level commands in cmd/
	root.AddCommand(
		deviceCmd,
		dynamicCmd,
		generateCmd,
		gitCmd,
		policyCmd,
		profileCmd,
		recipientsCmd,
		remoteCmd,
		runCmd,
		shareCmd,
		syncCmd,
		templateCmd,
		uiCmd,
	)

	return root
}

func SetStartTime(t time.Time) {
	cli.SetStartTime(t)
}

func Execute() {
	ExecuteRoot(NewRootCmd())
}

func ExecuteRoot(root *cobra.Command) {
	_ = cli.ExecuteRoot(root)
}

func SetVersionInfo(version, commit, date string) {
	cli.SetVersionInfo(version, commit, date)
}

func AppVersion() string { return cli.AppVersionStr() }

// SniffAndClearEnvPassphrase reads and caches the SYMVAULT_PASSPHRASE env var
// then unsets it so child processes cannot inherit the raw passphrase.
func SniffAndClearEnvPassphrase() {
	cli.SniffAndClearEnvPassphrase()
}

// printQuietAware prints to stdout unless quiet mode is enabled
func printQuietAware(format string, args ...interface{}) {
	cli.PrintQuietAware(format, args...)
}

// printlnQuietAware prints a line to stdout unless quiet mode is enabled
func printlnQuietAware(args ...interface{}) {
	cli.PrintlnQuietAware(args...)
}
