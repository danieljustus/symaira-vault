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
	vault            = cli.Vault
)

// rootCmd is the package-level root used by production code.
// Tests that modify command state should use a fresh NewRootCmd() for
// isolation.
var rootCmd = newPackageRootCmd()

// newPackageRootCmd builds the package-level root tree: a fresh
// NewRootCmd() tree whose top-level commands are replaced by the
// package-level compat instances (deviceCmd, generateCmd, mcp.ServeCmd,
// ...). This mirrors the pre-migration singleton topology for tests that
// execute or mutate package-level command vars directly (for example
// recipientsAddCmd.Execute() or resets of mcpcmd.ServeCmd flags): the
// executed commands are the same objects the tests mutate. Fresh
// NewRootCmd() calls are unaffected and remain fully independent trees.
func newPackageRootCmd() *cobra.Command {
	root := NewRootCmd()
	compat := []*cobra.Command{
		brokerCmd, deviceCmd, dynamicCmd, generateCmd, gitCmd, policyCmd, profileCmd,
		recipientsCmd, remoteCmd, runCmd, shareCmd, syncCmd, templateCmd, uiCmd,
		mcp.ServeCmd,
	}
	compatByName := make(map[string]struct{}, len(compat))
	for _, compatCmd := range compat {
		compatByName[compatCmd.Name()] = struct{}{}
	}
	for _, c := range root.Commands() {
		if _, ok := compatByName[c.Name()]; ok {
			root.RemoveCommand(c)
		}
	}
	root.AddCommand(compat...)
	return root
}

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
		newBrokerCmd(),
		newDeviceCmd(),
		newDynamicCmd(),
		newGenerateCmd(),
		newGitCmd(),
		newPolicyCmd(),
		newProfileCmd(),
		newRecipientsCmd(),
		newRemoteCmd(),
		newRunCmd(),
		newShareCmd(),
		newSyncCmd(),
		newTemplateCmd(),
		newUICmd(),
	)

	return root
}

func SetStartTime(t time.Time) {
	cli.SetStartTime(t)
}

func Execute() {
	ExecuteRoot(rootCmd)
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
