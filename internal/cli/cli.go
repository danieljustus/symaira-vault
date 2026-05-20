// Package cli provides shared CLI infrastructure for OpenPass commands.
// It is the central hub that the cmd/ entry point and all cmd sub-packages
// import to avoid circular dependencies.
package cli

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	agentctx "github.com/danieljustus/OpenPass/internal/agentctx"
	errorspkg "github.com/danieljustus/OpenPass/internal/errors"
	"github.com/danieljustus/OpenPass/internal/i18n"
	"github.com/danieljustus/OpenPass/internal/session"
	"github.com/danieljustus/OpenPass/internal/ui/cliout"
	"github.com/danieljustus/OpenPass/internal/ui/theme"
)

var OsExit = os.Exit

const RequiresVaultAnnotation = "openpass/requires-vault"

var (
	SessionLoadPassphrase func(vaultDir string) ([]byte, error)                               = session.LoadPassphrase
	SessionSavePassphrase func(vaultDir string, passphrase []byte, ttl time.Duration) error   = session.SavePassphrase
	SessionIsExpired      func(vaultDir string) bool                                          = session.IsSessionExpired
	SessionLoadBiometric  func(ctx context.Context, vaultDir string) ([]byte, error)          = session.LoadBiometricPassphrase
	SessionSaveBiometric  func(ctx context.Context, vaultDir string, passphrase []byte) error = session.SaveBiometricPassphrase
	SessionGetCacheStatus func() session.CacheStatus                                          = session.GetCacheStatus
	SessionLoadIdentity   func(vaultDir string) (string, error)                               = session.LoadIdentity
	SessionSaveIdentity   func(vaultDir string, identity string, ttl time.Duration) error     = session.SaveIdentity
)

var Vault string
var VaultFlag *pflag.Flag
var QuietMode bool
var Profile string
var ProfileFlag *pflag.Flag
var OutputFormat string
var NoPipeWarning bool
var ColorMode string
var ThemePreset string

var RootCmd = &cobra.Command{
	Use:   "openpass",
	Short: "OpenPass is a Go CLI password manager",
	Long: `Quick Start:
  openpass init            create a vault and identity
  openpass add <name>      add a credential
  openpass get <name>      retrieve a credential

OpenPass is a Go CLI password manager with an interactive TUI, multi-device
sync via Git, and an MCP server for AI-agent integration.

First-time setup:
   1. openpass init         create a vault and identity (non-interactive)
   2. openpass setup        same, plus guided wizard for sync/agents (TTY only)
   3. openpass doctor       health-check and self-heal

Daily use:
  openpass add <name>      add a credential (interactive form)
  openpass ui              browse and edit the vault in a TUI
  openpass get <name>      print a credential
  openpass --help          full command list`,
	SilenceUsage:  true,
	SilenceErrors: true,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		if !commandRequiresVault(cmd) {
			return nil
		}
		vDir, err := VaultPath()
		if err != nil {
			return err
		}

		if agentName := os.Getenv("OPENPASS_AGENT"); agentName != "" {
			_, loadErr := agentctx.Load(agentName, vDir)
			if loadErr != nil {
				return errorspkg.NewCLIError(errorspkg.ExitPermissionDenied,
					fmt.Sprintf("agent mode: %s", loadErr.Error()), loadErr)
			}
		}

		return nil
	},
}

func Execute() {
	cliout.SetQuiet(QuietMode)
	cliout.SetColorMode(cliout.ParseColorMode(ColorMode))
	i18n.ApplyFromEnv()
	if ThemePreset != "" {
		theme.ApplyPreset(theme.ParsePreset(ThemePreset))
	} else {
		theme.ApplyPresetFromEnv()
	}
	if err := RootCmd.Execute(); err != nil {
		cliout.Errorf("Error: %v", err)
		exitCode := errorspkg.ExitCodeFromError(err)
		switch exitCode {
		case errorspkg.ExitNotFound:
			cliout.Hintf("Try: openpass find <search-term>")
		case errorspkg.ExitNotInitialized:
			cliout.Hintf("Run 'openpass init' for a quick start, or 'openpass setup' for the guided wizard.")
		case errorspkg.ExitLocked:
			cliout.Hintf("Unlock with 'openpass unlock', or set OPENPASS_PASSPHRASE for non-interactive use.")
		case errorspkg.ExitSuccess, errorspkg.ExitGeneralError, errorspkg.ExitPermissionDenied, errorspkg.ExitDoctorWarn, errorspkg.ExitDoctorFail:
		}
		OsExit(int(exitCode))
	}
}

func PrintQuietAware(format string, args ...interface{}) {
	if !QuietMode {
		fmt.Printf(format, args...)
	}
}

func PrintlnQuietAware(args ...interface{}) {
	if !QuietMode {
		fmt.Println(args...)
	}
}

func init() {
	RootCmd.PersistentFlags().StringVar(&Vault, "vault", "~/.openpass", "path to the password vault")
	VaultFlag = RootCmd.PersistentFlags().Lookup("vault")
	RootCmd.PersistentFlags().BoolVar(&QuietMode, "quiet", false, "suppress non-error output")
	RootCmd.PersistentFlags().StringVar(&Profile, "profile", "", "use a named vault profile")
	ProfileFlag = RootCmd.PersistentFlags().Lookup("profile")
	_ = RootCmd.RegisterFlagCompletionFunc("profile", ProfileCompletionFunc)
	RootCmd.PersistentFlags().StringVar(&OutputFormat, "output", "text", "Output format (text, json, yaml)")
	RootCmd.PersistentFlags().BoolVar(&NoPipeWarning, "no-pipe-warning", false, "suppress 'reading from non-TTY' warning when piping secrets")
	RootCmd.PersistentFlags().StringVar(&ColorMode, "color", "auto", "When to emit ANSI color: auto, always, never")
	RootCmd.PersistentFlags().StringVar(&ThemePreset, "theme", "", "Color preset: default, highcontrast, colorblind (or OPENPASS_THEME)")
}

func commandRequiresVault(cmd *cobra.Command) bool {
	for current := cmd; current != nil; current = current.Parent() {
		if current.Annotations == nil {
			continue
		}
		if value, ok := current.Annotations[RequiresVaultAnnotation]; ok {
			return value != "false"
		}
	}
	return true
}
