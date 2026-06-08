// Package cli provides shared CLI infrastructure for Symaira Vault commands.
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

	agentctx "github.com/danieljustus/symaira-vault/internal/agentctx"
	configpkg "github.com/danieljustus/symaira-vault/internal/config"
	"github.com/danieljustus/symaira-vault/internal/envutil"
	errorspkg "github.com/danieljustus/symaira-vault/internal/errors"
	"github.com/danieljustus/symaira-vault/internal/i18n"
	"github.com/danieljustus/symaira-vault/internal/session"
	"github.com/danieljustus/symaira-vault/internal/ui/cliout"
	"github.com/danieljustus/symaira-vault/internal/ui/theme"
)

var OsExit = os.Exit

const RequiresVaultAnnotation = "symvault/requires-vault"

// SessionManager abstracts session persistence operations, allowing
// tests to substitute mock implementations and avoid global state.
type SessionManager interface {
	LoadPassphrase(vaultDir string) ([]byte, error)
	SavePassphrase(vaultDir string, passphrase []byte, ttl time.Duration) error
	IsExpired(vaultDir string) bool
	LoadBiometric(ctx context.Context, vaultDir string) ([]byte, error)
	SaveBiometric(ctx context.Context, vaultDir string, passphrase []byte) error
	GetCacheStatus() session.CacheStatus
	LoadIdentity(vaultDir string) (string, error)
	SaveIdentity(vaultDir string, identity string, ttl time.Duration) error
}

// defaultSessionManager delegates to the real session package.
type defaultSessionManager struct{}

func (defaultSessionManager) LoadPassphrase(vaultDir string) ([]byte, error) {
	return session.LoadPassphrase(vaultDir)
}
func (defaultSessionManager) SavePassphrase(vaultDir string, passphrase []byte, ttl time.Duration) error {
	return session.SavePassphrase(vaultDir, passphrase, ttl)
}
func (defaultSessionManager) IsExpired(vaultDir string) bool {
	return session.IsSessionExpired(vaultDir)
}
func (defaultSessionManager) LoadBiometric(ctx context.Context, vaultDir string) ([]byte, error) {
	return session.LoadBiometricPassphrase(ctx, vaultDir)
}
func (defaultSessionManager) SaveBiometric(ctx context.Context, vaultDir string, passphrase []byte) error {
	return session.SaveBiometricPassphrase(ctx, vaultDir, passphrase)
}
func (defaultSessionManager) GetCacheStatus() session.CacheStatus {
	return session.GetCacheStatus()
}
func (defaultSessionManager) LoadIdentity(vaultDir string) (string, error) {
	return session.LoadIdentity(vaultDir)
}
func (defaultSessionManager) SaveIdentity(vaultDir string, identity string, ttl time.Duration) error {
	return session.SaveIdentity(vaultDir, identity, ttl)
}

// DefaultSessionManager is a SessionManager that delegates to the real
// session package. It is used by NewCLIContext by default.
var DefaultSessionManager SessionManager = defaultSessionManager{}

// Legacy function variables retained for backwards compatibility.
// They delegate to the session package directly. Prefer injecting
// a SessionManager via CLIContext in new code.
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

// CLIContext groups mutable state that was previously stored as package-level
// globals. Holding state in a context struct makes test isolation straightforward:
// each test can create a fresh CLIContext via NewTestContext and avoid
// interference from parallel tests.
type CLIContext struct {
	Vault         string
	QuietMode     bool
	OutputFormat  string
	NoPipeWarning bool
	ColorMode     string
	ThemePreset   string
	Profile       string
	Session       SessionManager
	OsExit        func(int)

	vaultFlag   *pflag.Flag
	profileFlag *pflag.Flag
}

// NewCLIContext returns a CLIContext with production defaults and
// DefaultSessionManager.
func NewCLIContext() *CLIContext {
	return &CLIContext{
		Vault:        "~/" + configpkg.DefaultVaultSubdir,
		OutputFormat: "text",
		ColorMode:    "auto",
		Session:      DefaultSessionManager,
		OsExit:       os.Exit,
	}
}

// NewTestContext returns a CLIContext pre-configured for test isolation.
// The caller can set Session to a mock to avoid real keyring access.
func NewTestContext() *CLIContext {
	return &CLIContext{
		Vault:        "~/" + configpkg.DefaultVaultSubdir,
		OutputFormat: "text",
		ColorMode:    "auto",
		Session:      DefaultSessionManager,
		OsExit:       os.Exit,
	}
}

// ActiveContext is the CLIContext used by Execute. Tests may replace it
// before calling Execute to isolate state without modifying package globals.
var ActiveContext *CLIContext

// Vault path used for flag-binding compatibility with cobra.
// Execute syncs ActiveContext state into this after cobra parses flags.
var Vault string
var VaultFlag *pflag.Flag
var QuietMode bool
var Profile string
var ProfileFlag *pflag.Flag
var OutputFormat string
var NoPipeWarning bool
var ColorMode string
var ThemePreset string

// syncFromContext copies the ActiveContext state into the legacy globals
// so that cobra flag binding and code that reads the globals stay in sync.
func syncFromContext(ctx *CLIContext) {
	if ctx == nil {
		return
	}
	OsExit = ctx.OsExit
	// Sync flag-bound variables from context so cobra's StringVar/BoolVar
	// writes into the correct targets that other code reads.
	Vault = ctx.Vault
	QuietMode = ctx.QuietMode
	Profile = ctx.Profile
	OutputFormat = ctx.OutputFormat
	NoPipeWarning = ctx.NoPipeWarning
	ColorMode = ctx.ColorMode
	ThemePreset = ctx.ThemePreset
}

// syncToContext copies the cobra-parsed globals back into the context
// after RootCmd.Execute() processes flags.
func syncToContext(ctx *CLIContext) {
	if ctx == nil {
		return
	}
	ctx.Vault = Vault
	ctx.QuietMode = QuietMode
	ctx.Profile = Profile
	ctx.OutputFormat = OutputFormat
	ctx.NoPipeWarning = NoPipeWarning
	ctx.ColorMode = ColorMode
	ctx.ThemePreset = ThemePreset
	ctx.vaultFlag = VaultFlag
	ctx.profileFlag = ProfileFlag
}

var RootCmd = &cobra.Command{
	Use:   "symvault",
	Short: "Symaira Vault is a Go CLI password manager",
	Long: `Quick Start:
  symvault init            create a vault and identity
  symvault add <name>      add a credential
  symvault get <name>      retrieve a credential

Symaira Vault is a Go CLI password manager with an interactive TUI, multi-device
sync via Git, and an MCP server for AI-agent integration.

First-time setup:
   1. symvault init         create a vault and identity (non-interactive)
   2. symvault setup        same, plus guided wizard for sync/agents (TTY only)
   3. symvault doctor       health-check and self-heal

Daily use:
  symvault add <name>      add a credential (interactive form)
  symvault ui              browse and edit the vault in a TUI
  symvault get <name>      print a credential
  symvault --help          full command list`,
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

		if agentName := envutil.Getenv("SYMVAULT_AGENT", "OPENPASS_AGENT"); agentName != "" {
			_, loadErr := agentctx.Load(agentName, vDir)
			if loadErr != nil {
				return errorspkg.NewCLIError(errorspkg.ExitPermissionDenied,
					fmt.Sprintf("agent mode: %s", loadErr.Error()), loadErr)
			}
		}

		return nil
	},
}

// Execute runs the CLI with the ActiveContext. If ActiveContext is nil,
// it creates a default context. The context's state is synced into the
// legacy package globals before and after cobra execution so that both
// flag binding and direct globals reads stay coherent.
func Execute() {
	ctx := ActiveContext
	if ctx == nil {
		ctx = NewCLIContext()
		// Preserve the current OsExit so tests that install a custom
		// exit handler (e.g. a panic-to-capture) are not overwritten.
		ctx.OsExit = OsExit
	}
	ActiveContext = ctx
	syncFromContext(ctx)

	cliout.SetQuiet(ctx.QuietMode)
	cliout.SetColorMode(cliout.ParseColorMode(ctx.ColorMode))
	i18n.ApplyFromEnv()
	if ctx.ThemePreset != "" {
		theme.ApplyPreset(theme.ParsePreset(ctx.ThemePreset))
	} else {
		theme.ApplyPresetFromEnv()
	}
	if err := RootCmd.Execute(); err != nil {
		cliout.Errorf("Error: %v", err)
		exitCode := errorspkg.ExitCodeFromError(err)
		if hint := errorspkg.HintForError(err); hint != "" {
			cliout.Hintf("%s", hint)
		} else {
			switch exitCode {
			case errorspkg.ExitNotFound:
				cliout.Hintf("Try: symvault find <search-term>")
			case errorspkg.ExitNotInitialized:
				cliout.Hintf("Run 'symvault init' for a quick start, or 'symvault setup' for the guided wizard.")
			case errorspkg.ExitLocked:
				cliout.Hintf("Unlock with 'symvault unlock', or set SYMVAULT_PASSPHRASE (or OPENPASS_PASSPHRASE) for non-interactive use.")
			case errorspkg.ExitConfigError:
				cliout.Hintf("Run 'symvault doctor' to diagnose and fix configuration issues.")
			case errorspkg.ExitSuccess, errorspkg.ExitGeneralError, errorspkg.ExitPermissionDenied, errorspkg.ExitInvalidInput, errorspkg.ExitDoctorWarn, errorspkg.ExitDoctorFail, errorspkg.ExitUpdateAvailable:
			}
		}
		ctx.OsExit(int(exitCode))
	}

	syncToContext(ctx)
}

// ExecuteWithContext is the context-aware entry point for Execute.
// It sets ActiveContext then delegates to Execute.
func ExecuteWithContext(ctx *CLIContext) {
	ActiveContext = ctx
	Execute()
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
	RootCmd.PersistentFlags().StringVar(&Vault, "vault", "~/"+configpkg.DefaultVaultSubdir, "path to the password vault")
	VaultFlag = RootCmd.PersistentFlags().Lookup("vault")
	RootCmd.PersistentFlags().BoolVar(&QuietMode, "quiet", false, "suppress non-error output")
	RootCmd.PersistentFlags().StringVar(&Profile, "profile", "", "use a named vault profile")
	ProfileFlag = RootCmd.PersistentFlags().Lookup("profile")
	_ = RootCmd.RegisterFlagCompletionFunc("profile", ProfileCompletionFunc)
	RootCmd.PersistentFlags().StringVar(&OutputFormat, "output", "text", "Output format (text, json, yaml)")
	RootCmd.PersistentFlags().BoolVar(&NoPipeWarning, "no-pipe-warning", false, "suppress 'reading from non-TTY' warning when piping secrets")
	RootCmd.PersistentFlags().StringVar(&ColorMode, "color", "auto", "When to emit ANSI color: auto, always, never")
	RootCmd.PersistentFlags().StringVar(&ThemePreset, "theme", "", "Color preset: default, highcontrast, colorblind (or SYMVAULT_THEME)")
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
