// Package cli provides shared CLI infrastructure for OpenPass commands.
// It is the central hub that the cmd/ entry point and all cmd sub-packages
// import to avoid circular dependencies.
package cli

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unsafe"

	"filippo.io/age"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"golang.org/x/term"

	agentctx "github.com/danieljustus/OpenPass/internal/agentctx"
	configpkg "github.com/danieljustus/OpenPass/internal/config"
	cryptopkg "github.com/danieljustus/OpenPass/internal/crypto"
	errorspkg "github.com/danieljustus/OpenPass/internal/errors"
	"github.com/danieljustus/OpenPass/internal/i18n"
	"github.com/danieljustus/OpenPass/internal/metrics"
	"github.com/danieljustus/OpenPass/internal/session"
	"github.com/danieljustus/OpenPass/internal/ui/cliout"
	"github.com/danieljustus/OpenPass/internal/ui/theme"
	vaultpkg "github.com/danieljustus/OpenPass/internal/vault"
	vaultsvc "github.com/danieljustus/OpenPass/internal/vaultsvc"
)

var OsExit = os.Exit

const RequiresVaultAnnotation = "openpass/requires-vault"

var ReadPasswordFunc func(int) ([]byte, error) = term.ReadPassword
var IsTerminalFunc func(int) bool = term.IsTerminal

// PipeWarningEmitted tracks whether the pipe-input warning has already been
// printed in this process so we only nag once per invocation.
var PipeWarningEmitted bool

// WarnPipeRead prints a one-shot warning that hidden input is being read from
// a non-TTY (pipe/redirect).
func WarnPipeRead(label string) {
	if PipeWarningEmitted || QuietMode || NoPipeWarning {
		return
	}
	if v := os.Getenv("OPENPASS_NO_PIPE_WARNING"); v != "" && v != "0" {
		return
	}
	PipeWarningEmitted = true
	cliout.Warnf("Reading %s from a non-TTY source — the producing process may expose it in 'ps' or audit logs. Prefer OPENPASS_PASSPHRASE or 'openpass auth set touchid'.", label)
}

func ReadHiddenInput(prompt string, reader *bufio.Reader) ([]byte, error) {
	fmt.Fprint(os.Stderr, prompt)
	fdRaw := os.Stdin.Fd()
	if fdRaw > uintptr(^uint(0)>>1) {
		return nil, fmt.Errorf("file descriptor %d exceeds int range", fdRaw)
	}
	fd := int(fdRaw)
	if IsTerminalFunc(fd) {
		passphrase, err := ReadPasswordFunc(fd)
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", strings.TrimSuffix(strings.TrimSuffix(prompt, ": "), ":"), err)
		}
		return bytes.TrimSpace(passphrase), nil
	}
	label := strings.TrimSuffix(strings.TrimSuffix(prompt, ": "), ":")
	WarnPipeRead(label)
	if reader != nil {
		line, err := reader.ReadString('\n')
		if err != nil && line == "" {
			return nil, fmt.Errorf("read %s: %w", label, err)
		}
		return bytes.TrimSpace([]byte(line)), nil
	}
	line, err := ReadLineFromStdin()
	if err != nil && line == nil {
		return nil, fmt.Errorf("read %s: %w", label, err)
	}
	return bytes.TrimSpace(line), nil
}

func ReadLineFromStdin() ([]byte, error) {
	var result []byte
	var buf [1]byte
	for {
		n, err := os.Stdin.Read(buf[:])
		if n > 0 {
			if buf[0] == '\n' {
				return result, nil
			}
			result = append(result, buf[0])
		}
		if err != nil {
			if len(result) == 0 {
				return nil, err
			}
			return result, nil
		}
	}
}

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
	Long: `OpenPass is a Go CLI password manager with an interactive TUI, multi-device
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

func VaultPath() (string, error) {
	if VaultFlag != nil && VaultFlag.Changed {
		p, err := ExpandVaultDir(Vault)
		if err != nil {
			return "", errorspkg.NewCLIError(errorspkg.ExitGeneralError, "expand vault path", err)
		}
		return p, nil
	}

	if envVault := strings.TrimSpace(os.Getenv("OPENPASS_VAULT")); envVault != "" {
		p, err := ExpandVaultDir(envVault)
		if err != nil {
			return "", errorspkg.NewCLIError(errorspkg.ExitGeneralError, "expand vault path", err)
		}
		return p, nil
	}

	if ProfileFlag != nil && ProfileFlag.Changed {
		profileName := strings.TrimSpace(Profile)
		if profileName != "" {
			p, err := resolveProfileVaultDir(profileName)
			if err != nil {
				return "", errorspkg.NewCLIError(errorspkg.ExitGeneralError, "resolve profile", err)
			}
			return p, nil
		}
	}

	if envProfile := strings.TrimSpace(os.Getenv("OPENPASS_PROFILE")); envProfile != "" {
		p, err := resolveProfileVaultDir(envProfile)
		if err != nil {
			return "", errorspkg.NewCLIError(errorspkg.ExitGeneralError, "resolve profile", err)
		}
		return p, nil
	}

	home, err := os.UserHomeDir()
	if err == nil {
		cfg, cfgErr := configpkg.Load(filepath.Join(home, ".openpass", "config.yaml"))
		if cfgErr == nil && cfg.DefaultProfile != "" {
			p, profErr := resolveProfileVaultDir(cfg.DefaultProfile)
			if profErr == nil {
				return p, nil
			}
		}
	}

	p, err := ExpandVaultDir(Vault)
	if err != nil {
		return "", errorspkg.NewCLIError(errorspkg.ExitGeneralError, "expand vault path", err)
	}
	return p, nil
}

func resolveProfileVaultDir(profileName string) (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}

	cfg, err := configpkg.Load(filepath.Join(home, ".openpass", "config.yaml"))
	if err != nil {
		return "", fmt.Errorf("cannot load config: %w", err)
	}

	profile := cfg.ProfileForName(profileName)
	if profile == nil {
		return "", fmt.Errorf("profile %q not found", profileName)
	}

	if profile.VaultPath == "" {
		return "", fmt.Errorf("profile %q has no vault path configured", profileName)
	}

	return ExpandVaultDir(profile.VaultPath)
}

func ExpandVaultDir(vaultDir string) (string, error) {
	if vaultDir == "~" {
		return os.UserHomeDir()
	}
	if strings.HasPrefix(vaultDir, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("cannot determine home directory: %w", err)
		}
		return filepath.Join(home, vaultDir[2:]), nil
	}
	return filepath.Clean(vaultDir), nil
}

func UnlockVault(vaultDir string, interactive bool) (*vaultpkg.Vault, error) {
	v, _, err := UnlockVaultWithTTL(vaultDir, interactive, 0, false)
	return v, err
}

func UnlockVaultWithTTL(vaultDir string, interactive bool, ttlOverride time.Duration, cacheEnvPassphrase bool) (*vaultpkg.Vault, time.Duration, error) {
	if cachedIdentity, cacheErr := SessionLoadIdentity(vaultDir); cacheErr == nil && cachedIdentity != "" {
		if identity, parseErr := age.ParseX25519Identity(cachedIdentity); parseErr == nil {
			v, openErr := vaultpkg.OpenWithCachedIdentity(vaultDir, identity)
			if openErr == nil {
				metrics.RecordIdentityCacheEvent("hit")
				ttl := ConfiguredSessionTTL(v, ttlOverride)
				return v, ttl, nil
			}
		}
		metrics.RecordIdentityCacheEvent("miss")
	} else {
		metrics.RecordIdentityCacheEvent("miss")
	}

	cfg := loadVaultConfigForUnlock(vaultDir)

	passphrase, passphraseFromEnv, passphraseFromBiometric, err := resolveUnlockPassphrase(vaultDir, interactive, cfg)
	if err != nil {
		return nil, 0, err
	}
	defer func() {
		cryptopkg.Wipe(passphrase)
	}()

	v, err := vaultpkg.OpenWithPassphrase(vaultDir, passphrase)
	if err != nil {
		return nil, 0, errorspkg.NewCLIError(errorspkg.ExitGeneralError, "open vault", err)
	}

	ttl := ConfiguredSessionTTL(v, ttlOverride)

	if !passphraseFromEnv || cacheEnvPassphrase {
		if err := SessionSavePassphrase(vaultDir, passphrase, ttl); err != nil {
			return nil, 0, errorspkg.NewCLIError(errorspkg.ExitGeneralError, "save session", err)
		}
		if v != nil && v.Identity != nil {
			_ = SessionSaveIdentity(vaultDir, v.Identity.String(), ttl)
		}
	}
	if cfg.EffectiveAuthMethod() == configpkg.AuthMethodTouchID && !passphraseFromBiometric && (!passphraseFromEnv || cacheEnvPassphrase) {
		if err := SessionSaveBiometric(context.Background(), vaultDir, passphrase); err != nil && interactive {
			fmt.Fprintf(os.Stderr, "Warning: could not update Touch ID unlock: %v\n", err)
		}
	}

	return v, ttl, nil
}

func resolveUnlockPassphrase(vaultDir string, interactive bool, cfg *configpkg.Config) ([]byte, bool, bool, error) {
	passphrase, err := SessionLoadPassphrase(vaultDir)
	passphraseFromEnv := false
	passphraseFromBiometric := false
	if err != nil || len(passphrase) == 0 {
		if cfg.EffectiveAuthMethod() == configpkg.AuthMethodTouchID {
			if biometricPassphrase, biometricErr := SessionLoadBiometric(context.Background(), vaultDir); biometricErr == nil && len(biometricPassphrase) > 0 {
				passphrase = biometricPassphrase
				passphraseFromBiometric = true
			}
		}
		if len(passphrase) == 0 {
			if envPass := os.Getenv("OPENPASS_PASSPHRASE"); envPass != "" {
				// Use unsafe.Slice to alias the string backing array without a heap copy.
				// This way the deferred Wipe(passphrase) at the call site clears the only
				// copy of the passphrase in memory, and the os.Unsetenv does not leave a
				// lingering string on the heap.
				// #nosec G103 — intentional: unsafe.Slice avoids heap-copying the passphrase
				// so that the subsequent Wipe clears the only copy in memory.
				passphrase = unsafe.Slice(unsafe.StringData(envPass), len(envPass))
				passphraseFromEnv = true
			}
			_ = os.Unsetenv("OPENPASS_PASSPHRASE")
		}
	}
	if len(passphrase) == 0 {
		if !interactive {
			return nil, false, false, errorspkg.NewCLIError(errorspkg.ExitLocked, lockedMessageForCache(), nil)
		}
		var readErr error
		passphrase, readErr = ReadHiddenInput("Passphrase: ", nil)
		if readErr != nil {
			return nil, false, false, errorspkg.NewCLIError(errorspkg.ExitLocked, "read passphrase", readErr)
		}
	}
	return passphrase, passphraseFromEnv, passphraseFromBiometric, nil
}

func WithVault(fn func(vaultsvc.Service) error) error {
	vaultDir, err := VaultPath()
	if err != nil {
		return err
	}
	if !vaultpkg.IsInitialized(vaultDir) {
		return errorspkg.NewCLIError(errorspkg.ExitNotInitialized,
			"vault not initialized. Run 'openpass init' first",
			errorspkg.ErrVaultNotInitialized)
	}
	v, err := UnlockVault(vaultDir, true)
	if err != nil {
		return err
	}
	return fn(vaultsvc.New(slog.Default(), v))
}

func WithVaultRaw(fn func(*vaultpkg.Vault) error) error {
	vaultDir, err := VaultPath()
	if err != nil {
		return err
	}
	if !vaultpkg.IsInitialized(vaultDir) {
		return errorspkg.NewCLIError(errorspkg.ExitNotInitialized,
			"vault not initialized. Run 'openpass init' first",
			errorspkg.ErrVaultNotInitialized)
	}
	v, err := UnlockVault(vaultDir, true)
	if err != nil {
		return err
	}
	return fn(v)
}

func loadVaultConfigForUnlock(vaultDir string) *configpkg.Config {
	cfg, err := configpkg.Load(filepath.Join(vaultDir, "config.yaml"))
	if err != nil {
		return configpkg.Default()
	}
	return cfg
}

func lockedMessageForCache() string {
	status := SessionGetCacheStatus()
	if !status.Persistent {
		return "vault locked: this build cannot share 'openpass unlock' sessions across processes; set OPENPASS_PASSPHRASE or use a build with OS keyring support"
	}
	return "vault locked: run 'openpass unlock' first, enable Touch ID with 'openpass auth set touchid', or set OPENPASS_PASSPHRASE"
}

func DefaultSessionTTL() time.Duration {
	return configpkg.Default().SessionTimeout
}

func ConfiguredSessionTTL(v *vaultpkg.Vault, override time.Duration) time.Duration {
	if override > 0 {
		return override
	}
	if v != nil && v.Config != nil && v.Config.SessionTimeout > 0 {
		return v.Config.SessionTimeout
	}
	return DefaultSessionTTL()
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

// GetVaultDir returns the vault directory path, falling back to ~/.openpass on error.
func GetVaultDir() string {
	dir, err := VaultPath()
	if err != nil {
		home, _ := os.UserHomeDir()
		return home + "/.openpass"
	}
	return dir
}

// ReadVisibleInput prints a prompt to stderr and reads a line from stdin.
func ReadVisibleInput(prompt string) (string, error) {
	fmt.Fprint(os.Stderr, prompt)
	line, err := ReadLineFromStdin()
	if err != nil && len(line) == 0 {
		return "", fmt.Errorf("read response: %w", err)
	}
	return strings.TrimSpace(string(line)), nil
}

// StdinIsTerminal returns true when stdin is a terminal (TTY).
func StdinIsTerminal() bool {
	fdRaw := os.Stdin.Fd()
	if fdRaw > uintptr(^uint(0)>>1) {
		return false
	}
	return IsTerminalFunc(int(fdRaw))
}
