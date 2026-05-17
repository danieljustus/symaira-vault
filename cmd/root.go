package cmd

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

	"filippo.io/age"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"golang.org/x/term"

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

var osExit = os.Exit

const requiresVaultAnnotation = "openpass/requires-vault"

var readPasswordFunc func(int) ([]byte, error) = term.ReadPassword
var isTerminalFunc func(int) bool = term.IsTerminal

// pipeWarningEmitted tracks whether the pipe-input warning has already been
// printed in this process so we only nag once per invocation.
var pipeWarningEmitted bool

// warnPipeRead prints a one-shot warning that hidden input is being read from
// a non-TTY (pipe/redirect). Callers like `echo secret | openpass unlock`
// expose the value in /proc/<pid>/cmdline and `ps`, so the user should know.
// Suppressed by --no-pipe-warning, OPENPASS_NO_PIPE_WARNING=1, or quiet mode.
func warnPipeRead(label string) {
	if pipeWarningEmitted || quietMode || noPipeWarning {
		return
	}
	if v := os.Getenv("OPENPASS_NO_PIPE_WARNING"); v != "" && v != "0" {
		return
	}
	pipeWarningEmitted = true
	cliout.Warnf("Reading %s from a non-TTY source — the producing process may expose it in 'ps' or audit logs. Prefer OPENPASS_PASSPHRASE or 'openpass auth set touchid'.", label)
}

func readHiddenInput(prompt string, reader *bufio.Reader) ([]byte, error) {
	fmt.Fprint(os.Stderr, prompt)
	fdRaw := os.Stdin.Fd()
	// Bounds check: file descriptors are small non-negative integers; ensure they fit in int
	if fdRaw > uintptr(^uint(0)>>1) {
		return nil, fmt.Errorf("file descriptor %d exceeds int range", fdRaw)
	}
	fd := int(fdRaw)
	if isTerminalFunc(fd) {
		passphrase, err := readPasswordFunc(fd)
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", strings.TrimSuffix(strings.TrimSuffix(prompt, ": "), ":"), err)
		}
		return bytes.TrimSpace(passphrase), nil
	}
	label := strings.TrimSuffix(strings.TrimSuffix(prompt, ": "), ":")
	warnPipeRead(label)
	if reader != nil {
		line, err := reader.ReadString('\n')
		if err != nil && line == "" {
			return nil, fmt.Errorf("read %s: %w", label, err)
		}
		return bytes.TrimSpace([]byte(line)), nil
	}
	line, err := readLineFromStdin()
	if err != nil && line == nil {
		return nil, fmt.Errorf("read %s: %w", label, err)
	}
	return bytes.TrimSpace(line), nil
}

func readLineFromStdin() ([]byte, error) {
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
	sessionLoadPassphrase func(vaultDir string) ([]byte, error)                               = session.LoadPassphrase
	sessionSavePassphrase func(vaultDir string, passphrase []byte, ttl time.Duration) error   = session.SavePassphrase
	sessionIsExpired      func(vaultDir string) bool                                          = session.IsSessionExpired
	sessionLoadBiometric  func(ctx context.Context, vaultDir string) ([]byte, error)          = session.LoadBiometricPassphrase
	sessionSaveBiometric  func(ctx context.Context, vaultDir string, passphrase []byte) error = session.SaveBiometricPassphrase
	sessionGetCacheStatus func() session.CacheStatus                                          = session.GetCacheStatus
	sessionLoadIdentity   func(vaultDir string) (string, error)                               = session.LoadIdentity
	sessionSaveIdentity   func(vaultDir string, identity string, ttl time.Duration) error     = session.SaveIdentity
)

var vault string
var vaultFlag *pflag.Flag
var quietMode bool
var profile string
var profileFlag *pflag.Flag
var outputFormat string
var noPipeWarning bool
var colorMode string
var themePreset string

var rootCmd = &cobra.Command{
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
		_, err := vaultPath()
		return err
	},
}

func Execute() {
	cliout.SetQuiet(quietMode)
	cliout.SetColorMode(cliout.ParseColorMode(colorMode))
	i18n.ApplyFromEnv()
	if themePreset != "" {
		theme.ApplyPreset(theme.ParsePreset(themePreset))
	} else {
		theme.ApplyPresetFromEnv()
	}
	if err := rootCmd.Execute(); err != nil {
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
			// no specific hint for these exit codes
		}
		osExit(int(exitCode))
	}
}

// printQuietAware prints to stdout unless quiet mode is enabled
func printQuietAware(format string, args ...interface{}) {
	if !quietMode {
		fmt.Printf(format, args...)
	}
}

// printlnQuietAware prints a line to stdout unless quiet mode is enabled
func printlnQuietAware(args ...interface{}) {
	if !quietMode {
		fmt.Println(args...)
	}
}

func init() {
	rootCmd.PersistentFlags().StringVar(&vault, "vault", "~/.openpass", "path to the password vault")
	vaultFlag = rootCmd.PersistentFlags().Lookup("vault")
	rootCmd.PersistentFlags().BoolVar(&quietMode, "quiet", false, "suppress non-error output")
	rootCmd.PersistentFlags().StringVar(&profile, "profile", "", "use a named vault profile")
	profileFlag = rootCmd.PersistentFlags().Lookup("profile")
	_ = rootCmd.RegisterFlagCompletionFunc("profile", profileCompletionFunc)
	rootCmd.PersistentFlags().StringVar(&outputFormat, "output", "text", "Output format (text, json, yaml)")
	rootCmd.PersistentFlags().BoolVar(&noPipeWarning, "no-pipe-warning", false, "suppress 'reading from non-TTY' warning when piping secrets")
	rootCmd.PersistentFlags().StringVar(&colorMode, "color", "auto", "When to emit ANSI color: auto, always, never")
	rootCmd.PersistentFlags().StringVar(&themePreset, "theme", "", "Color preset: default, highcontrast, colorblind (or OPENPASS_THEME)")
}

func vaultPath() (string, error) {
	// 1. --vault flag (highest priority)
	if vaultFlag != nil && vaultFlag.Changed {
		p, err := expandVaultDir(vault)
		if err != nil {
			return "", errorspkg.NewCLIError(errorspkg.ExitGeneralError, "expand vault path", err)
		}
		return p, nil
	}

	// 2. OPENPASS_VAULT env var
	if envVault := strings.TrimSpace(os.Getenv("OPENPASS_VAULT")); envVault != "" {
		p, err := expandVaultDir(envVault)
		if err != nil {
			return "", errorspkg.NewCLIError(errorspkg.ExitGeneralError, "expand vault path", err)
		}
		return p, nil
	}

	// 3. --profile flag
	if profileFlag != nil && profileFlag.Changed {
		profileName := strings.TrimSpace(profile)
		if profileName != "" {
			p, err := resolveProfileVaultDir(profileName)
			if err != nil {
				return "", errorspkg.NewCLIError(errorspkg.ExitGeneralError, "resolve profile", err)
			}
			return p, nil
		}
	}

	// 4. OPENPASS_PROFILE env var
	if envProfile := strings.TrimSpace(os.Getenv("OPENPASS_PROFILE")); envProfile != "" {
		p, err := resolveProfileVaultDir(envProfile)
		if err != nil {
			return "", errorspkg.NewCLIError(errorspkg.ExitGeneralError, "resolve profile", err)
		}
		return p, nil
	}

	// 5. defaultProfile from config
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

	// 6. Default ~/.openpass
	p, err := expandVaultDir(vault)
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

	return expandVaultDir(profile.VaultPath)
}

// unlockVault attempts to decrypt the vault identity.
// When interactive is false, only the keyring and OPENPASS_PASSPHRASE env var are tried.
func unlockVault(vaultDir string, interactive bool) (*vaultpkg.Vault, error) {
	v, _, err := unlockVaultWithTTL(vaultDir, interactive, 0, false)
	return v, err
}

func unlockVaultWithTTL(vaultDir string, interactive bool, ttlOverride time.Duration, cacheEnvPassphrase bool) (*vaultpkg.Vault, time.Duration, error) {
	// 1. Try identity cache first — skips scrypt entirely on cache hit
	if cachedIdentity, cacheErr := sessionLoadIdentity(vaultDir); cacheErr == nil && cachedIdentity != "" {
		if identity, parseErr := age.ParseX25519Identity(cachedIdentity); parseErr == nil {
			v, openErr := vaultpkg.OpenWithCachedIdentity(vaultDir, identity)
			if openErr == nil {
				metrics.RecordIdentityCacheEvent("hit")
				ttl := configuredSessionTTL(v, ttlOverride)
				return v, ttl, nil
			}
		}
		metrics.RecordIdentityCacheEvent("miss")
	} else {
		metrics.RecordIdentityCacheEvent("miss")
	}

	// Load vault config once before the passphrase flow
	cfg := loadVaultConfigForUnlock(vaultDir)

	// 2. Fall back to passphrase-based flow
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

	ttl := configuredSessionTTL(v, ttlOverride)

	// Normal commands avoid persisting env-provided secrets; the unlock command opts in.
	if !passphraseFromEnv || cacheEnvPassphrase {
		if err := sessionSavePassphrase(vaultDir, passphrase, ttl); err != nil {
			return nil, 0, errorspkg.NewCLIError(errorspkg.ExitGeneralError, "save session", err)
		}
		if v != nil && v.Identity != nil {
			_ = sessionSaveIdentity(vaultDir, v.Identity.String(), ttl)
		}
	}
	if cfg.EffectiveAuthMethod() == configpkg.AuthMethodTouchID && !passphraseFromBiometric && (!passphraseFromEnv || cacheEnvPassphrase) {
		if err := sessionSaveBiometric(context.Background(), vaultDir, passphrase); err != nil && interactive {
			fmt.Fprintf(os.Stderr, "Warning: could not update Touch ID unlock: %v\n", err)
		}
	}

	return v, ttl, nil
}

func resolveUnlockPassphrase(vaultDir string, interactive bool, cfg *configpkg.Config) ([]byte, bool, bool, error) {
	passphrase, err := sessionLoadPassphrase(vaultDir)
	passphraseFromEnv := false
	passphraseFromBiometric := false
	if err != nil || len(passphrase) == 0 {
		if cfg.EffectiveAuthMethod() == configpkg.AuthMethodTouchID {
			if biometricPassphrase, biometricErr := sessionLoadBiometric(context.Background(), vaultDir); biometricErr == nil && len(biometricPassphrase) > 0 {
				passphrase = biometricPassphrase
				passphraseFromBiometric = true
			}
		}
		if len(passphrase) == 0 {
			if envPass := os.Getenv("OPENPASS_PASSPHRASE"); envPass != "" {
				passphrase = []byte(envPass)
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
		passphrase, readErr = readHiddenInput("Passphrase: ", nil)
		if readErr != nil {
			return nil, false, false, errorspkg.NewCLIError(errorspkg.ExitLocked, "read passphrase", readErr)
		}
	}
	return passphrase, passphraseFromEnv, passphraseFromBiometric, nil
}

func withVault(fn func(vaultsvc.Service) error) error {
	vaultDir, err := vaultPath()
	if err != nil {
		return err
	}
	if !vaultpkg.IsInitialized(vaultDir) {
		return errorspkg.NewCLIError(errorspkg.ExitNotInitialized,
			"vault not initialized. Run 'openpass init' first",
			errorspkg.ErrVaultNotInitialized)
	}
	v, err := unlockVault(vaultDir, true)
	if err != nil {
		return err
	}
	return fn(vaultsvc.New(slog.Default(), v))
}

func withVaultRaw(fn func(*vaultpkg.Vault) error) error {
	vaultDir, err := vaultPath()
	if err != nil {
		return err
	}
	if !vaultpkg.IsInitialized(vaultDir) {
		return errorspkg.NewCLIError(errorspkg.ExitNotInitialized,
			"vault not initialized. Run 'openpass init' first",
			errorspkg.ErrVaultNotInitialized)
	}
	v, err := unlockVault(vaultDir, true)
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
	status := session.GetCacheStatus()
	if !status.Persistent {
		return "vault locked: this build cannot share 'openpass unlock' sessions across processes; set OPENPASS_PASSPHRASE or use a build with OS keyring support"
	}
	return "vault locked: run 'openpass unlock' first, enable Touch ID with 'openpass auth set touchid', or set OPENPASS_PASSPHRASE"
}

func defaultSessionTTL() time.Duration {
	return configpkg.Default().SessionTimeout
}

func configuredSessionTTL(v *vaultpkg.Vault, override time.Duration) time.Duration {
	if override > 0 {
		return override
	}
	if v != nil && v.Config != nil && v.Config.SessionTimeout > 0 {
		return v.Config.SessionTimeout
	}
	return defaultSessionTTL()
}

func commandRequiresVault(cmd *cobra.Command) bool {
	for current := cmd; current != nil; current = current.Parent() {
		if current.Annotations == nil {
			continue
		}
		if value, ok := current.Annotations[requiresVaultAnnotation]; ok {
			return value != "false"
		}
	}
	return true
}
