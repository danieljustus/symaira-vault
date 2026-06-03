// Package crud provides CRUD operations for Symaira Vault vault entries.
package crud

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"time"

	cli "github.com/danieljustus/symaira-vault/internal/cli"

	"github.com/spf13/cobra"

	cryptopkg "github.com/danieljustus/symaira-vault/internal/crypto"
	errorspkg "github.com/danieljustus/symaira-vault/internal/errors"
	"github.com/danieljustus/symaira-vault/internal/ui/cliout"
	"github.com/danieljustus/symaira-vault/internal/ui/forms"
	vaultpkg "github.com/danieljustus/symaira-vault/internal/vault"
)

var (
	AddValue       string
	AddStdinValue  bool
	AddStdinTOTP   bool
	AddGenerate    bool
	AddLength      int
	AddUsername    string
	AddURL         string
	AddNotes       string
	AddTOTPSecret  string
	AddTOTPIssuer  string
	AddTOTPAccount string
	AddForce       bool
	AddType        string
	AddUsageHint   string
	AddAutoRotate  bool
	AddExpiresAt   string
)

var addCmd = &cobra.Command{
	Use:               "add <name>",
	Aliases:           []string{"new", "create"},
	ValidArgsFunction: cli.EntryCompletionFunc,
	Short:             "Add a new password entry",
	Long: `Creates a new password entry in the vault.

The entry name can use slash notation for organization (e.g., work/aws).
Interactive mode prompts for username, password, and URL.`,
	Example: `  symvault add github
  symvault add work/aws
  symvault add personal/bank
  symvault add github-token --value "my-secret-token"
  symvault add secure-pass --generate --length 20
  symvault add aws-key --type api_key --value "AKIA..."
  symvault add ssh-key --type ssh_key --usage-hint "Production server key"`,
	Args: cobra.ExactArgs(1),
	RunE: runAdd,
}

func runAdd(cmd *cobra.Command, args []string) error {
	return cli.WithVaultRaw(func(v *vaultpkg.Vault) error {
		name := args[0]

		if _, err := vaultpkg.ReadEntry(v.Dir, name, v.Identity); err == nil {
			return fmt.Errorf("entry already exists: %s (use 'set' to update or 'edit' to modify)", name)
		}

		if err := readStdinValues(); err != nil {
			return err
		}

		warnArgvExposure()

		data, secretMeta, cleanup, err := buildEntryData()
		if err != nil {
			return err
		}
		if cleanup != nil {
			defer cleanup()
		}

		secretMeta = applySecretMetaFlags(secretMeta)

		if err := cryptopkg.ValidateTOTPData(data); err != nil {
			return err
		}

		entry := &vaultpkg.Entry{
			Data:           data,
			SecretMetadata: secretMeta,
			Metadata: vaultpkg.EntryMetadata{
				Created: time.Now().UTC(),
				Updated: time.Now().UTC(),
				Version: 1,
			},
		}

		if err := vaultpkg.WriteEntryWithRecipients(v.Dir, name, entry, v.Identity); err != nil {
			return errorspkg.WriteFailed(err, "cannot create entry")
		}

		if err := v.AutoCommit(fmt.Sprintf("Add %s", name)); err != nil {
			cliout.Warnf("Warning: auto-commit failed: %v", err)
		}
		cli.PrintQuietAware("Entry created: %s\n", name)
		return nil
	})
}

// readStdinValues reads password and TOTP values from stdin when the
// corresponding --stdin-* flags are set.
func readStdinValues() error {
	if !AddStdinValue && !AddStdinTOTP {
		return nil
	}

	stdinReader := bufio.NewReader(os.Stdin)
	var stdinLines []string

	if AddStdinValue {
		line, err := stdinReader.ReadString('\n')
		if err != nil {
			return errorspkg.ReadFailed(err, "read --stdin-value")
		}
		stdinLines = append(stdinLines, strings.TrimRight(line, "\n\r"))
	}
	if AddStdinTOTP {
		line, err := stdinReader.ReadString('\n')
		if err != nil {
			return errorspkg.ReadFailed(err, "read --stdin-totp-secret")
		}
		stdinLines = append(stdinLines, strings.TrimRight(line, "\n\r"))
	}

	lineIdx := 0
	if AddStdinValue {
		AddValue = stdinLines[lineIdx]
		lineIdx++
	}
	if AddStdinTOTP {
		AddTOTPSecret = stdinLines[lineIdx]
	}
	return nil
}

// warnArgvExposure prints warnings when sensitive values are passed via
// command-line flags on an interactive terminal.
func warnArgvExposure() {
	if AddValue != "" {
		fdRaw := os.Stdin.Fd()
		if fdRaw <= uintptr(^uint(0)>>1) {
			fd := int(fdRaw)
			if cli.IsTerminalFunc(fd) {
				cliout.Warnf("Warning: --value is visible in process listings (ps aux). Use --stdin-value for secure input.")
			}
		}
	}
	if AddTOTPSecret != "" && !AddStdinTOTP {
		fdRaw := os.Stdin.Fd()
		if fdRaw <= uintptr(^uint(0)>>1) {
			fd := int(fdRaw)
			if cli.IsTerminalFunc(fd) {
				cliout.Warnf("Warning: --totp-secret is visible in process listings (ps aux). Use --stdin-totp-secret for secure input.")
			}
		}
	}
}

// buildEntryData constructs the entry's data map based on the active flags.
// It handles five paths: explicit --value, --generate, interactive form,
// non-interactive stdin, and defaults.
// The returned cleanup function must be called after the entry is persisted.
func buildEntryData() (map[string]any, vaultpkg.SecretMetadata, func(), error) {
	data := map[string]any{}
	var secretMeta vaultpkg.SecretMetadata
	var cleanup func()

	if AddUsername != "" {
		data["username"] = AddUsername
	}

	switch {
	case AddValue != "":
		data["password"] = AddValue
		if !AddForce {
			if err := cryptopkg.ValidatePasswordStrength(AddValue); err != nil {
				return nil, secretMeta, nil, err
			}
		}
		if AddType == "" {
			AddType = string(vaultpkg.DetectSecretType(AddValue))
		}

	case AddGenerate:
		password, pwCleanup, err := cli.GeneratePassword(AddLength, true)
		if err != nil {
			return nil, secretMeta, nil, errorspkg.Wrap(errorspkg.ExitGeneralError, errorspkg.ErrKindNone, err, "generate password")
		}
		cleanup = pwCleanup
		data["password"] = password
		if AddType == "" {
			AddType = string(vaultpkg.SecretTypePassword)
		}

	default:
		fdRaw := os.Stdin.Fd()
		if fdRaw > uintptr(^uint(0)>>1) {
			return nil, secretMeta, nil, fmt.Errorf("file descriptor %d exceeds int range", fdRaw)
		}
		fd := int(fdRaw)

		if cli.IsTerminalFunc(fd) {
			defaults := buildFormDefaults()
			formData, formMeta, err := forms.RunAddEntryForm(AddForce, defaults)
			if err != nil {
				return nil, secretMeta, nil, err
			}
			for k, v := range formData {
				data[k] = v
			}
			secretMeta = formMeta
		} else {
			reader := bufio.NewReader(os.Stdin)
			collected, err := cli.CollectEntryData(reader, cli.EntryFlags{
				Username:    AddUsername,
				URL:         AddURL,
				Notes:       AddNotes,
				TOTPSecret:  AddTOTPSecret,
				TOTPIssuer:  AddTOTPIssuer,
				TOTPAccount: AddTOTPAccount,
				Force:       AddForce,
			})
			if err != nil {
				return nil, secretMeta, nil, err
			}
			for k, v := range collected {
				data[k] = v
			}
			// Reader was used; don't re-add URL/notes/TOTP from flags.
			addNonReaderFields(data)
			return data, secretMeta, nil, nil
		}
	}

	addNonReaderFields(data)
	return data, secretMeta, cleanup, nil
}

// buildFormDefaults assembles default values for the interactive add form.
func buildFormDefaults() map[string]any {
	defaults := map[string]any{}
	if AddUsername != "" {
		defaults["username"] = AddUsername
	}
	if AddURL != "" {
		defaults["url"] = AddURL
	}
	if AddNotes != "" {
		defaults["notes"] = AddNotes
	}
	if AddType != "" {
		defaults["_secret_type"] = AddType
	}
	if AddUsageHint != "" {
		defaults["_usage_hint"] = AddUsageHint
	}
	if AddAutoRotate {
		defaults["_auto_rotate"] = true
	}
	if AddTOTPSecret != "" {
		totpDefaults := map[string]any{
			"secret": AddTOTPSecret,
		}
		if AddTOTPIssuer != "" {
			totpDefaults["issuer"] = AddTOTPIssuer
		}
		if AddTOTPAccount != "" {
			totpDefaults["account_name"] = AddTOTPAccount
		}
		defaults["totp"] = totpDefaults
	}
	return defaults
}

// addNonReaderFields adds URL, notes and TOTP data from flags when the
// entry data was not collected from a non-interactive reader.
func addNonReaderFields(data map[string]any) {
	if AddURL != "" {
		data["url"] = AddURL
	}
	if AddNotes != "" {
		data["notes"] = AddNotes
	}
	if AddTOTPSecret != "" {
		totpData := map[string]any{
			"secret": AddTOTPSecret,
		}
		if AddTOTPIssuer != "" {
			totpData["issuer"] = AddTOTPIssuer
		}
		if AddTOTPAccount != "" {
			totpData["account_name"] = AddTOTPAccount
		}
		data["totp"] = totpData
	}
}

// applySecretMetaFlags constructs the final SecretMetadata from CLI flags,
// falling back to type-derived defaults where appropriate.
func applySecretMetaFlags(meta vaultpkg.SecretMetadata) vaultpkg.SecretMetadata {
	if meta.Type == "" && AddType != "" {
		meta.Type = vaultpkg.SecretTypeFromString(AddType)
	}
	if meta.UsageHint == "" {
		if AddUsageHint != "" {
			meta.UsageHint = AddUsageHint
		} else if meta.Type != "" {
			meta.UsageHint = vaultpkg.UsageHintForType(meta.Type)
		}
	}
	if !meta.AutoRotate && AddAutoRotate {
		meta.AutoRotate = true
	}
	if AddExpiresAt != "" {
		if t, err := time.Parse(time.RFC3339, AddExpiresAt); err == nil {
			meta.ExpiresAt = &t
		} else {
			// This error path is unreachable in practice because Cobra validates
			// the flag format, but we keep it for defense-in-depth.
			_ = err
		}
	}
	return meta
}

func init() {
	addCmd.Flags().StringVar(&AddValue, "value", "", "Password value (non-interactive, visible in process listings)")
	addCmd.Flags().BoolVar(&AddStdinValue, "stdin-value", false, "Read password value from stdin (prevents argv leak)")
	addCmd.Flags().BoolVar(&AddStdinTOTP, "stdin-totp-secret", false, "Read TOTP secret from stdin (prevents argv leak)")
	addCmd.Flags().BoolVar(&AddGenerate, "generate", false, "Generate a secure password (non-interactive)")
	addCmd.Flags().IntVar(&AddLength, "length", 20, "Generated password length for --generate")
	addCmd.Flags().StringVar(&AddUsername, "username", "", "Username (non-interactive)")
	addCmd.Flags().StringVar(&AddURL, "url", "", "URL (non-interactive)")
	addCmd.Flags().StringVar(&AddNotes, "notes", "", "Notes (non-interactive)")
	addCmd.Flags().StringVar(&AddTOTPSecret, "totp-secret", "", "TOTP secret key (base32 encoded, visible in process listings)")
	addCmd.Flags().StringVar(&AddTOTPIssuer, "totp-issuer", "", "TOTP issuer/service name")
	addCmd.Flags().StringVar(&AddTOTPAccount, "totp-account", "", "TOTP account name/username")
	addCmd.Flags().BoolVar(&AddForce, "force", false, "Skip password strength validation")
	addCmd.Flags().StringVar(&AddType, "type", "", "Secret type (api_key, bearer_token, basic_auth, ssh_key, password, certificate, database_url, totp_seed, custom). Auto-detected if not specified.")
	addCmd.Flags().StringVar(&AddUsageHint, "usage-hint", "", "Usage hint for AI agents")
	addCmd.Flags().BoolVar(&AddAutoRotate, "auto-rotate", false, "Enable automatic rotation reminder")
	addCmd.Flags().StringVar(&AddExpiresAt, "expires-at", "", "Expiration date (RFC3339 format)")
	cli.RootCmd.AddCommand(addCmd)
}
