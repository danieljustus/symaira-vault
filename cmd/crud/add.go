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
	RunE: func(cmd *cobra.Command, args []string) error {
		return cli.WithVaultRaw(func(v *vaultpkg.Vault) error {
			name := args[0]

			if _, err := vaultpkg.ReadEntry(v.Dir, name, v.Identity); err == nil {
				return fmt.Errorf("entry already exists: %s (use 'set' to update or 'edit' to modify)", name)
			}

			// Read values from stdin to avoid argv leaks
			var stdinLines []string
			if AddStdinValue || AddStdinTOTP {
				stdinReader := bufio.NewReader(os.Stdin)
				if AddStdinValue {
					line, err := stdinReader.ReadString('\n')
					if err != nil {
						return fmt.Errorf("read --stdin-value: %w", err)
					}
					stdinLines = append(stdinLines, strings.TrimRight(line, "\n\r"))
				}
				if AddStdinTOTP {
					line, err := stdinReader.ReadString('\n')
					if err != nil {
						return fmt.Errorf("read --stdin-totp-secret: %w", err)
					}
					stdinLines = append(stdinLines, strings.TrimRight(line, "\n\r"))
				}
			}
			lineIdx := 0
			if AddStdinValue {
				AddValue = stdinLines[lineIdx]
				lineIdx++
			}
			if AddStdinTOTP {
				AddTOTPSecret = stdinLines[lineIdx]
			}

			// Warn about argv-exposed flags on interactive TTY
			if AddValue != "" {
				fdRaw := os.Stdin.Fd()
				if fdRaw <= uintptr(^uint(0)>>1) {
					fd := int(fdRaw)
					if cli.IsTerminalFunc(fd) {
						fmt.Fprintf(os.Stderr, "Warning: --value is visible in process listings (ps aux). Use --stdin-value for secure input.\n")
					}
				}
			}
			if AddTOTPSecret != "" && !AddStdinTOTP {
				fdRaw := os.Stdin.Fd()
				if fdRaw <= uintptr(^uint(0)>>1) {
					fd := int(fdRaw)
					if cli.IsTerminalFunc(fd) {
						fmt.Fprintf(os.Stderr, "Warning: --totp-secret is visible in process listings (ps aux). Use --stdin-totp-secret for secure input.\n")
					}
				}
			}

			data := map[string]any{}
			var secretMeta vaultpkg.SecretMetadata
			var reader *bufio.Reader
			var readerUsed bool

			if AddUsername != "" {
				data["username"] = AddUsername
			}

			if AddValue != "" {
				data["password"] = AddValue
				if !AddForce {
					if err := cryptopkg.ValidatePasswordStrength(AddValue); err != nil {
						return err
					}
				}
				if AddType == "" {
					AddType = string(vaultpkg.DetectSecretType(AddValue))
				}
			} else if AddGenerate {
				password, cleanup, err := cli.GeneratePassword(AddLength, true)
				if err != nil {
					return fmt.Errorf("generate password: %w", err)
				}
				if cleanup != nil {
					defer cleanup()
				}
				data["password"] = password
				if AddType == "" {
					AddType = string(vaultpkg.SecretTypePassword)
				}
			} else {
				fdRaw := os.Stdin.Fd()
				if fdRaw > uintptr(^uint(0)>>1) {
					return fmt.Errorf("file descriptor %d exceeds int range", fdRaw)
				}
				fd := int(fdRaw)

				if cli.IsTerminalFunc(fd) {
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

					formData, formMeta, err := forms.RunAddEntryForm(AddForce, defaults)
					if err != nil {
						return err
					}
					for k, v := range formData {
						data[k] = v
					}
					secretMeta = formMeta
				} else {
					reader = bufio.NewReader(os.Stdin)
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
						return err
					}
					for k, v := range collected {
						data[k] = v
					}
					readerUsed = true
				}
			}

			if !readerUsed {
				if AddURL != "" {
					data["url"] = AddURL
				}
			}

			if !readerUsed {
				if AddNotes != "" {
					data["notes"] = AddNotes
				}
			}

			if !readerUsed {
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

			if secretMeta.Type == "" && AddType != "" {
				secretMeta.Type = vaultpkg.SecretTypeFromString(AddType)
			}
			if secretMeta.UsageHint == "" {
				if AddUsageHint != "" {
					secretMeta.UsageHint = AddUsageHint
				} else if secretMeta.Type != "" {
					secretMeta.UsageHint = vaultpkg.UsageHintForType(secretMeta.Type)
				}
			}
			if !secretMeta.AutoRotate && AddAutoRotate {
				secretMeta.AutoRotate = true
			}
			if AddExpiresAt != "" {
				if t, err := time.Parse(time.RFC3339, AddExpiresAt); err == nil {
					secretMeta.ExpiresAt = &t
				} else {
					return fmt.Errorf("invalid expires_at format, use RFC3339: %w", err)
				}
			}

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
				return fmt.Errorf("cannot create entry: %w", err)
			}

			if err := v.AutoCommit(fmt.Sprintf("Add %s", name)); err != nil {
				cliout.Warnf("Warning: auto-commit failed: %v", err)
			}
			cli.PrintQuietAware("Entry created: %s\n", name)
			return nil
		})
	},
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
