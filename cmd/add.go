// Package cmd implements the OpenPass CLI commands using Cobra.
package cmd

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	cryptopkg "github.com/danieljustus/OpenPass/internal/crypto"
	"github.com/danieljustus/OpenPass/internal/ui/cliout"
	"github.com/danieljustus/OpenPass/internal/ui/forms"
	vaultpkg "github.com/danieljustus/OpenPass/internal/vault"
)

var (
	addValue       string
	addStdinValue  bool
	addStdinTOTP   bool
	addGenerate    bool
	addLength      int
	addUsername    string
	addURL         string
	addNotes       string
	addTOTPSecret  string
	addTOTPIssuer  string
	addTOTPAccount string
	addForce       bool
	addType        string
	addUsageHint   string
	addAutoRotate  bool
	addExpiresAt   string
)

var addCmd = &cobra.Command{
	Use:               "add <name>",
	Aliases:           []string{"new", "create"},
	ValidArgsFunction: entryCompletionFunc,
	Short:             "Add a new password entry",
	Long: `Creates a new password entry in the vault.

The entry name can use slash notation for organization (e.g., work/aws).
Interactive mode prompts for username, password, and URL.`,
	Example: `  openpass add github
  openpass add work/aws
  openpass add personal/bank
  openpass add github-token --value "my-secret-token"
  openpass add secure-pass --generate --length 20
  openpass add aws-key --type api_key --value "AKIA..."
  openpass add ssh-key --type ssh_key --usage-hint "Production server key"`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return withVaultRaw(func(v *vaultpkg.Vault) error {
			name := args[0]

			if _, err := vaultpkg.ReadEntry(v.Dir, name, v.Identity); err == nil {
				return fmt.Errorf("entry already exists: %s (use 'set' to update or 'edit' to modify)", name)
			}

			// Read values from stdin to avoid argv leaks
			var stdinLines []string
			if addStdinValue || addStdinTOTP {
				stdinReader := bufio.NewReader(os.Stdin)
				if addStdinValue {
					line, err := stdinReader.ReadString('\n')
					if err != nil {
						return fmt.Errorf("read --stdin-value: %w", err)
					}
					stdinLines = append(stdinLines, strings.TrimRight(line, "\n\r"))
				}
				if addStdinTOTP {
					line, err := stdinReader.ReadString('\n')
					if err != nil {
						return fmt.Errorf("read --stdin-totp-secret: %w", err)
					}
					stdinLines = append(stdinLines, strings.TrimRight(line, "\n\r"))
				}
			}
			lineIdx := 0
			if addStdinValue {
				addValue = stdinLines[lineIdx]
				lineIdx++
			}
			if addStdinTOTP {
				addTOTPSecret = stdinLines[lineIdx]
			}

			// Warn about argv-exposed flags on interactive TTY
			if addValue != "" {
				fdRaw := os.Stdin.Fd()
				if fdRaw <= uintptr(^uint(0)>>1) {
					fd := int(fdRaw)
					if isTerminalFunc(fd) {
						fmt.Fprintf(os.Stderr, "Warning: --value is visible in process listings (ps aux). Use --stdin-value for secure input.\n")
					}
				}
			}
			if addTOTPSecret != "" && !addStdinTOTP {
				fdRaw := os.Stdin.Fd()
				if fdRaw <= uintptr(^uint(0)>>1) {
					fd := int(fdRaw)
					if isTerminalFunc(fd) {
						fmt.Fprintf(os.Stderr, "Warning: --totp-secret is visible in process listings (ps aux). Use --stdin-totp-secret for secure input.\n")
					}
				}
			}

			data := map[string]any{}
			var secretMeta vaultpkg.SecretMetadata
			var reader *bufio.Reader
			var readerUsed bool

			if addUsername != "" {
				data["username"] = addUsername
			}

			if addValue != "" {
				data["password"] = addValue
				if !addForce {
					if err := cryptopkg.ValidatePasswordStrength(addValue); err != nil {
						return err
					}
				}
				if addType == "" {
					addType = string(vaultpkg.DetectSecretType(addValue))
				}
			} else if addGenerate {
				password, err := generatePassword(addLength, true)
				if err != nil {
					return fmt.Errorf("generate password: %w", err)
				}
				data["password"] = password
				if addType == "" {
					addType = string(vaultpkg.SecretTypePassword)
				}
			} else {
				fdRaw := os.Stdin.Fd()
				if fdRaw > uintptr(^uint(0)>>1) {
					return fmt.Errorf("file descriptor %d exceeds int range", fdRaw)
				}
				fd := int(fdRaw)

				if isTerminalFunc(fd) {
					defaults := map[string]any{}
					if addUsername != "" {
						defaults["username"] = addUsername
					}
					if addURL != "" {
						defaults["url"] = addURL
					}
					if addNotes != "" {
						defaults["notes"] = addNotes
					}
					if addType != "" {
						defaults["_secret_type"] = addType
					}
					if addUsageHint != "" {
						defaults["_usage_hint"] = addUsageHint
					}
					if addAutoRotate {
						defaults["_auto_rotate"] = true
					}
					if addTOTPSecret != "" {
						totpDefaults := map[string]any{
							"secret": addTOTPSecret,
						}
						if addTOTPIssuer != "" {
							totpDefaults["issuer"] = addTOTPIssuer
						}
						if addTOTPAccount != "" {
							totpDefaults["account_name"] = addTOTPAccount
						}
						defaults["totp"] = totpDefaults
					}

					formData, formMeta, err := forms.RunAddEntryForm(addForce, defaults)
					if err != nil {
						return err
					}
					for k, v := range formData {
						data[k] = v
					}
					secretMeta = formMeta
				} else {
					reader = bufio.NewReader(os.Stdin)
					collected, err := collectEntryData(reader, entryFlags{
						username:    addUsername,
						url:         addURL,
						notes:       addNotes,
						totpSecret:  addTOTPSecret,
						totpIssuer:  addTOTPIssuer,
						totpAccount: addTOTPAccount,
						force:       addForce,
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
				if addURL != "" {
					data["url"] = addURL
				}
			}

			if !readerUsed {
				if addNotes != "" {
					data["notes"] = addNotes
				}
			}

			if !readerUsed {
				if addTOTPSecret != "" {
					totpData := map[string]any{
						"secret": addTOTPSecret,
					}
					if addTOTPIssuer != "" {
						totpData["issuer"] = addTOTPIssuer
					}
					if addTOTPAccount != "" {
						totpData["account_name"] = addTOTPAccount
					}
					data["totp"] = totpData
				}
			}

			if secretMeta.Type == "" && addType != "" {
				secretMeta.Type = vaultpkg.SecretTypeFromString(addType)
			}
			if secretMeta.UsageHint == "" {
				if addUsageHint != "" {
					secretMeta.UsageHint = addUsageHint
				} else if secretMeta.Type != "" {
					secretMeta.UsageHint = vaultpkg.UsageHintForType(secretMeta.Type)
				}
			}
			if !secretMeta.AutoRotate && addAutoRotate {
				secretMeta.AutoRotate = true
			}
			if addExpiresAt != "" {
				if t, err := time.Parse(time.RFC3339, addExpiresAt); err == nil {
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
			printQuietAware("Entry created: %s\n", name)
			return nil
		})
	},
}

func init() {
	addCmd.Flags().StringVar(&addValue, "value", "", "Password value (non-interactive, visible in process listings)")
	addCmd.Flags().BoolVar(&addStdinValue, "stdin-value", false, "Read password value from stdin (prevents argv leak)")
	addCmd.Flags().BoolVar(&addStdinTOTP, "stdin-totp-secret", false, "Read TOTP secret from stdin (prevents argv leak)")
	addCmd.Flags().BoolVar(&addGenerate, "generate", false, "Generate a secure password (non-interactive)")
	addCmd.Flags().IntVar(&addLength, "length", 20, "Generated password length for --generate")
	addCmd.Flags().StringVar(&addUsername, "username", "", "Username (non-interactive)")
	addCmd.Flags().StringVar(&addURL, "url", "", "URL (non-interactive)")
	addCmd.Flags().StringVar(&addNotes, "notes", "", "Notes (non-interactive)")
	addCmd.Flags().StringVar(&addTOTPSecret, "totp-secret", "", "TOTP secret key (base32 encoded, visible in process listings)")
	addCmd.Flags().StringVar(&addTOTPIssuer, "totp-issuer", "", "TOTP issuer/service name")
	addCmd.Flags().StringVar(&addTOTPAccount, "totp-account", "", "TOTP account name/username")
	addCmd.Flags().BoolVar(&addForce, "force", false, "Skip password strength validation")
	addCmd.Flags().StringVar(&addType, "type", "", "Secret type (api_key, bearer_token, basic_auth, ssh_key, password, certificate, database_url, totp_seed, custom). Auto-detected if not specified.")
	addCmd.Flags().StringVar(&addUsageHint, "usage-hint", "", "Usage hint for AI agents")
	addCmd.Flags().BoolVar(&addAutoRotate, "auto-rotate", false, "Enable automatic rotation reminder")
	addCmd.Flags().StringVar(&addExpiresAt, "expires-at", "", "Expiration date (RFC3339 format)")
	rootCmd.AddCommand(addCmd)
}
