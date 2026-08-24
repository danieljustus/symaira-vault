package crud

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	cli "github.com/danieljustus/symaira-vault/internal/cli"
	cliinput "github.com/danieljustus/symaira-vault/internal/cli/input"

	"github.com/spf13/cobra"

	cryptopkg "github.com/danieljustus/symaira-vault/internal/crypto"
	errorspkg "github.com/danieljustus/symaira-vault/internal/errors"
	vaultpkg "github.com/danieljustus/symaira-vault/internal/vault"
)

var (
	SetValue       string
	SetStdinValue  bool
	SetAllowEmpty  bool
	SetTOTPSecret  string
	SetTOTPIssuer  string
	SetTOTPAccount string
	SetForce       bool
)

// isSensitiveField reports whether fieldName contains any sensitive substring:
// "password", "token", "secret", "key", "passwd", or "pwd" (case-insensitive).
func isSensitiveField(fieldName string) bool {
	lower := strings.ToLower(fieldName)
	for _, sub := range []string{"password", "token", "secret", "key", "passwd", "pwd"} {
		if strings.Contains(lower, sub) {
			return true
		}
	}
	return false
}

func newSetCmd() *cobra.Command {
	setCmd := &cobra.Command{
		Use:   "set <path[.field]>",
		Short: "Set a password entry or field",
		Long:  "Creates or updates a password entry. Use --value, --stdin-value, or interactive mode.",
		Example: `  # Set a field from stdin
  echo "mysecret" | symvault set github.password --stdin-value

  # Set a field non-interactively (visible in process listing)
  symvault set github.password --value "mysecret"

  # Set TOTP data
  symvault set github --totp-secret JBSWY3DPEHPK3PXP`,
		Args:              cobra.ExactArgs(1),
		ValidArgsFunction: cli.EntryCompletionFunc,
		RunE: func(cmd *cobra.Command, args []string) error {
			query := args[0]
			path := query
			field := ""
			if idx := strings.LastIndex(query, "."); idx > 0 {
				path = query[:idx]
				field = query[idx+1:]
			}

			targetField := field
			if targetField == "" {
				targetField = "password"
			}

			if SetStdinValue {
				stdinReader := bufio.NewReader(os.Stdin)
				line, err := stdinReader.ReadString('\n')
				if err != nil && line == "" {
					return errorspkg.ReadFailed(err, "read --stdin-value")
				}
				SetValue = strings.TrimRight(line, "\n\r")
			}

			warnArgvExposure(SetValue, SetTOTPSecret, false)

			data := map[string]any{}
			isExplicitValue := cmd.Flags().Changed("value") || SetStdinValue

			if isExplicitValue {
				if SetValue == "" && isSensitiveField(targetField) && !SetAllowEmpty {
					return errorspkg.NewCLIError(errorspkg.ExitInvalidInput, fmt.Sprintf("cannot set empty value for sensitive field %q (use --allow-empty to override)", targetField), nil)
				}
				data[targetField] = SetValue
				if !SetForce && (targetField == "password") && SetValue != "" {
					if err := cryptopkg.ValidatePasswordStrength(SetValue); err != nil {
						return err
					}
				}
			} else {
				reader := bufio.NewReader(os.Stdin)
				if field != "" {
					prompt := fmt.Sprintf("Enter value for %s: ", field)
					valueBytes, err := cliinput.ReadHiddenInputFn(prompt, reader)
					if err != nil && len(valueBytes) == 0 {
						return errorspkg.ReadFailed(err, "read value")
					}
					defer cryptopkg.Wipe(valueBytes)
					valueStr := string(valueBytes)

					if isSensitiveField(field) {
						if len(valueBytes) == 0 && !SetAllowEmpty {
							return errorspkg.NewCLIError(errorspkg.ExitInvalidInput, fmt.Sprintf("cannot set empty value for sensitive field %q (use --allow-empty to override)", field), nil)
						}
						if len(valueBytes) > 0 {
							confirmPrompt := fmt.Sprintf("Confirm value for %s: ", field)
							confirmBytes, err := cliinput.ReadHiddenInputFn(confirmPrompt, reader)
							if err != nil && len(confirmBytes) == 0 {
								return errorspkg.ReadFailed(err, "read confirmation")
							}
							defer cryptopkg.Wipe(confirmBytes)
							if len(confirmBytes) == 0 {
								return errorspkg.NewCLIError(errorspkg.ExitInvalidInput, "confirmation cannot be empty", nil)
							}
							if string(confirmBytes) != valueStr {
								return errorspkg.NewCLIError(errorspkg.ExitInvalidInput, "values do not match", nil)
							}
						}
					}
					data[field] = valueStr
				} else {
					collected, err := cli.CollectEntryData(reader, cli.EntryFlags{
						TOTPSecret:      SetTOTPSecret,
						TOTPIssuer:      SetTOTPIssuer,
						TOTPAccount:     SetTOTPAccount,
						Force:           SetForce,
						SkipNotes:       true,
						SkipTOTPDetails: true,
					})
					if err != nil {
						return err
					}
					for k, v := range collected {
						data[k] = v
					}
				}
			}

			if SetTOTPSecret != "" {
				totpData := map[string]any{
					"secret": SetTOTPSecret,
				}
				if SetTOTPIssuer != "" {
					totpData["issuer"] = SetTOTPIssuer
				}
				if SetTOTPAccount != "" {
					totpData["account_name"] = SetTOTPAccount
				}
				data["totp"] = totpData
			}

			if err := cryptopkg.ValidateTOTPData(data); err != nil {
				return err
			}

			return cli.WithVault(func(v *vaultpkg.Vault, vs *cli.VaultService) error {
				if err := vs.SetFields(path, data); err != nil {
					return errorspkg.WriteFailed(err, "cannot write entry")
				}
				cli.PrintQuietAware("Entry saved: %s\n", path)
				return nil
			})
		},
	}

	setCmd.Flags().StringVar(&SetValue, "value", "", "Value to set (non-interactive, visible in process listings)")
	setCmd.Flags().BoolVar(&SetStdinValue, "stdin-value", false, "Read value from stdin (prevents argv leak)")
	setCmd.Flags().BoolVar(&SetAllowEmpty, "allow-empty", false, "Allow setting empty values on sensitive fields")
	setCmd.Flags().StringVar(&SetTOTPSecret, "totp-secret", "", "TOTP secret key (base32 encoded, visible in process listings)")
	setCmd.Flags().StringVar(&SetTOTPIssuer, "totp-issuer", "", "TOTP issuer/service name")
	setCmd.Flags().StringVar(&SetTOTPAccount, "totp-account", "", "TOTP account name/username")
	setCmd.Flags().BoolVar(&SetForce, "force", false, "Skip password strength validation")
	setCmd.GroupID = cli.GroupIDEssentials
	return setCmd
}
