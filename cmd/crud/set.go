package crud

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	cli "github.com/danieljustus/OpenPass/internal/cli"

	"github.com/spf13/cobra"

	cryptopkg "github.com/danieljustus/OpenPass/internal/crypto"
	vaultsvc "github.com/danieljustus/OpenPass/internal/vaultsvc"
)

var (
	SetValue       string
	SetTOTPSecret  string
	SetTOTPIssuer  string
	SetTOTPAccount string
	SetForce       bool
)

var setCmd = &cobra.Command{
	Use:   "set <path[.field]> [--value value]",
	Short: "Set a password entry or field",
	Long:  "Creates or updates a password entry. Use --value or interactive mode.",
	Example: `  # Set a field non-interactively
  openpass set github.password --value "mysecret"

  # Set TOTP data
  openpass set github --totp-secret JBSWY3DPEHPK3PXP`,
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

		data := map[string]any{}
		if SetValue != "" {
			if field != "" {
				data[field] = SetValue
			} else {
				data["password"] = SetValue
			}
			if !SetForce && (field == "" || field == "password") {
				if err := cryptopkg.ValidatePasswordStrength(SetValue); err != nil {
					return err
				}
			}
		} else {
			reader := bufio.NewReader(os.Stdin)
			if field != "" {
				fmt.Fprintf(os.Stderr, "Enter value for %s: ", field)
				value, err := reader.ReadString('\n')
				if err != nil && value == "" {
					return fmt.Errorf("read value: %w", err)
				}
				data[field] = strings.TrimSpace(value)
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

		return cli.WithVault(func(svc vaultsvc.Service) error {
			if err := svc.SetFields(path, data); err != nil {
				return fmt.Errorf("cannot write entry: %w", err)
			}
			cli.PrintQuietAware("Entry saved: %s\n", path)
			return nil
		})
	},
}

func init() {
	setCmd.Flags().StringVar(&SetValue, "value", "", "Value to set (skip interactive)")
	setCmd.Flags().StringVar(&SetTOTPSecret, "totp-secret", "", "TOTP secret key (base32 encoded)")
	setCmd.Flags().StringVar(&SetTOTPIssuer, "totp-issuer", "", "TOTP issuer/service name")
	setCmd.Flags().StringVar(&SetTOTPAccount, "totp-account", "", "TOTP account name/username")
	setCmd.Flags().BoolVar(&SetForce, "force", false, "Skip password strength validation")
	cli.RootCmd.AddCommand(setCmd)
}
