package cmd

import (
	"fmt"
	"time"

	"github.com/spf13/cobra"

	cli "github.com/danieljustus/OpenPass/internal/cli"
	"github.com/danieljustus/OpenPass/internal/crypto"
	vaultpkg "github.com/danieljustus/OpenPass/internal/vault"
)

var (
	genLength  int
	genSymbols bool
	genStore   string
	genReveal  bool
	genQuiet   bool
)

var generateCmd = &cobra.Command{
	Use:     "generate",
	Aliases: []string{"gen"},
	Short:   "Generate a secure password",
	Example: `  # Generate a 20-character password
  openpass generate --length 20

  # Include symbols
  openpass generate --length 32 --symbols

  # Generate and store
  openpass generate --store newaccount.password`,
	RunE: func(cmd *cobra.Command, args []string) error {
		password, err := generatePassword(genLength, genSymbols)
		if err != nil {
			return err
		}

		if genStore != "" {
			return withVaultRaw(func(v *vaultpkg.Vault) error {
				entryPath := vaultpkg.EntryPath(v, genStore)
				if _, err := vaultpkg.ReadEntry(v.Dir, genStore, v.Identity); err == nil {
					if _, err := vaultpkg.MergeEntryWithRecipients(v.Dir, genStore, map[string]any{"password": password}, v.Identity); err != nil {
						return fmt.Errorf("cannot store password: %w", err)
					}
				} else {
					entry := &vaultpkg.Entry{Data: map[string]any{"password": password}, Metadata: vaultpkg.EntryMetadata{Created: time.Now().UTC(), Updated: time.Now().UTC(), Version: 0}}
					if err := vaultpkg.WriteEntryWithRecipients(v.Dir, genStore, entry, v.Identity); err != nil {
						return fmt.Errorf("cannot store password: %w", err)
					}
				}

				if err := v.AutoCommit(fmt.Sprintf("Generate password for %s", genStore)); err != nil {
					return fmt.Errorf("auto-commit failed: %w", err)
				}

				if cli.OutputFormat == "text" {
					if genQuiet {
						return nil
					}
					printQuietAware("Password stored at: %s\n", entryPath)
				} else {
					result := map[string]any{
						"stored": true,
						"path":   genStore,
						"file":   entryPath,
					}
					if genReveal {
						result["password"] = password
					}
					if err := PrintResult(result); err != nil {
						return err
					}
				}
				return nil
			})
		}

		if cli.OutputFormat == "text" {
			printlnQuietAware(password)
		} else {
			if err := PrintResult(map[string]interface{}{"password": password}); err != nil {
				return err
			}
		}
		return nil
	},
}

func generatePassword(length int, useSymbols bool) (string, error) {
	if length <= 0 {
		return "", fmt.Errorf("length must be greater than zero")
	}
	if length > crypto.MaxPasswordLength {
		return "", fmt.Errorf("length must be at most %d", crypto.MaxPasswordLength)
	}
	return crypto.GeneratePassword(length, useSymbols)
}

func init() {
	generateCmd.Flags().IntVarP(&genLength, "length", "l", 20, "Password length")
	generateCmd.Flags().BoolVarP(&genSymbols, "symbols", "s", false, "Include symbols")
	generateCmd.Flags().StringVar(&genStore, "store", "", "Store at path (optional)")
	generateCmd.Flags().BoolVar(&genReveal, "reveal", false, "Include generated password in output when using --store")
	generateCmd.Flags().BoolVar(&genQuiet, "quiet", false, "Suppress success output when using --store")
	generateCmd.AddCommand(manpagesCmd)
	rootCmd.AddCommand(generateCmd)
}
