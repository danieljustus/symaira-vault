package crud

import (
	"fmt"
	"os"

	cli "github.com/danieljustus/symaira-vault/internal/cli"

	"github.com/spf13/cobra"

	errorspkg "github.com/danieljustus/symaira-vault/internal/errors"
	"github.com/danieljustus/symaira-vault/internal/secureedit"
	"github.com/danieljustus/symaira-vault/internal/ui/cliout"
	vaultpkg "github.com/danieljustus/symaira-vault/internal/vault"
)

var EditorFlag string

// OSCreateTemp is overridable in tests for permission verification.
var OSCreateTemp = secureedit.CreateTemp

var editCmd = &cobra.Command{
	Use:     "edit <name>",
	Aliases: []string{"modify"},
	Short:   "Edit an existing password entry",
	Long: `Opens an existing password entry in your default editor for modification.

The entry is opened in JSON format. Save and exit the editor to update the entry.
If the entry does not exist, an error is returned.

The editor is determined by the --editor flag or EDITOR environment variable (defaults to vi).`,
	Example: `  symvault edit github
  symvault edit work/aws
  symvault edit personal/bank --editor nano
  EDITOR=nano symvault edit personal/bank`,
	Args:              cobra.ExactArgs(1),
	ValidArgsFunction: cli.EntryCompletionFunc,
	RunE: func(cmd *cobra.Command, args []string) error {
		return cli.WithVaultRaw(func(v *vaultpkg.Vault, vs *cli.VaultService) error {
			name := args[0]

			entry, err := vs.GetEntry(name)
			if err != nil {
				return errorspkg.NotFound("entry not found: %s", name)
			}

			editor := EditorFlag
			if editor == "" {
				editor = os.Getenv("EDITOR")
			}
			if editor == "" {
				editor = "vi"
			}

			secureedit.CreateTemp = OSCreateTemp
			defer func() { secureedit.CreateTemp = os.CreateTemp }()
			updatedEntry, err := secureedit.EditEntry(entry, editor, secureedit.DefaultStreams())
			if err != nil {
				return errorspkg.Wrap(errorspkg.ExitGeneralError, errorspkg.ErrKindNone, err, "edit entry")
			}

			if err := vs.WriteEntry(name, updatedEntry); err != nil {
				return errorspkg.WriteFailed(err, "cannot save entry")
			}

			if err := v.AutoCommit(fmt.Sprintf("Edit %s", name)); err != nil {
				cliout.Warnf("Warning: auto-commit failed: %v", err)
			}
			cli.PrintQuietAware("Entry updated: %s\n", name)
			return nil
		})
	},
}

func init() {
	editCmd.Flags().StringVar(&EditorFlag, "editor", "", "Editor to use (overrides EDITOR env var)")
	cli.RootCmd.AddCommand(editCmd)
}
