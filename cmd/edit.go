package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"

	"github.com/spf13/cobra"

	"github.com/danieljustus/OpenPass/internal/envfilter"
	errorspkg "github.com/danieljustus/OpenPass/internal/errors"
	"github.com/danieljustus/OpenPass/internal/ui/cliout"
	vaultpkg "github.com/danieljustus/OpenPass/internal/vault"
)

var editorFlag string

var editCmd = &cobra.Command{
	Use:     "edit <name>",
	Aliases: []string{"modify"},
	Short:   "Edit an existing password entry",
	Long: `Opens an existing password entry in your default editor for modification.

The entry is opened in JSON format. Save and exit the editor to update the entry.
If the entry does not exist, an error is returned.

The editor is determined by the --editor flag or EDITOR environment variable (defaults to vi).`,
	Example: `  openpass edit github
  openpass edit work/aws
  openpass edit personal/bank --editor nano
  EDITOR=nano openpass edit personal/bank`,
	Args:              cobra.ExactArgs(1),
	ValidArgsFunction: entryCompletionFunc,
	RunE: func(cmd *cobra.Command, args []string) error {
		return withVaultRaw(func(v *vaultpkg.Vault) error {
			name := args[0]

			entry, err := vaultpkg.ReadEntry(v.Dir, name, v.Identity)
			if err != nil {
				return errorspkg.NewCLIError(errorspkg.ExitNotFound, fmt.Sprintf("entry not found: %s", name), errorspkg.ErrEntryNotFound)
			}

			editor := editorFlag
			if editor == "" {
				editor = os.Getenv("EDITOR")
			}
			if editor == "" {
				editor = "vi"
			}

			// Validate editor exists in PATH before executing (G204 mitigation)
			if _, lookErr := exec.LookPath(editor); lookErr != nil {
				return fmt.Errorf("editor %q not found in PATH: %w", editor, lookErr)
			}

			tmpFile, err := os.CreateTemp("", "openpass-edit-*.json")
			if err != nil {
				return fmt.Errorf("cannot create temp file: %w", err)
			}
			defer func() { _ = os.Remove(tmpFile.Name()) }()

			encoder := json.NewEncoder(tmpFile)
			encoder.SetIndent("", "  ")
			if encErr := encoder.Encode(entry); encErr != nil {
				_ = tmpFile.Close()
				return fmt.Errorf("cannot encode entry: %w", encErr)
			}
			if closeErr := tmpFile.Close(); closeErr != nil {
				return fmt.Errorf("cannot close temp file: %w", closeErr)
			}

			//#nosec G204 -- editor path validated via exec.LookPath above
			editorCmd := exec.Command(editor, tmpFile.Name())
			envfilter.PrepareCmd(editorCmd)
			editorCmd.Stdin = os.Stdin
			editorCmd.Stdout = os.Stdout
			editorCmd.Stderr = os.Stderr

			if runErr := editorCmd.Run(); runErr != nil {
				return fmt.Errorf("editor failed: %w", runErr)
			}

			content, err := os.ReadFile(tmpFile.Name())
			if err != nil {
				return fmt.Errorf("cannot read edited file: %w", err)
			}

			content = bytes.TrimSpace(content)
			if len(content) == 0 {
				return fmt.Errorf("empty file, changes discarded")
			}

			var updatedEntry vaultpkg.Entry
			if err := json.Unmarshal(content, &updatedEntry); err != nil {
				return fmt.Errorf("invalid JSON: %w", err)
			}

			if updatedEntry.Data == nil {
				updatedEntry.Data = map[string]any{}
			}

			if err := vaultpkg.WriteEntryWithRecipients(v.Dir, name, &updatedEntry, v.Identity); err != nil {
				return fmt.Errorf("cannot save entry: %w", err)
			}

			if err := v.AutoCommit(fmt.Sprintf("Edit %s", name)); err != nil {
				cliout.Warnf("Warning: auto-commit failed: %v", err)
			}
			printQuietAware("Entry updated: %s\n", name)
			return nil
		})
	},
}

func init() {
	editCmd.Flags().StringVar(&editorFlag, "editor", "", "Editor to use (overrides EDITOR env var)")
	rootCmd.AddCommand(editCmd)
}
