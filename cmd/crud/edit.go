package crud

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"

	cli "github.com/danieljustus/symaira-vault/internal/cli"

	"github.com/spf13/cobra"

	errorspkg "github.com/danieljustus/symaira-vault/internal/errors"
	"github.com/danieljustus/symaira-vault/internal/secrets"
	"github.com/danieljustus/symaira-vault/internal/ui/cliout"
	vaultpkg "github.com/danieljustus/symaira-vault/internal/vault"
)

var EditorFlag string

// OSCreateTemp is overridable in tests for permission verification.
var OSCreateTemp = os.CreateTemp

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
		return cli.WithVaultRaw(func(v *vaultpkg.Vault) error {
			name := args[0]

			entry, err := vaultpkg.ReadEntry(v.Dir, name, v.Identity)
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

			// Validate editor exists in PATH before executing (G204 mitigation)
			if _, lookErr := exec.LookPath(editor); lookErr != nil {
				return errorspkg.Wrap(errorspkg.ExitGeneralError, errorspkg.ErrKindNone, lookErr, "editor %q not found in PATH", editor)
			}

			var tmpFile *os.File
			tmpFile, err = OSCreateTemp("", "symvault-edit-*.json")
			if err != nil {
				return errorspkg.WriteFailed(err, "cannot create temp file")
			}
			if err = os.Chmod(tmpFile.Name(), 0o600); err != nil {
				_ = tmpFile.Close()
				_ = os.Remove(tmpFile.Name())
				return errorspkg.WriteFailed(err, "cannot set temp file permissions")
			}
			defer func() { _ = os.Remove(tmpFile.Name()) }()

			encoder := json.NewEncoder(tmpFile)
			encoder.SetIndent("", "  ")
			if encErr := encoder.Encode(entry); encErr != nil {
				_ = tmpFile.Close()
				return errorspkg.WriteFailed(encErr, "cannot encode entry")
			}
			if closeErr := tmpFile.Close(); closeErr != nil {
				return errorspkg.WriteFailed(closeErr, "cannot close temp file")
			}

			//#nosec G204 -- editor path validated via exec.LookPath above
			editorCmd := exec.Command(editor, tmpFile.Name())
			secrets.PrepareCmd(editorCmd)
			editorCmd.Stdin = os.Stdin
			editorCmd.Stdout = os.Stdout
			editorCmd.Stderr = os.Stderr

			if runErr := editorCmd.Run(); runErr != nil {
				return errorspkg.Wrap(errorspkg.ExitGeneralError, errorspkg.ErrKindNone, runErr, "editor failed")
			}

			content, err := os.ReadFile(tmpFile.Name())
			if err != nil {
				return errorspkg.ReadFailed(err, "cannot read edited file")
			}

			content = bytes.TrimSpace(content)
			if len(content) == 0 {
				return fmt.Errorf("empty file, changes discarded")
			}

			var updatedEntry vaultpkg.Entry
			if err := json.Unmarshal(content, &updatedEntry); err != nil {
				return errorspkg.Wrap(errorspkg.ExitGeneralError, errorspkg.ErrKindNone, err, "invalid JSON")
			}

			if updatedEntry.Data == nil {
				updatedEntry.Data = map[string]any{}
			}

			if err := vaultpkg.WriteEntryWithRecipients(v.Dir, name, &updatedEntry, v.Identity); err != nil {
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
