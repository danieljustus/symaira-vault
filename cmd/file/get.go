package file

import (
	"encoding/base64"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	cli "github.com/danieljustus/symaira-vault/internal/cli"
	errorspkg "github.com/danieljustus/symaira-vault/internal/errors"
	"github.com/danieljustus/symaira-vault/internal/ui/cliout"
	vaultpkg "github.com/danieljustus/symaira-vault/internal/vault"
)

var (
	GetField string
	GetOut   string
)

var getCmd = &cobra.Command{
	Use:   "get <path>[#field]",
	Short: "Export a stored file attachment to disk",
	Long: `Decodes a vault entry's attachment field back to its original binary
content and writes it to the given output path. Use path#field, or --field,
to select the field when an entry has more than one attachment.`,
	Example: `  symvault file get elster/cert#cert_p12 --out ~/elster.pfx`,
	Args:    cobra.ExactArgs(1),
	RunE:    runFileGet,
}

func runFileGet(cmd *cobra.Command, args []string) error {
	path, field := splitPathField(args[0])
	if field == "" {
		field = GetField
	}
	if GetOut == "" {
		return errorspkg.NewCLIError(errorspkg.ExitInvalidInput, "--out is required", nil)
	}

	return cli.WithVaultRaw(func(v *vaultpkg.Vault, vs *cli.VaultService) error {
		entry, err := vs.GetEntry(path)
		if err != nil {
			return errorspkg.ReadFailed(err, "cannot read entry")
		}

		resolvedField, attachment, resolveErr := resolveAttachmentField(entry, field)
		if resolveErr != nil {
			return resolveErr
		}

		raw, ok := entry.Data[resolvedField]
		if !ok {
			return errorspkg.NewCLIError(errorspkg.ExitNotFound, fmt.Sprintf("field %q not found in entry %q", resolvedField, path), nil)
		}
		encoded, ok := raw.(string)
		if !ok {
			return errorspkg.NewCLIError(errorspkg.ExitGeneralError, fmt.Sprintf("field %q is not string-encoded content", resolvedField), nil)
		}

		content, decErr := base64.StdEncoding.DecodeString(encoded)
		if decErr != nil {
			return errorspkg.Wrap(errorspkg.ExitGeneralError, errorspkg.ErrKindNone, decErr, "decode attachment content")
		}

		if attachment != nil {
			if got := vaultpkg.HashAttachmentSHA256(content); got != attachment.SHA256 {
				cliout.Warnf("Warning: sha256 mismatch for %s#%s (expected %s, got %s)", path, resolvedField, attachment.SHA256, got)
			}
		}

		if err := os.WriteFile(GetOut, content, 0o600); err != nil {
			return errorspkg.WriteFailed(err, "cannot write output file")
		}

		cli.PrintQuietAware("Exported %s#%s to %s (%d bytes)\n", path, resolvedField, GetOut, len(content))
		return nil
	})
}

func init() {
	getCmd.Flags().StringVar(&GetField, "field", "", "Data field to export (auto-detected when the entry has exactly one attachment)")
	getCmd.Flags().StringVar(&GetOut, "out", "", "Output file path (required)")
	fileCmd.AddCommand(getCmd)
}
