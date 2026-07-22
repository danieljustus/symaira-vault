package file

import (
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	cli "github.com/danieljustus/symaira-vault/internal/cli"
	errorspkg "github.com/danieljustus/symaira-vault/internal/errors"
	"github.com/danieljustus/symaira-vault/internal/secrets"
	"github.com/danieljustus/symaira-vault/internal/ui/cliout"
	vaultpkg "github.com/danieljustus/symaira-vault/internal/vault"
)

// DefaultMaxAttachmentSize caps a stored attachment's original (pre-base64)
// size, keeping vault entries and git history sane by default.
const DefaultMaxAttachmentSize int64 = 1 << 20 // 1 MiB

var (
	AddField   string
	AddFrom    string
	AddType    = string(vaultpkg.SecretTypeCertificate)
	AddMaxSize = DefaultMaxAttachmentSize
	AddShred   bool
)

var addCmd = &cobra.Command{
	Use:   "add <path>",
	Short: "Attach a certificate/key file to a vault entry",
	Long: `Reads a file from disk, base64-encodes it, and stores it in the named
vault entry's field, recording sha256, original filename and size as
attachment metadata. Creates the entry if it does not exist, or merges the
field into an existing entry.`,
	Example: `  symvault file add elster/cert --field cert_p12 --from ~/Downloads/elster.pfx --shred`,
	Args:    cobra.ExactArgs(1),
	RunE:    runFileAdd,
}

func runFileAdd(cmd *cobra.Command, args []string) error {
	path := args[0]
	if AddField == "" {
		return errorspkg.NewCLIError(errorspkg.ExitInvalidInput, "--field is required", nil)
	}
	if AddFrom == "" {
		return errorspkg.NewCLIError(errorspkg.ExitInvalidInput, "--from is required", nil)
	}

	info, statErr := os.Stat(AddFrom)
	if statErr != nil {
		return errorspkg.ReadFailed(statErr, "cannot stat source file")
	}
	if info.Size() > AddMaxSize {
		return errorspkg.NewCLIError(errorspkg.ExitInvalidInput,
			fmt.Sprintf("source file is %d bytes, exceeds the %d byte limit (override with --max-size)", info.Size(), AddMaxSize), nil)
	}

	content, readErr := os.ReadFile(AddFrom) // #nosec G304 -- user-provided CLI argument, size already bounded above
	if readErr != nil {
		return errorspkg.ReadFailed(readErr, "cannot read source file")
	}

	sha := vaultpkg.HashAttachmentSHA256(content)
	encoded := base64.StdEncoding.EncodeToString(content)

	return cli.WithVaultRaw(func(v *vaultpkg.Vault, vs *cli.VaultService) error {
		// Attachment content (base64) routinely exceeds the generic
		// vs.SetFields/UpsertEntry field-length cap (4096 chars, meant for
		// pasted secrets, not files) — read-or-create and vs.WriteEntry
		// directly instead, so --max-size is the only size gate that applies.
		entry, err := vs.GetEntry(path)
		if err != nil {
			var cliErr *errorspkg.CLIError
			if errors.As(err, &cliErr) && cliErr.Code == errorspkg.ExitNotFound {
				entry = &vaultpkg.Entry{Data: map[string]any{}}
			} else {
				return errorspkg.ReadFailed(err, "cannot read entry")
			}
		}
		if entry.Data == nil {
			entry.Data = map[string]any{}
		}
		entry.Data[AddField] = encoded

		if entry.SecretMetadata.Attachments == nil {
			entry.SecretMetadata.Attachments = map[string]vaultpkg.AttachmentInfo{}
		}
		entry.SecretMetadata.Attachments[AddField] = vaultpkg.AttachmentInfo{
			Filename: filepath.Base(AddFrom),
			Size:     int64(len(content)),
			SHA256:   sha,
		}
		if entry.SecretMetadata.Type == "" {
			entry.SecretMetadata.Type = vaultpkg.SecretTypeFromString(AddType)
		}

		now := time.Now().UTC()
		if entry.Metadata.Created.IsZero() {
			entry.Metadata.Created = now
		}
		entry.Metadata.Updated = now
		entry.Metadata.Version++

		if err := vs.WriteEntry(path, entry); err != nil {
			return errorspkg.WriteFailed(err, "cannot write attachment")
		}

		if commitErr := v.AutoCommitEntry(fmt.Sprintf("Attach %s to %s", filepath.Base(AddFrom), path), path); commitErr != nil {
			cliout.Warnf("Warning: auto-commit failed: %v", commitErr)
		}

		cli.PrintQuietAware("Attached %s to %s#%s (%d bytes, sha256:%s)\n", filepath.Base(AddFrom), path, AddField, len(content), sha)

		if AddShred {
			secrets.ShredFile(AddFrom)
			cli.PrintQuietAware("Shredded source file: %s\n", AddFrom)
		}
		return nil
	})
}

func init() {
	addCmd.Flags().StringVar(&AddField, "field", "", "Data field name to store the attachment under (required)")
	addCmd.Flags().StringVar(&AddFrom, "from", "", "Path to the source file to attach (required)")
	addCmd.Flags().StringVar(&AddType, "type", string(vaultpkg.SecretTypeCertificate), "Secret type to set on the entry if not already set")
	addCmd.Flags().Int64Var(&AddMaxSize, "max-size", DefaultMaxAttachmentSize, "Maximum source file size in bytes")
	addCmd.Flags().BoolVar(&AddShred, "shred", false, "Best-effort overwrite and remove the source file after a successful attach")
	fileCmd.AddCommand(addCmd)
}
