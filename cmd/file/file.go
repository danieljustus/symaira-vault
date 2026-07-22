// Package file provides CLI commands for storing, exporting, and consuming
// binary file attachments (e.g. a PKCS#12 certificate) through vault entries.
package file

import (
	"github.com/spf13/cobra"

	cli "github.com/danieljustus/symaira-vault/internal/cli"
)

var fileCmd = &cobra.Command{
	Use:   "file",
	Short: "Store, export, and consume file attachments in the vault",
	Long: `Store, export, and consume binary file attachments (e.g. a PKCS#12
certificate) through vault entries. Content is base64-encoded at rest, with
sha256, original filename and size recorded as attachment metadata.`,
	Example: `  symvault file add elster/cert --field cert_p12 --from ~/elster.pfx --shred
  symvault file get elster/cert#cert_p12 --out ~/elster.pfx
  symvault file use elster/cert -- java -jar elstertool.jar --cert $SYMVAULT_FILE_CERT_P12`,
}

func init() {
	cli.RootCmd.AddCommand(fileCmd)
}
