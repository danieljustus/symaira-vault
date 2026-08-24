package file

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	cli "github.com/danieljustus/symaira-vault/internal/cli"
	errorspkg "github.com/danieljustus/symaira-vault/internal/errors"
	"github.com/danieljustus/symaira-vault/internal/secrets"
	vaultpkg "github.com/danieljustus/symaira-vault/internal/vault"
)

var (
	UseField   string
	UseAs      string
	UseTimeout time.Duration
)

// newUseCmd builds the `file use` command and registers its flags inline.
func newUseCmd() *cobra.Command {
	useCmd := &cobra.Command{
		Use:   "use <path>[#field] -- <command> [args...]",
		Short: "Run a command with a stored file attachment materialized to an ephemeral path",
		Long: `Decodes a vault entry's attachment field back to its original binary
content, writes it to a private ephemeral file for the lifetime of the given
command, exposes it as $SYMVAULT_FILE_<NAME>, and shreds it afterward — the
CLI twin of the MCP run_command "files" map.`,
		Example: `  symvault file use elster/cert -- java -jar elstertool.jar --cert $SYMVAULT_FILE_CERT_P12`,
		Args:    cobra.MinimumNArgs(2),
		RunE:    runFileUse,
	}

	useCmd.Flags().StringVar(&UseField, "field", "", "Data field to materialize (auto-detected when the entry has exactly one attachment)")
	useCmd.Flags().StringVar(&UseAs, "as", "", "Name exposed as $SYMVAULT_FILE_<NAME> (defaults to the uppercased field name)")
	useCmd.Flags().DurationVarP(&UseTimeout, "timeout", "t", 0, "Timeout for the command (e.g., 30s)")
	return useCmd
}

func runFileUse(cmd *cobra.Command, args []string) error {
	path, field := splitPathField(args[0])
	if field == "" {
		field = UseField
	}
	command := args[1:]

	return cli.WithVaultRaw(func(v *vaultpkg.Vault, vs *cli.VaultService) error {
		entry, err := vs.GetEntry(path)
		if err != nil {
			return errorspkg.ReadFailed(err, "cannot read entry")
		}

		resolvedField, _, resolveErr := resolveAttachmentField(entry, field)
		if resolveErr != nil {
			return resolveErr
		}

		content, decErr := decodeAttachmentContent(entry, resolvedField)
		if decErr != nil {
			return decErr
		}

		name := UseAs
		if name == "" {
			name = strings.ToUpper(resolvedField)
		}

		result, runErr := secrets.RunCommand(secrets.RunOptions{
			Command: command,
			Files:   map[string]string{name: string(content)},
			Timeout: UseTimeout,
		})
		if runErr != nil {
			return runErr
		}

		if result.Stdout != "" {
			_, _ = fmt.Print(result.Stdout)
		}
		if result.Stderr != "" {
			_, _ = fmt.Fprint(os.Stderr, result.Stderr)
		}
		if result.ExitCode != 0 {
			return errorspkg.NewCLIError(errorspkg.ExitGeneralError, fmt.Sprintf("command exited with code %d", result.ExitCode), nil)
		}
		return nil
	})
}
