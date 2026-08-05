package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/cobra/doc"
)

// rootForManpages carries the package-level rootCmd for the manpages
// renderer. It exists to break Go's initialization dependency cycle:
// rootCmd -> NewRootCmd -> newGenerateCmd -> newManpagesCmd would
// reference rootCmd again through the RunE closure, which the
// initializer analysis treats as a hard dependency. The assignment below
// runs after rootCmd is initialized (dependency order) and the renderer
// only reads it at runtime.
var rootForManpages *cobra.Command

var _ = func() int {
	rootForManpages = rootCmd
	return 0
}()

func newManpagesCmd() *cobra.Command {
	manpagesCmd := &cobra.Command{
		Use:   "manpages <directory>",
		Short: "Generate manual pages",
		Example: `  # Generate man pages into ./man
  symvault manpages ./man

  # System-wide install (requires sudo)
  sudo symvault manpages /usr/local/share/man/man1`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			dir, err := filepath.Abs(args[0])
			if err != nil {
				return fmt.Errorf("resolve manpage directory: %w", err)
			}
			if err := os.MkdirAll(dir, 0o750); err != nil {
				return fmt.Errorf("create manpage directory: %w", err)
			}

			header := &doc.GenManHeader{
				Title:   strings.ToUpper(rootForManpages.Name()),
				Section: "1",
				Manual:  "Symaira Vault Manual",
				Source:  "Symaira Vault",
			}
			rootForManpages.DisableAutoGenTag = true
			if err := doc.GenManTree(rootForManpages, header, dir); err != nil {
				return fmt.Errorf("generate manpages: %w", err)
			}

			if _, err := fmt.Fprintf(cmd.OutOrStdout(), "Generated manpages in %s\n", dir); err != nil {
				return fmt.Errorf("write manpage result: %w", err)
			}
			return nil
		},
	}
	return manpagesCmd
}
