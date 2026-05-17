package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/cobra/doc"
)

var manpagesCmd = &cobra.Command{
	Use:   "manpages <directory>",
	Short: "Generate manual pages",
	Example: `  # Generate man pages into ./man
  openpass manpages ./man

  # System-wide install (requires sudo)
  sudo openpass manpages /usr/local/share/man/man1`,
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
			Title:   strings.ToUpper(rootCmd.Name()),
			Section: "1",
			Manual:  "OpenPass Manual",
			Source:  "OpenPass",
		}
		rootCmd.DisableAutoGenTag = true
		if err := doc.GenManTree(rootCmd, header, dir); err != nil {
			return fmt.Errorf("generate manpages: %w", err)
		}

		if _, err := fmt.Fprintf(cmd.OutOrStdout(), "Generated manpages in %s\n", dir); err != nil {
			return fmt.Errorf("write manpage result: %w", err)
		}
		return nil
	},
}
