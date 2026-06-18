package admin

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/danieljustus/symaira-vault/internal/audit"
	cli "github.com/danieljustus/symaira-vault/internal/cli"
)

var (
	auditExportAgent       string
	auditExportAction      string
	auditExportSince       string
	auditExportFailed      bool
	auditExportOutput      string
	auditExportFormat      string
	auditExportVerifyHMAC  bool
	auditExportRedactPaths bool
)

var auditExportCmd = &cobra.Command{
	Use:   "export",
	Short: "Export audit evidence for auditor or incident-response bundles",
	Long: `Export local audit evidence without exposing secret values.

Supports JSON and table output. Filter by time range, agent, and action.
Optionally verify HMAC integrity and redact vault paths.`,
	Example: `  # Export all audit entries as JSON
  symvault audit export --format json

  # Export last 7 days to a file
  symvault audit export --since 7d --output evidence.json

  # Export with path redaction for sharing
  symvault audit export --redact-paths --output shared-evidence.json

  # Verify HMAC integrity
  symvault audit export --verify-hmac

  # Filter by agent and action
  symvault audit export --agent claude-code --action get_entry`,
	Annotations: map[string]string{
		cli.RequiresVaultAnnotation: "false",
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		vaultDir, _ := cli.VaultPath()

		opts := audit.ExportOptions{
			Agent:       auditExportAgent,
			Action:      auditExportAction,
			Since:       auditExportSince,
			FailedOnly:  auditExportFailed,
			RedactPaths: auditExportRedactPaths,
			VerifyHMAC:  auditExportVerifyHMAC,
		}

		if opts.VerifyHMAC && vaultDir != "" {
			ks := audit.NewKeystore(vaultDir, nil)
			key, err := ks.LoadOrCreateHMACKey()
			if err != nil {
				return fmt.Errorf("load HMAC key: %w", err)
			}
			opts.HMACKey = key
		}

		if opts.Action != "" {
			opts.Action = strings.TrimSpace(opts.Action)
		}

		if auditExportOutput != "" {
			cleanPath := filepath.Clean(auditExportOutput)
			dir := filepath.Dir(cleanPath)
			if err := os.MkdirAll(dir, 0o700); err != nil {
				return fmt.Errorf("create output directory: %w", err)
			}

			f, err := os.OpenFile(cleanPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600) // #nosec G304 -- output path is user-provided CLI argument
			if err != nil {
				return fmt.Errorf("create output file: %w", err)
			}
			defer func() { _ = f.Close() }()

			result, err := audit.ExportAuditLog(opts, f, auditExportFormat)
			if err != nil {
				return err
			}
			printExportSummary(cmd, result)
			return nil
		}

		result, err := audit.ExportAuditLog(opts, cmd.OutOrStdout(), auditExportFormat)
		if err != nil {
			return err
		}
		printExportSummary(cmd, result)
		return nil
	},
}

func printExportSummary(cmd *cobra.Command, result *audit.ExportResult) {
	if result == nil {
		return
	}
	cmd.Printf("Exported %d audit entries", result.Total)
	if result.Verified > 0 || result.Tampered > 0 {
		cmd.Printf(" (verified: %d, legacy: %d, tampered: %d)",
			result.Verified, result.Legacy, result.Tampered)
	}
	cmd.Println()
}

func init() {
	auditExportCmd.Flags().StringVar(&auditExportAgent, "agent", "", "Agent name to filter by (default: all agents)")
	auditExportCmd.Flags().StringVar(&auditExportAction, "action", "", "Action type to filter by (e.g. get_entry, set_entry)")
	auditExportCmd.Flags().StringVar(&auditExportSince, "since", "", "Export entries since duration (e.g. 1h, 24h, 7d)")
	auditExportCmd.Flags().BoolVar(&auditExportFailed, "failed", false, "Export only failed entries")
	auditExportCmd.Flags().StringVarP(&auditExportOutput, "output", "o", "", "Output file path (default: stdout)")
	auditExportCmd.Flags().StringVar(&auditExportFormat, "format", "json", "Output format: json or table")
	auditExportCmd.Flags().BoolVar(&auditExportVerifyHMAC, "verify-hmac", false, "Verify HMAC integrity of exported entries")
	auditExportCmd.Flags().BoolVar(&auditExportRedactPaths, "redact-paths", false, "Redact vault paths in exported entries")
	AuditCmd.AddCommand(auditExportCmd)
}
