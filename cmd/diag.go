//go:build metrics

package cmd

import (
	"bytes"
	"fmt"
	cli "github.com/danieljustus/symaira-vault/internal/cli"

	"github.com/prometheus/common/expfmt"
	"github.com/spf13/cobra"

	"github.com/danieljustus/symaira-vault/internal/metrics"
)

func newDiagCmd() *cobra.Command {
	diagCmd := &cobra.Command{
		Use:     "diag",
		Short:   "Diagnostic commands for Symaira Vault",
		Example: `  symvault diag metrics`,
		Annotations: map[string]string{
			requiresVaultAnnotation: "false",
		},
	}
	diagCmd.GroupID = cli.GroupIDAdministration
	diagCmd.AddCommand(newDiagMetricsCmd())
	return diagCmd
}

// diagCmd is intentionally attached to the package-level rootCmd only:
// NewRootCmd() does not include it, so the shipped CLI has no diag
// command. This initializer runs after rootCmd is built (dependency
// order) and preserves that exact tree shape.
var _ = func() int {
	rootCmd.AddCommand(newDiagCmd())
	return 0
}()

func newDiagMetricsCmd() *cobra.Command {
	diagMetricsCmd := &cobra.Command{
		Use:   "metrics",
		Short: "Print current metric values for debugging",
		Annotations: map[string]string{
			requiresVaultAnnotation: "false",
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			return printMetrics(cmd)
		},
	}
	return diagMetricsCmd
}

func printMetrics(cmd *cobra.Command) error {
	reg := metrics.Registry()

	metricFamilies, err := reg.Gather()
	if err != nil {
		return fmt.Errorf("gather metrics: %w", err)
	}

	if len(metricFamilies) == 0 {
		cmd.Println("No metrics collected yet.")
		return nil
	}

	var buf bytes.Buffer
	encoder := expfmt.NewEncoder(&buf, expfmt.NewFormat(expfmt.TypeTextPlain))

	for _, mf := range metricFamilies {
		if err := encoder.Encode(mf); err != nil {
			return fmt.Errorf("encode metric %s: %w", *mf.Name, err)
		}
	}

	cmd.Print(buf.String())
	return nil
}
