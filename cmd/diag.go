//go:build metrics

package cmd

import (
	"bytes"
	"fmt"

	"github.com/prometheus/common/expfmt"
	"github.com/spf13/cobra"

	"github.com/danieljustus/OpenPass/internal/metrics"
)

var diagCmd = &cobra.Command{
	Use:     "diag",
	Short:   "Diagnostic commands for OpenPass",
	Example: `  openpass diag metrics`,
	Annotations: map[string]string{
		requiresVaultAnnotation: "false",
	},
}

var diagMetricsCmd = &cobra.Command{
	Use:   "metrics",
	Short: "Print current metric values for debugging",
	Annotations: map[string]string{
		requiresVaultAnnotation: "false",
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		return printMetrics(cmd)
	},
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

func init() {
	rootCmd.AddCommand(diagCmd)
	diagCmd.AddCommand(diagMetricsCmd)
}
