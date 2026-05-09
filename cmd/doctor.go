package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/danieljustus/OpenPass/internal/health"
)

var (
	doctorJSON      bool
	doctorNoNetwork bool
)

var doctorCmd = &cobra.Command{
	Use:   "doctor",
	Short: "Check vault health and configuration",
	Long: `Run a series of health checks on the current vault and report their status.

Output modes:
  --text (default): colored output, one line per check
  --json:           machine-readable JSON (suitable for CI/monitoring)

Use --no-network to skip checks that require network access (git remote reachability, update check).`,
	Annotations: map[string]string{
		requiresVaultAnnotation: "false",
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		vaultDir := getVaultDir()
		opts := health.Options{NoNetwork: doctorNoNetwork}
		results := health.RunChecks(vaultDir, opts)

		if doctorJSON {
			return outputDoctorJSON(cmd, vaultDir, results)
		}
		return outputDoctorText(cmd, vaultDir, results)
	},
}

func outputDoctorText(cmd *cobra.Command, vaultDir string, results []health.Result) error {
	isTTY := term.IsTerminal(int(os.Stdout.Fd()))
	noColor := os.Getenv("NO_COLOR") != ""
	useColor := isTTY && !noColor

	colorize := func(code, s string) string {
		if !useColor {
			return s
		}
		return code + s + "\033[0m"
	}

	cmd.Printf("OpenPass Doctor — Vault: %s\n\n", vaultDir)

	for _, r := range results {
		var symbol, colorCode string
		switch r.Status {
		case health.StatusOK:
			symbol = " ✓ "
			colorCode = "\033[32m" // green
		case health.StatusWarn:
			symbol = " ⚠ "
			colorCode = "\033[33m" // yellow
		case health.StatusFail:
			symbol = " ✗ "
			colorCode = "\033[31m" // red
		}

		line := fmt.Sprintf("%-3s %-40s %s", symbol, r.Name, r.Message)
		cmd.Println(colorize(colorCode, line))
		if r.Hint != "" {
			indent := strings.Repeat(" ", 4)
			cmd.Println(colorize("\033[2m", indent+"→ "+r.Hint))
		}
	}

	ok, warn, fail := health.Score(results)
	total := ok + warn + fail
	cmd.Printf("\nScore: %d/%d OK", ok, total)
	if warn > 0 {
		cmd.Printf(" · %s", colorize("\033[33m", fmt.Sprintf("%d warning(s)", warn)))
	}
	if fail > 0 {
		cmd.Printf(" · %s", colorize("\033[31m", fmt.Sprintf("%d failed", fail)))
	}
	cmd.Println()
	return nil
}

type doctorJSONOutput struct {
	VaultDir string          `json:"vault_dir"`
	Results  []health.Result `json:"results"`
	Score    struct {
		OK    int `json:"ok"`
		Warn  int `json:"warn"`
		Fail  int `json:"fail"`
		Total int `json:"total"`
	} `json:"score"`
}

func outputDoctorJSON(cmd *cobra.Command, vaultDir string, results []health.Result) error {
	ok, warn, fail := health.Score(results)
	out := doctorJSONOutput{
		VaultDir: vaultDir,
		Results:  results,
	}
	out.Score.OK = ok
	out.Score.Warn = warn
	out.Score.Fail = fail
	out.Score.Total = ok + warn + fail

	enc := json.NewEncoder(cmd.OutOrStdout())
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

func getVaultDir() string {
	dir, err := vaultPath()
	if err != nil {
		home, _ := os.UserHomeDir()
		return home + "/.openpass"
	}
	return dir
}

func init() {
	rootCmd.AddCommand(doctorCmd)
	doctorCmd.Flags().BoolVar(&doctorJSON, "json", false, "Output in JSON format")
	doctorCmd.Flags().BoolVar(&doctorNoNetwork, "no-network", false, "Skip network-dependent checks")
}
