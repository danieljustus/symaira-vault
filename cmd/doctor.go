package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	errorspkg "github.com/danieljustus/OpenPass/internal/errors"
	"github.com/danieljustus/OpenPass/internal/health"
)

var (
	doctorJSON      bool
	doctorNoNetwork bool
	doctorStrict    bool
	doctorOnly      []string
	doctorExclude   []string
	doctorFix       bool
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
		opts := health.Options{
			NoNetwork: doctorNoNetwork,
			Version:   appVersion,
			Only:      doctorOnly,
			Exclude:   doctorExclude,
		}
		results := health.RunChecks(vaultDir, opts)

		if doctorFix {
			for i := range results {
				r := &results[i]
				if r.Fixable && r.Status != health.StatusOK && r.Fix != nil {
					if err := r.Fix(); err != nil {
						r.Message = "fix failed: " + err.Error()
					} else {
						r.Fixed = true
						r.Status = health.StatusOK
						r.Message = "fixed — " + r.Message
					}
				}
			}
		}

		if wantJSONOutput(doctorJSON) {
			if err := outputDoctorJSON(cmd, vaultDir, results); err != nil {
				return err
			}
		} else {
			if err := outputDoctorText(cmd, vaultDir, results); err != nil {
				return err
			}
		}

		if doctorStrict {
			_, warn, fail := health.Score(results)
			if fail > 0 {
				return errorspkg.NewCLIError(errorspkg.ExitDoctorFail, fmt.Sprintf("%d check(s) failed", fail), nil)
			}
			if warn > 0 {
				return errorspkg.NewCLIError(errorspkg.ExitDoctorWarn, fmt.Sprintf("%d warning(s)", warn), nil)
			}
		}
		return nil
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

		fixedTag := ""
		if r.Fixed {
			fixedTag = " (fixed)"
		}
		line := fmt.Sprintf("%-3s %-40s %s%s", symbol, r.Name, r.Message, fixedTag)
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
	doctorCmd.Flags().BoolVar(&doctorJSON, "json", false, "Output in JSON format (deprecated: use --output=json)")
	doctorCmd.Flags().BoolVar(&doctorNoNetwork, "no-network", false, "Skip network-dependent checks")
	doctorCmd.Flags().BoolVar(&doctorStrict, "strict", false, "Return non-zero exit code for warnings (7) or failures (8)")
	doctorCmd.Flags().StringSliceVar(&doctorOnly, "only", nil, "Only run checks matching these glob patterns (comma-separated, e.g. vault.*)")
	doctorCmd.Flags().StringSliceVar(&doctorExclude, "exclude", nil, "Skip checks matching these glob patterns (comma-separated)")
	doctorCmd.Flags().BoolVar(&doctorFix, "fix", false, "auto-repair safe issues (permissions, gitignore, git init)")
}
