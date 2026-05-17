package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	errorspkg "github.com/danieljustus/OpenPass/internal/errors"
	"github.com/danieljustus/OpenPass/internal/health"
	cliout "github.com/danieljustus/OpenPass/internal/ui/cliout"
)

var (
	doctorJSON      bool
	doctorNoNetwork bool
	doctorStrict    bool
	doctorOnly      []string
	doctorExclude   []string
	doctorFix       bool
	doctorFixDryRun bool
	doctorQuick     bool
)

var doctorCmd = &cobra.Command{
	Use:   "doctor",
	Short: "Check vault health and configuration",
	Long: `Run a series of health checks on the current vault and report their status.

Output modes:
  --text (default): colored output, one line per check
  --json:           machine-readable JSON (suitable for CI/monitoring)

Use --no-network to skip checks that require network access (git remote reachability, update check).`,
	Example: `  # Full health check
  openpass doctor

  # JSON output, no network
  openpass doctor --output json --no-network

  # Run only config checks
  openpass doctor --only 'config.*'

  # Auto-fix what's safe to fix (with dry-run first)
  openpass doctor --fix-dry-run
  openpass doctor --fix`,
	Annotations: map[string]string{
		requiresVaultAnnotation: "false",
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		vaultDir := getVaultDir()
		opts := health.Options{
			NoNetwork: doctorNoNetwork,
			Quick:     doctorQuick,
			Version:   appVersion,
			Only:      doctorOnly,
			Exclude:   doctorExclude,
		}
		results := health.RunChecks(vaultDir, opts)

		// Fix ordering: --fix runs first to patch results (changing their Status),
		// then Score() evaluates the final state. This ensures the score reflects
		// any repairs that were applied. --fix-dry-run logs intent without changes.
		if doctorFix {
			for i := range results {
				r := &results[i]
				if r.Fixable && r.Status != health.StatusOK && r.Fix != nil {
					if doctorFixDryRun {
						cmd.Printf("Would fix %s: %s\n", r.ID, r.Message)
						continue
					}
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
	cmd.Printf("OpenPass Doctor — Vault: %s\n\n", vaultDir)

	for _, r := range results {
		var symbol string
		switch r.Status {
		case health.StatusOK:
			symbol = " ✓ "
		case health.StatusWarn:
			symbol = " ⚠ "
		case health.StatusFail:
			symbol = " ✗ "
		}

		fixedTag := ""
		if r.Fixed {
			fixedTag = " (fixed)"
		}
		fixableTag := ""
		if r.Fixable && r.Status != health.StatusOK {
			fixableTag = " (fixable — run with --fix)"
		}
		formatted := fmt.Sprintf("%-3s %-40s %s%s%s", symbol, r.Name, r.Message, fixedTag, fixableTag)

		switch r.Status {
		case health.StatusOK:
			cmd.Println(cliout.ColorizeSuccess(formatted))
		case health.StatusWarn:
			cmd.Println(cliout.ColorizeWarn(formatted))
		case health.StatusFail:
			cmd.Println(cliout.ColorizeError(formatted))
		}
		if r.Hint != "" {
			indent := strings.Repeat(" ", 4)
			cmd.Println(cliout.ColorizeDim(indent + "→ " + r.Hint))
		}
	}

	ok, warn, fail := health.Score(results)
	total := ok + warn + fail
	cmd.Printf("\nScore: %d/%d OK", ok, total)
	if warn > 0 {
		cmd.Printf(" · %s", cliout.ColorizeWarn(fmt.Sprintf("%d warning(s)", warn)))
	}
	if fail > 0 {
		cmd.Printf(" · %s", cliout.ColorizeError(fmt.Sprintf("%d failed", fail)))
	}
	cmd.Println()
	return nil
}

type doctorJSONOutput struct {
	SchemaVersion string          `json:"schema_version"`
	VaultDir      string          `json:"vault_dir"`
	Results       []health.Result `json:"results"`
	Score         struct {
		OK    int `json:"ok"`
		Warn  int `json:"warn"`
		Fail  int `json:"fail"`
		Total int `json:"total"`
	} `json:"score"`
}

func outputDoctorJSON(cmd *cobra.Command, vaultDir string, results []health.Result) error {
	ok, warn, fail := health.Score(results)
	out := doctorJSONOutput{
		SchemaVersion: "1.0",
		VaultDir:      vaultDir,
		Results:       results,
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
	doctorCmd.Flags().BoolVar(&doctorFixDryRun, "fix-dry-run", false, "Log what --fix would do without modifying anything")
	doctorCmd.Flags().BoolVar(&doctorQuick, "quick", false, "Skip slow checks (scrypt benchmark, update check)")
}
