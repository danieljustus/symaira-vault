package admin

import (
	"encoding/json"
	"fmt"
	"strings"

	cli "github.com/danieljustus/OpenPass/internal/cli"

	"github.com/spf13/cobra"

	errorspkg "github.com/danieljustus/OpenPass/internal/errors"
	"github.com/danieljustus/OpenPass/internal/health"
	cliout "github.com/danieljustus/OpenPass/internal/ui/cliout"
)

var (
	DoctorJSON      bool
	DoctorNoNetwork bool
	DoctorStrict    bool
	DoctorOnly      []string
	DoctorExclude   []string
	DoctorFix       bool
	DoctorFixDryRun bool
	DoctorQuick     bool
)

var DoctorCmd = &cobra.Command{
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
		cli.RequiresVaultAnnotation: "false",
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		vaultDir := cli.GetVaultDir()
		opts := health.Options{
			NoNetwork: DoctorNoNetwork,
			Quick:     DoctorQuick,
			Version:   cli.AppVersion,
			Only:      DoctorOnly,
			Exclude:   DoctorExclude,
		}
		results := health.RunChecks(vaultDir, opts)

		// Fix ordering: --fix runs first to patch results (changing their Status),
		// then Score() evaluates the final state. This ensures the score reflects
		// any repairs that were applied. --fix-dry-run logs intent without changes.
		if DoctorFix {
			for i := range results {
				r := &results[i]
				if r.Fixable && r.Status != health.StatusOK && r.Fix != nil {
					if DoctorFixDryRun {
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

		if cli.WantJSONOutput(DoctorJSON) {
			if err := outputDoctorJSON(cmd, vaultDir, results); err != nil {
				return err
			}
		} else {
			if err := outputDoctorText(cmd, vaultDir, results); err != nil {
				return err
			}
		}

		if DoctorStrict {
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

func init() {
	cli.RootCmd.AddCommand(DoctorCmd)
	DoctorCmd.Flags().BoolVar(&DoctorJSON, "json", false, "Output in JSON format (deprecated: use --output=json)")
	DoctorCmd.Flags().BoolVar(&DoctorNoNetwork, "no-network", false, "Skip network-dependent checks")
	DoctorCmd.Flags().BoolVar(&DoctorStrict, "strict", false, "Return non-zero exit code for warnings (7) or failures (8)")
	DoctorCmd.Flags().StringSliceVar(&DoctorOnly, "only", nil, "Only run checks matching these glob patterns (comma-separated, e.g. vault.*)")
	DoctorCmd.Flags().StringSliceVar(&DoctorExclude, "exclude", nil, "Skip checks matching these glob patterns (comma-separated)")
	DoctorCmd.Flags().BoolVar(&DoctorFix, "fix", false, "auto-repair safe issues (permissions, gitignore, git init)")
	DoctorCmd.Flags().BoolVar(&DoctorFixDryRun, "fix-dry-run", false, "Log what --fix would do without modifying anything")
	DoctorCmd.Flags().BoolVar(&DoctorQuick, "quick", false, "Skip slow checks (scrypt benchmark, update check)")
}
