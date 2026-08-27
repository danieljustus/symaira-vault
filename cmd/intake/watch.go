package intakecmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	cli "github.com/danieljustus/symaira-vault/internal/cli"
	errorspkg "github.com/danieljustus/symaira-vault/internal/errors"
	"github.com/danieljustus/symaira-vault/internal/intake"
	vaultpkg "github.com/danieljustus/symaira-vault/internal/vault"
)

var (
	watchInterval time.Duration
	watchDebounce time.Duration
	watchOnce     bool
	watchJSON     bool
)

func newIntakeWatchCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "watch <directory>",
		Short: "Watch a folder for new credential files and stage quarantined batches",
		Long: `Watches a user-selected folder for new credential material (screenshots,
exports, certificate files, backup codes) and stages each pickup as a
quarantined review batch under quarantine/<import-id>/. The watcher is
deliberately conservative:

- Files are only picked up after their size and mtime stabilized (debounce);
  partial downloads and files still being written are skipped.
- Sources are never deleted, never moved, and never auto-promoted. Review
  and promotion happen through ` + "`import review promote`" + `.
- Already-staged files are remembered across polls (ledger), so the same
  file is not intaked twice.

Run with --once for a single scan (cron/LaunchAgent friendly). For an
always-on watcher, run without --once and stop it with Ctrl-C (SIGINT) or
SIGTERM; to pause, stop the process and restart it later. To disable, remove
the LaunchAgent entry or stop invoking the command.

Example LaunchAgent plist (adjust paths):
  ~/Library/LaunchAgents/com.symaira.vault-intake.plist
  ProgramArguments: [ /usr/local/bin/symvault, intake, watch, /path/to/folder, --once ]
  StartInterval: 300`,
		Example: `  # One scan, stage anything new (cron-friendly)
  symvault intake watch ~/Downloads/intake --once

  # Machine-readable single scan
  symvault intake watch ~/Downloads/intake --once --json

  # Always-on watcher with a 15s poll interval
  symvault intake watch ~/Downloads/intake --interval 15s`,
		Args: cobra.ExactArgs(1),
		RunE: runIntakeWatch,
	}
	cmd.Flags().DurationVar(&watchInterval, "interval", 10*time.Second, "Poll interval (always-on mode)")
	cmd.Flags().DurationVar(&watchDebounce, "debounce", 5*time.Second, "Require files to be stable for this long before pickup")
	cmd.Flags().BoolVar(&watchOnce, "once", false, "Run a single scan and exit")
	cmd.Flags().BoolVar(&watchJSON, "json", false, "Emit machine-readable JSON per scan")
	cmd.AddCommand(newIntakeWatchDisableCmd())
	return cmd
}

// newIntakeWatchDisableCmd documents and triggers the explicit disable path:
// remove the LaunchAgent plist the user created for --once mode.
func newIntakeWatchDisableCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "disable",
		Short: "Disable an intake watch LaunchAgent (macOS)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			plist := os.ExpandEnv("$HOME/Library/LaunchAgents/com.symaira.vault-intake.plist")
			if _, err := os.Stat(plist); os.IsNotExist(err) {
				cli.PrintQuietAware("No intake LaunchAgent found at %s — nothing to disable.\n", plist)
				return nil
			}
			if runtime.GOOS != "darwin" {
				return errorspkg.NewCLIError(errorspkg.ExitInvalidInput, "LaunchAgent disable is only supported on macOS", nil)
			}
			_ = exec.Command("/bin/launchctl", "unload", plist).Run()
			if err := os.Remove(plist); err != nil {
				return errorspkg.NewCLIError(errorspkg.ExitGeneralError, "remove LaunchAgent plist", err)
			}
			cli.PrintQuietAware("Removed intake LaunchAgent %s\n", plist)
			return nil
		},
	}
	return cmd
}

func runIntakeWatch(cmd *cobra.Command, args []string) error {
	dir := args[0]
	wopts := intake.WatcherOptions{
		Interval: watchInterval,
		Debounce: watchDebounce,
		Options: intake.Options{
			MaxFileSize:  intake.DefaultMaxFileSize,
			MaxBatchSize: intake.DefaultMaxBatchSize,
			MaxFiles:     intake.DefaultMaxFiles,
		},
	}
	watcher, err := intake.NewWatcher(dir, wopts)
	if err != nil {
		return errorspkg.NewCLIError(errorspkg.ExitInvalidInput, "watch", err)
	}
	defer watcher.Close()

	// Signal handling: SIGINT/SIGTERM stop the loop cleanly.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	onBatch := func(results []intake.FileResult) error {
		return cli.WithVault(func(v *vaultpkg.Vault, vs *cli.VaultService) error {
			importID, written, err := intake.WriteBatch(vs, results, intake.BatchOptions{})
			if err != nil {
				return err
			}
			if len(written) == 0 {
				// Everything was already staged (duplicate hash / existing
				// entry): no new batch, no notification.
				if watchJSON {
					return json.NewEncoder(cmd.OutOrStdout()).Encode(map[string]any{
						"import_id": nil,
						"written":   0,
					})
				}
				cli.PrintQuietAware("No new files to stage.\n")
				return nil
			}
			if watchJSON {
				out := map[string]any{
					"import_id": importID,
					"written":   written,
				}
				enc := json.NewEncoder(cmd.OutOrStdout())
				return enc.Encode(out)
			}
			cli.PrintQuietAware("Staged batch %s (%d entries)\n", importID, len(written))
			cli.PrintQuietAware("Review with: symvault import review promote %s\n", importID)
			notifyLocal("Symaira Vault Intake", fmt.Sprintf("Batch %s bereit zur Prüfung (%d Einträge)", importID, len(written)))
			return nil
		})
	}

	if watchOnce {
		res, err := watcher.Scan()
		if err != nil {
			return errorspkg.NewCLIError(errorspkg.ExitGeneralError, "scan", err)
		}
		if watchJSON {
			enc := json.NewEncoder(cmd.OutOrStdout())
			return enc.Encode(res)
		}
		cli.PrintQuietAware("Scanned %d candidate(s), staged %d, skipped %d, errors %d\n",
			res.Scanned, len(res.StagedPaths), len(res.Skipped), len(res.Errors))
		for _, s := range res.Skipped {
			cli.PrintQuietAware("  skip: %s\n", s)
		}
		for _, e := range res.Errors {
			cli.PrintQuietAware("  error: %s\n", e)
		}
		if len(res.StagedResults) > 0 {
			return onBatch(res.StagedResults)
		}
		return nil
	}

	cli.PrintQuietAware("Watching %s (interval %s, debounce %s). Ctrl-C to stop.\n", dir, watchInterval, watchDebounce)
	return watcher.Run(ctx.Done(), onBatch)
}

// notifyLocal posts a local macOS notification (best-effort; silent
// everywhere else). Used to surface a ready review batch without telemetry.
func notifyLocal(title, message string) {
	if runtime.GOOS != "darwin" {
		return
	}
	script := fmt.Sprintf("display notification %q with title %q", message, title)
	_ = exec.Command("/usr/bin/osascript", "-e", script).Run()
}
