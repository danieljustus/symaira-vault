package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	configpkg "github.com/danieljustus/OpenPass/internal/config"
	errorspkg "github.com/danieljustus/OpenPass/internal/errors"
	updatepkg "github.com/danieljustus/OpenPass/internal/update"
)

type updateChecker interface {
	Check(ctx context.Context, currentVersion string) (*updatepkg.Result, error)
	CheckWithForce(ctx context.Context, currentVersion string, force bool) (*updatepkg.Result, error)
}

func updateCacheTTL() time.Duration {
	home, err := os.UserHomeDir()
	if err != nil {
		return updatepkg.DefaultCacheTTL
	}
	cfg, err := configpkg.Load(filepath.Join(home, ".openpass", "config.yaml"))
	if err != nil {
		return updatepkg.DefaultCacheTTL
	}
	if cfg.Update != nil && cfg.Update.CacheTTL > 0 {
		return cfg.Update.CacheTTL
	}
	return updatepkg.DefaultCacheTTL
}

var updateCheckerFactory = func() updateChecker {
	checker := updatepkg.NewChecker(nil)
	checker.Cache = updatepkg.NewCacheWithTTL("", updateCacheTTL())
	return checker
}

var (
	updateCheckJSON  bool
	updateCheckQuiet bool
	updateCheckForce bool
)

var errUpdateAvailable = errorspkg.NewCLIError(1, "update available", nil)

var updateCmd = &cobra.Command{
	Use:     "update",
	Short:   "Check for OpenPass updates",
	Example: `  openpass update check`,
	Args:    cobra.NoArgs,
	Annotations: map[string]string{
		requiresVaultAnnotation: "false",
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		return cmd.Help()
	},
}

type updateCheckJSONOutput struct {
	CurrentVersion  string `json:"current_version"`
	LatestVersion   string `json:"latest_version,omitempty"`
	ReleaseURL      string `json:"release_url,omitempty"`
	Checkable       bool   `json:"checkable"`
	UpdateAvailable bool   `json:"update_available"`
}

var updateCheckCmd = &cobra.Command{
	Use:   "check",
	Short: "Check GitHub for a newer OpenPass release",
	Args:  cobra.NoArgs,
	Annotations: map[string]string{
		requiresVaultAnnotation: "false",
	},
	SilenceUsage:  true,
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		checker := updateCheckerFactory()
		result, err := checker.CheckWithForce(cmd.Context(), appVersion, updateCheckForce)
		if err != nil {
			return fmt.Errorf("check for updates: %w", err)
		}

		if wantJSONOutput(updateCheckJSON) {
			output := updateCheckJSONOutput{
				CurrentVersion:  result.CurrentVersion,
				LatestVersion:   result.LatestVersion,
				ReleaseURL:      result.ReleaseURL,
				Checkable:       result.Checkable,
				UpdateAvailable: result.UpdateAvailable,
			}
			encoder := json.NewEncoder(cmd.OutOrStdout())
			encoder.SetIndent("", "  ")
			if err := encoder.Encode(output); err != nil {
				return fmt.Errorf("encode JSON output: %w", err)
			}
			if result.UpdateAvailable {
				return errUpdateAvailable
			}
			return nil
		}

		if updateCheckQuiet {
			if result.UpdateAvailable {
				return errUpdateAvailable
			}
			return nil
		}

		if !result.Checkable {
			cmd.Printf("Update checks are only available for stable release builds. Current version: %s\n", result.CurrentVersion)
			return nil
		}

		if result.UpdateAvailable {
			cmd.Printf("Update available: %s -> %s\n", result.CurrentVersion, result.LatestVersion)
			if result.ReleaseURL != "" {
				cmd.Printf("Download: %s\n", result.ReleaseURL)
			}
			return errUpdateAvailable
		}

		if result.CurrentVersion == result.LatestVersion {
			cmd.Printf("OpenPass is up to date (%s).\n", result.CurrentVersion)
			return nil
		}

		cmd.Printf("No newer stable release found. Current version: %s. Latest published stable release: %s.\n", result.CurrentVersion, result.LatestVersion)
		return nil
	},
}

func init() {
	updateCheckCmd.Flags().BoolVar(&updateCheckJSON, "json", false, "output update check result as JSON (deprecated: use --output=json)")
	updateCheckCmd.Flags().BoolVar(&updateCheckQuiet, "quiet", false, "suppress non-essential output (exit code 1 if update available)")
	updateCheckCmd.Flags().BoolVar(&updateCheckForce, "force", false, "bypass cache and force a fresh check")

	updateCmd.AddCommand(updateCheckCmd)
	rootCmd.AddCommand(updateCmd)
}
