package admin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	cli "github.com/danieljustus/OpenPass/internal/cli"

	"github.com/spf13/cobra"

	configpkg "github.com/danieljustus/OpenPass/internal/config"
	errorspkg "github.com/danieljustus/OpenPass/internal/errors"
	updatepkg "github.com/danieljustus/OpenPass/internal/update"
)

type UpdateChecker interface {
	Check(ctx context.Context, currentVersion string) (*updatepkg.Result, error)
	CheckWithForce(ctx context.Context, currentVersion string, force bool) (*updatepkg.Result, error)
}

func UpdateCacheTTL() time.Duration {
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

var UpdateCheckerFactory = func() UpdateChecker {
	checker := updatepkg.NewChecker(nil)
	checker.Cache = updatepkg.NewCacheWithTTL("", UpdateCacheTTL())
	return checker
}

var (
	UpdateCheckJSON  bool
	UpdateCheckQuiet bool
	UpdateCheckForce bool

	UpdateApplyForce  bool
	updateApplyDryRun bool
	updateApplyJSON   bool

	updateInfoJSON bool
)

var errUpdateAvailable = errorspkg.NewCLIError(1, "update available", nil)

var UpdateCmd = &cobra.Command{
	Use:     "update",
	Short:   "Check for OpenPass updates",
	Example: `  openpass update check`,
	Args:    cobra.NoArgs,
	Annotations: map[string]string{
		cli.RequiresVaultAnnotation: "false",
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

var UpdateCheckCmd = &cobra.Command{
	Use:   "check",
	Short: "Check GitHub for a newer OpenPass release",
	Args:  cobra.NoArgs,
	Annotations: map[string]string{
		cli.RequiresVaultAnnotation: "false",
	},
	SilenceUsage:  true,
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		checker := UpdateCheckerFactory()
		result, err := checker.CheckWithForce(cmd.Context(), cli.AppVersion, UpdateCheckForce)
		if err != nil {
			return fmt.Errorf("check for updates: %w", err)
		}

		if cli.WantJSONOutput(UpdateCheckJSON) {
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

		if UpdateCheckQuiet {
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

type updateApplyJSONOutput struct {
	Method     string `json:"method"`
	OldVersion string `json:"old_version"`
	NewVersion string `json:"new_version"`
	BackupPath string `json:"backup_path,omitempty"`
	BinaryPath string `json:"binary_path"`
	DryRun     bool   `json:"dry_run"`
}

type updateInfoJSONOutput struct {
	Method              string `json:"method"`
	BinaryPath          string `json:"binary_path"`
	SelfUpdateSupported bool   `json:"self_update_supported"`
	Guidance            string `json:"guidance"`
}

var updateApplyCmd = &cobra.Command{
	Use:   "apply",
	Short: "Apply the latest OpenPass self-update",
	Long: `Downloads, verifies, and applies the latest OpenPass release.

Supports direct-download installations only. When run via Homebrew, go install,
or a package manager, self-update is disabled and guidance is shown instead.`,
	Args: cobra.NoArgs,
	Annotations: map[string]string{
		cli.RequiresVaultAnnotation: "false",
	},
	SilenceUsage:  true,
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		if updateApplyDryRun {
			checker := UpdateCheckerFactory()
			result, err := checker.CheckWithForce(cmd.Context(), cli.AppVersion, UpdateApplyForce)
			if err != nil {
				return fmt.Errorf("check for updates: %w", err)
			}

			if cli.WantJSONOutput(updateApplyJSON) {
				output := updateApplyJSONOutput{
					OldVersion: result.CurrentVersion,
					BinaryPath: "",
					DryRun:     true,
				}
				if result.UpdateAvailable {
					output.NewVersion = result.LatestVersion
				} else {
					output.NewVersion = result.CurrentVersion
				}
				encoder := json.NewEncoder(cmd.OutOrStdout())
				encoder.SetIndent("", "  ")
				if err := encoder.Encode(output); err != nil {
					return fmt.Errorf("encode JSON output: %w", err)
				}
				return nil
			}

			if !result.Checkable {
				cmd.Printf("Update checks are only available for stable release builds. Current version: %s\n", result.CurrentVersion)
				return nil
			}

			if result.UpdateAvailable {
				cmd.Printf("Update available: %s -> %s (use --dry-run to preview)\n", result.CurrentVersion, result.LatestVersion)
			} else {
				cmd.Printf("OpenPass is up to date (%s).\n", result.CurrentVersion)
			}
			return nil
		}

		applyResult, err := updatepkg.Apply(cmd.Context(), cli.AppVersion, UpdateApplyForce, false)
		if err != nil {
			var unsupported *updatepkg.ErrUnsupportedMethod
			if errors.As(err, &unsupported) {
				if cli.WantJSONOutput(updateApplyJSON) {
					encoder := json.NewEncoder(cmd.OutOrStdout())
					encoder.SetIndent("", "  ")
					if encodeErr := encoder.Encode(map[string]string{
						"error":    err.Error(),
						"guidance": unsupported.Guidance,
					}); encodeErr != nil {
						_ = encodeErr
					}
				} else {
					cmd.PrintErrln("Error: " + err.Error())
					cmd.PrintErrln("Guidance: " + unsupported.Guidance)
				}
				return errorspkg.NewCLIError(errorspkg.ExitNotFound, "self-update not supported", err)
			}
			return fmt.Errorf("apply update: %w", err)
		}

		if cli.WantJSONOutput(updateApplyJSON) {
			output := updateApplyJSONOutput{
				Method:     string(applyResult.Method),
				OldVersion: applyResult.OldVersion,
				NewVersion: applyResult.NewVersion,
				BackupPath: applyResult.BackupPath,
				BinaryPath: applyResult.BinaryPath,
			}
			encoder := json.NewEncoder(cmd.OutOrStdout())
			encoder.SetIndent("", "  ")
			if err := encoder.Encode(output); err != nil {
				return fmt.Errorf("encode JSON output: %w", err)
			}
			return nil
		}

		if applyResult.OldVersion == applyResult.NewVersion {
			cmd.Printf("OpenPass is already up to date (%s).\n", applyResult.NewVersion)
			return nil
		}

		cmd.Printf("Updated OpenPass: %s -> %s\n", applyResult.OldVersion, applyResult.NewVersion)
		cmd.Printf("Installation method: %s\n", applyResult.Method)
		cmd.Printf("Binary: %s\n", applyResult.BinaryPath)
		if applyResult.BackupPath != "" {
			cmd.Printf("Backup saved to: %s\n", applyResult.BackupPath)
		}
		return nil
	},
}

var updateInfoCmd = &cobra.Command{
	Use:   "info",
	Short: "Show OpenPass installation method info",
	Long: `Detects how OpenPass was installed and shows whether self-update
is supported, along with upgrade guidance for the detected method.`,
	Args: cobra.NoArgs,
	Annotations: map[string]string{
		cli.RequiresVaultAnnotation: "false",
	},
	SilenceUsage:  true,
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		info, err := updatepkg.Info()
		if err != nil {
			return fmt.Errorf("update info: %w", err)
		}

		if cli.WantJSONOutput(updateInfoJSON) {
			output := updateInfoJSONOutput{
				Method:              string(info.Method),
				BinaryPath:          info.BinaryPath,
				SelfUpdateSupported: info.SelfUpdateSupported,
				Guidance:            info.Guidance,
			}
			encoder := json.NewEncoder(cmd.OutOrStdout())
			encoder.SetIndent("", "  ")
			if err := encoder.Encode(output); err != nil {
				return fmt.Errorf("encode JSON output: %w", err)
			}
			return nil
		}

		cmd.Printf("Installation method: %s\n", info.Method)
		cmd.Printf("Binary path: %s\n", info.BinaryPath)
		if info.SelfUpdateSupported {
			cmd.Println("Self-update: supported")
		} else {
			cmd.Println("Self-update: not supported")
		}
		cmd.Printf("Guidance: %s\n", info.Guidance)
		return nil
	},
}

func init() {
	UpdateCheckCmd.Flags().BoolVar(&UpdateCheckJSON, "json", false, "output update check result as JSON (deprecated: use --output=json)")
	UpdateCheckCmd.Flags().BoolVar(&UpdateCheckQuiet, "quiet", false, "suppress non-essential output (exit code 1 if update available)")
	UpdateCheckCmd.Flags().BoolVar(&UpdateCheckForce, "force", false, "bypass cache and force a fresh check")

	updateApplyCmd.Flags().BoolVar(&UpdateApplyForce, "force", false, "bypass cache and force a fresh check")
	updateApplyCmd.Flags().BoolVar(&updateApplyDryRun, "dry-run", false, "preview update without applying")
	updateApplyCmd.Flags().BoolVar(&updateApplyJSON, "json", false, "output apply result as JSON (deprecated: use --output=json)")

	updateInfoCmd.Flags().BoolVar(&updateInfoJSON, "json", false, "output info as JSON (deprecated: use --output=json)")

	UpdateCmd.AddCommand(UpdateCheckCmd)
	UpdateCmd.AddCommand(updateApplyCmd)
	UpdateCmd.AddCommand(updateInfoCmd)
	cli.RootCmd.AddCommand(UpdateCmd)
}
