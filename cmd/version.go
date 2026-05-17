package cmd

import (
	"github.com/spf13/cobra"
)

var (
	appVersion = "dev"
	appCommit  = "none"
	appDate    = "unknown"
)

// VersionResult is the stable shape emitted by `openpass version --output=json`.
// New fields may be added but existing ones must keep their name + type
// so tooling that parses the JSON does not break.
type VersionResult struct {
	Version string `json:"version" yaml:"version"`
	Commit  string `json:"commit" yaml:"commit"`
	Built   string `json:"built" yaml:"built"`
}

// String formats the human-readable representation used by TextPrinter.
func (v VersionResult) String() string {
	return "openpass " + v.Version + " (commit: " + v.Commit + ", built: " + v.Built + ")"
}

// SetVersionInfo is called from main to inject build-time values.
func SetVersionInfo(version, commit, date string) {
	appVersion = version
	appCommit = commit
	appDate = date
	rootCmd.Version = version
}

// AppVersion returns the current application version string.
func AppVersion() string { return appVersion }

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the version of OpenPass",
	Example: `  openpass version
  openpass version --output json`,
	Annotations: map[string]string{
		requiresVaultAnnotation: "false",
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		result := VersionResult{
			Version: appVersion,
			Commit:  appCommit,
			Built:   appDate,
		}
		// Honor --output for json/yaml; for text we route through
		// cmd.OutOrStdout so existing tests using cmd.SetOut(buf) still
		// observe the output.
		switch outputFormat {
		case "json", "yaml":
			return PrintResult(result)
		default:
			cmd.Println(result.String())
			return nil
		}
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}
