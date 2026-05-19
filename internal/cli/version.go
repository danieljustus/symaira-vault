package cli

import (
	"github.com/spf13/cobra"
)

var (
	AppVersion = "dev"
	AppCommit  = "none"
	AppDate    = "unknown"
)

type VersionResult struct {
	Version string `json:"version" yaml:"version"`
	Commit  string `json:"commit" yaml:"commit"`
	Built   string `json:"built" yaml:"built"`
}

func (v VersionResult) String() string {
	return "openpass " + v.Version + " (commit: " + v.Commit + ", built: " + v.Built + ")"
}

func SetVersionInfo(version, commit, date string) {
	AppVersion = version
	AppCommit = commit
	AppDate = date
	RootCmd.Version = version
}

func AppVersionStr() string { return AppVersion }

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the version of OpenPass",
	Example: `  openpass version
  openpass version --output json`,
	Annotations: map[string]string{
		RequiresVaultAnnotation: "false",
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		result := VersionResult{
			Version: AppVersion,
			Commit:  AppCommit,
			Built:   AppDate,
		}
		return PrintResult(result)
	},
}

func init() {
	RootCmd.AddCommand(versionCmd)
}
