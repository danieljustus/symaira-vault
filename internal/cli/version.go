package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/danieljustus/symaira-corekit/versionkit"
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
	return "symvault " + v.Version + " (commit: " + v.Commit + ", built: " + v.Built + ")"
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
	Short: "Print the version of Symaira Vault",
	Example: `  symvault version
  symvault version --json`,
	Annotations: map[string]string{
		RequiresVaultAnnotation: "false",
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		flagJSON, _ := cmd.Flags().GetBool("json")
		info := versionkit.New("symvault", AppVersion, 1)
		if WantJSONOutput(flagJSON) {
			return info.Write(cmd.OutOrStdout())
		}
		_, err := fmt.Fprintln(cmd.OutOrStdout(), info.String())
		return err
	},
}

func init() {
	versionCmd.Flags().Bool("json", false, "Emit version as machine-readable JSON")
	RootCmd.AddCommand(versionCmd)
}
