package admin

import (
	"github.com/spf13/cobra"
)

// NewCommands returns all administration commands for root command assembly.
// Each call builds a fresh command tree so consecutive calls never share
// command objects or flag state.
func NewCommands() []*cobra.Command {
	return []*cobra.Command{
		newAuditCmd(),
		newBackupCmd(),
		newRestoreCmd(),
		newConfigCmd(),
		newDoctorCmd(),
		newExportCmd(),
		newImportCmd(),
		newInitCmd(),
		newMigrateCmd(),
		newSetupCmd(),
		newStartupProfileCmd(),
		newUpdateCmd(),
		newVerifyCmd(),
	}
}
