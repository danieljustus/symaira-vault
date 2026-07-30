package admin

import (
	"github.com/spf13/cobra"
)

// NewCommands returns all administration commands for root command assembly.
func NewCommands() []*cobra.Command {
	return []*cobra.Command{
		AuditCmd,
		backupCmd,
		restoreCmd,
		configCmd,
		DoctorCmd,
		exportCmd,
		importCmd,
		initCmd,
		MigrateCmd,
		setupCmd,
		startupProfileCmd,
		UpdateCmd,
		verifyCmd,
	}
}
