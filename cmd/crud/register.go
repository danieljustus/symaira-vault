package crud

import (
	"github.com/spf13/cobra"
	vaultpkg "github.com/danieljustus/symaira-vault/internal/vault"
)

// RegisterCommands registers all CRUD commands with the root command using the provided OperationService.
func RegisterCommands(rootCmd *cobra.Command, ops vaultpkg.OperationService) {
	rootCmd.AddCommand(
		NewAddCmd(ops),
		NewDeleteCmd(ops),
		NewEditCmd(ops),
		NewFindCmd(ops),
		NewGetCmd(ops),
		NewListCmd(ops),
		NewSetCmd(ops),
	)
}
