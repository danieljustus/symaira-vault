package mcp

import (
	"github.com/spf13/cobra"
)

// NewCommands returns all MCP and agent commands for root command assembly.
// Each call builds a fresh command tree so consecutive calls never share
// command objects or flag state.
func NewCommands() []*cobra.Command {
	return []*cobra.Command{
		newAgentCmd(),
		newMcpConfigCmd(),
		newMcpTokenRotateCmd(),
		newMcpCmd(),
		newServeCmd(),
	}
}
