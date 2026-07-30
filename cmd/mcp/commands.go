package mcp

import (
	"github.com/spf13/cobra"
)

// NewCommands returns all MCP and agent commands for root command assembly.
func NewCommands() []*cobra.Command {
	return []*cobra.Command{
		agentCmd,
		McpConfigCmd,
		mcpTokenRotateCmd,
		mcpCmd,
		ServeCmd,
	}
}
