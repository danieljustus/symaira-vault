package server

import (
	"github.com/danieljustus/symaira-vault/internal/mcp/auth"
)

func init() {
	RegisterTools()
	auth.CurrentToolRegistryHash = computeToolRegistryHashDefs(toolDefinitions())
}
