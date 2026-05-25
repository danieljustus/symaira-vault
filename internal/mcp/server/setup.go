package server

import (
	"github.com/danieljustus/symaira-vault/internal/mcp/auth"
)

func init() {
	auth.CurrentToolRegistryHash = computeToolRegistryHashDefs(toolDefinitions())
}
