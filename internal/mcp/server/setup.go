package server

import (
	"github.com/danieljustus/OpenPass/internal/mcp/auth"
)

func init() {
	auth.CurrentToolRegistryHash = computeToolRegistryHashDefs(toolDefinitions())
}
