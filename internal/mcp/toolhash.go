package mcp

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
)

// ToolHashDef is a minimal representation of a tool used for computing
// a content-hash of the tool registry.
type ToolHashDef struct {
	Name            string
	Description     string
	InputSchema     map[string]any
	ReadOnlyHint    bool
	DestructiveHint bool
}

// ComputeToolRegistryHash returns a SHA-256 hex digest of the given tool
// definitions sorted by name. The hash covers name, description, and input
// schema so any injection-relevant change is detected.
func ComputeToolRegistryHash(defs []ToolHashDef) string {
	sorted := make([]ToolHashDef, len(defs))
	copy(sorted, defs)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Name < sorted[j].Name })
	h := sha256.New()
	for _, def := range sorted {
		schemaJSON, err := json.Marshal(def.InputSchema)
		if err != nil {
			schemaJSON = []byte("{}")
		}
		_, _ = fmt.Fprintf(h, "%s|%s|%s|%v|%v\n", def.Name, def.Description, schemaJSON, def.ReadOnlyHint, def.DestructiveHint)
	}
	return hex.EncodeToString(h.Sum(nil))
}
