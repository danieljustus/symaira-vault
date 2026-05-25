// Command generate_schema generates the Symaira Vault config JSON schema file.
package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/invopop/jsonschema"

	configpkg "github.com/danieljustus/symaira-vault/internal/config"
)

func main() {
	r := &jsonschema.Reflector{
		DoNotReference: true,
	}

	schema := r.Reflect(&configpkg.Config{})
	schema.ID = "https://symaira.dev/config.schema.json"
	schema.Version = "https://json-schema.org/draft/2020-12/schema"
	schema.Description = "Symaira Vault configuration schema"

	data, err := json.MarshalIndent(schema, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error marshaling schema: %v\n", err)
		os.Exit(1)
	}

	fmt.Println(string(data))
}
