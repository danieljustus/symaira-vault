// Command toolhashseed builds a disposable vault plus scoped tokens whose
// tool-registry hashes cover the TOOLHASH-001 drift scenarios. The tokens are
// issued through the real token registry after importing the server package
// (whose init sets auth.CurrentToolRegistryHash), then the stale/legacy hashes
// are assigned on the issued entries, exactly the states a binary upgrade
// leaves behind. It prints {name: rawToken} as JSON.
package main

import (
	"encoding/json"
	"flag"
	"os"
	"time"

	"github.com/danieljustus/symaira-vault/internal/config"
	"github.com/danieljustus/symaira-vault/internal/mcp/auth"
	_ "github.com/danieljustus/symaira-vault/internal/mcp/server" // sets auth.CurrentToolRegistryHash
	"github.com/danieljustus/symaira-vault/internal/vault"
)

const staleHash = "0000000000000000000000000000000000000000000000000000000000000000"

func main() {
	root := flag.String("root", "", "private disposable vault")
	flag.Parse()
	if auth.CurrentToolRegistryHash == "" {
		panic("server init did not set the tool registry hash")
	}
	cfg := config.Default()
	cfg.Vault = &config.VaultConfig{FormatVersion: 2, AuthMethod: "passphrase", Argon2idTime: 2, Argon2idMemory: 19456, Argon2idThreads: 1}
	cfg.MCP = &config.MCPConfig{AllowInsecureBind: true, RateLimit: 0}
	profile := config.AgentProfile{Tier: config.StrPtr("admin"), ApprovalMode: config.StrPtr("none"), AllowedPaths: []string{"public"}, CanReadValues: config.BoolPtr(true), CanRunCommands: config.BoolPtr(true), ExposeValueTools: config.BoolPtr(true)}
	cfg.Agents = map[string]config.AgentProfile{"fixture": profile}
	cfg.DefaultAgent = "fixture"
	identity, err := vault.InitWithPassphrase(*root, []byte("correct horse battery staple"), cfg)
	if err != nil {
		panic(err)
	}
	entry := &vault.Entry{Data: map[string]any{"password": "public-toolhash-secret-1f3e"}}
	if err = vault.WriteEntry(*root, "public/fixture", entry, identity); err != nil {
		panic(err)
	}
	registry := auth.NewTokenRegistry(auth.TokenRegistryFilePath(*root))
	if err = registry.Load(); err != nil {
		panic(err)
	}
	tokens := map[string]string{}
	for _, spec := range []struct {
		name  string
		tools []string
		hash  *string // nil keeps the hash Create stamped (the current registry)
	}{
		{"go_current", []string{"*"}, nil},
		{"go_legacy_empty", []string{"*"}, strPtr("")},
		{"go_stale", []string{"*"}, strPtr(staleHash)},
		{"go_stale_scoped_health", []string{"health"}, strPtr(staleHash)},
	} {
		token, raw, e := registry.Create(spec.name, spec.tools, "fixture", time.Hour)
		if e != nil {
			panic(e)
		}
		if spec.hash != nil {
			token.ToolRegistryHash = *spec.hash
		}
		tokens[spec.name] = raw
	}
	if err = registry.Save(); err != nil {
		panic(err)
	}
	if err = json.NewEncoder(os.Stdout).Encode(tokens); err != nil {
		panic(err)
	}
}

func strPtr(s string) *string { return &s }
