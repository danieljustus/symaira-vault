// Command entrypolicygen captures the actual production Go resource decisions.
// Every vault and identity is disposable public fixture material.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"filippo.io/age"

	vaultcrypto "github.com/danieljustus/symaira-vault/internal/crypto"
	"github.com/danieljustus/symaira-vault/internal/vault"
)

const fixtureIdentity = "AGE-SECRET-KEY-1HS3YTK69EJH0ZYM8ANNNDWQMPT7ZMLPYGTMC47F5T4EDJ5N7EYMQ4L5CDL"

type recipe struct {
	ID    string `json:"id"`
	Kind  string `json:"kind"`
	Count int    `json:"count"`
}
type observation struct {
	Recipe      recipe `json:"recipe"`
	InputSHA256 string `json:"recipe_input_sha256"`
	Outcome     string `json:"outcome"`
	Reads       int    `json:"accepted_reads"`
	Fields      int    `json:"data_fields"`
	BackupCodes int    `json:"backup_codes"`
}

func recipes() []recipe {
	return []recipe{
		{"ordinary", "ordinary", 0},
		{"metadata-array-exact", "metadata", 1024}, {"metadata-array-over", "metadata", 1025},
		{"unknown-duplicates-exact", "duplicates", 4094}, {"unknown-duplicates-over", "duplicates", 4095},
		{"unknown-depth-exact", "depth", 33}, {"unknown-depth-over", "depth", 34},
		{"unknown-string-exact", "string", 1024 * 1024}, {"unknown-string-over", "string", 1024*1024 + 1},
		{"raw-values-below", "values", 63}, {"raw-values-over", "values", 64},
		{"backup-codes-exact", "backup", 1024}, {"backup-codes-over", "backup", 1025},
		{"plaintext-exact", "plaintext", 16 * 1024 * 1024}, {"plaintext-over", "plaintext", 16*1024*1024 + 1},
		{"ciphertext-over", "ciphertext", 24*1024*1024 + 1},
		{"shared-read-session", "batch", 14},
		{"logical-depth-over", "logical", 65},
		{"physical-list-depth-over", "listing", 65},
	}
}
func input(r recipe) []byte {
	switch r.Kind {
	case "ordinary":
		return []byte(`{"data":{"fixture":"ordinary-control"}}`)
	case "metadata":
		return []byte(`{"data":{},"meta":{"tags":[` + strings.TrimSuffix(strings.Repeat(`"public",`, r.Count), ",") + `]}}`)
	case "duplicates":
		return []byte(`{"data":{},"future":{` + strings.TrimSuffix(strings.Repeat(`"same":0,`, r.Count), ",") + `}}`)
	case "depth":
		return []byte(`{"data":{},"future":` + strings.Repeat("[", r.Count) + "0" + strings.Repeat("]", r.Count) + `}`)
	case "string":
		return []byte(`{"data":{},"future":"` + strings.Repeat("x", r.Count) + `"}`)
	case "values":
		array := "[" + strings.TrimSuffix(strings.Repeat("0,", 1024), ",") + "]"
		return []byte(`{"data":{},"future":[` + strings.TrimSuffix(strings.Repeat(array+",", r.Count), ",") + `]}`)
	case "backup":
		return []byte(`{"data":{"backup_codes":"` + strings.Repeat(`public\n`, r.Count) + `"}}`)
	case "plaintext":
		fields := make([]string, 16)
		for i := range fields {
			fields[i] = fmt.Sprintf(`"p%02d":"%s"`, i, strings.Repeat("x", 1024*1024))
		}
		raw := `{"data":{},"future":{` + strings.Join(fields, ",") + `}}`
		excess := len(raw) - r.Count
		fields[15] = fmt.Sprintf(`"p15":"%s"`, strings.Repeat("x", 1024*1024-excess))
		return []byte(`{"data":{},"future":{` + strings.Join(fields, ",") + `}}`)
	case "batch":
		fields := make([]string, 4)
		for i := range fields {
			fields[i] = fmt.Sprintf(`"p%d":"%s"`, i, strings.Repeat("public-fixture", (1024*1024)/14))
		}
		return []byte(`{"data":{` + strings.Join(fields, ",") + `}}`)
	default:
		return []byte(r.Kind)
	}
}
func classify(err error) string {
	switch {
	case err == nil:
		return "accepted"
	case errors.Is(err, vault.ErrVaultResourceLimit):
		return "resource_limit"
	case errors.Is(err, vault.ErrVaultResourceBusy):
		return "resource_busy"
	default:
		panic(fmt.Sprintf("unexpected fixture error: %v", err))
	}
}
func observe(r recipe, identity *age.X25519Identity) observation {
	root, err := os.MkdirTemp("", "symvault-entry-policy-")
	if err != nil {
		panic(err)
	}
	defer func() {
		if err := os.RemoveAll(root); err != nil {
			panic(err)
		}
	}()
	if err := os.Mkdir(filepath.Join(root, "entries"), 0o700); err != nil {
		panic(err)
	}
	if err := os.WriteFile(filepath.Join(root, "config.yaml"), []byte("vault:\n  format_version: 2\n"), 0o600); err != nil {
		panic(err)
	}
	raw := input(r)
	digest := sha256.Sum256(raw)
	result := observation{Recipe: r, InputSHA256: hex.EncodeToString(digest[:])}
	path := "control"
	if r.Kind == "logical" || r.Kind == "listing" {
		path = strings.Repeat("a/", r.Count-1) + "control"
	}
	filePath := filepath.Join(root, "entries", filepath.FromSlash(path)+".age")
	if err := os.MkdirAll(filepath.Dir(filePath), 0o700); err != nil {
		panic(err)
	}
	if r.Kind == "ciphertext" || r.Kind == "listing" {
		file, err := os.Create(filePath) // #nosec G304 -- validated fixed recipes write only inside a newly created disposable vault
		if err != nil {
			panic(err)
		}
		if r.Kind == "ciphertext" {
			if err := file.Truncate(int64(r.Count)); err != nil {
				panic(err)
			}
		}
		if err := file.Close(); err != nil {
			panic(err)
		}
	} else {
		if r.Kind == "logical" {
			raw = input(recipe{Kind: "ordinary"})
		}
		ciphertext, err := vaultcrypto.Encrypt(raw, identity.Recipient())
		if err != nil {
			panic(err)
		}
		if err := os.WriteFile(filePath, ciphertext, 0o600); err != nil {
			panic(err)
		}
	}
	if r.Kind == "listing" {
		_, err := vault.NewReadSession(root, identity).EntryFiles()
		result.Outcome = classify(err)
		return result
	}
	reader := vault.NewReadSession(root, identity)
	count := 1
	if r.Kind == "batch" {
		count = r.Count
	}
	for i := 0; i < count; i++ {
		entry, err := reader.Get(path)
		result.Outcome = classify(err)
		if err != nil {
			break
		}
		result.Reads++
		result.Fields = len(entry.Data)
		if codes, ok := entry.Data["backup_codes"].([]any); ok {
			result.BackupCodes = len(codes)
		}
	}
	return result
}
func main() {
	identity, err := age.ParseX25519Identity(fixtureIdentity)
	if err != nil {
		panic(err)
	}
	results := make([]observation, 0, len(recipes()))
	for _, r := range recipes() {
		results = append(results, observe(r, identity))
	}
	if err := json.NewEncoder(os.Stdout).Encode(results); err != nil {
		panic(err)
	}
}
