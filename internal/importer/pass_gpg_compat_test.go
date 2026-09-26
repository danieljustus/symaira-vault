package importer

import (
	"encoding/json"
	"fmt"
	"os"
	"testing"
)

func TestPassGPGCompatibilityOracle(t *testing.T) {
	store := os.Getenv("SYMVAULT_PASS_GPG_STORE")
	badStore := os.Getenv("SYMVAULT_PASS_GPG_BAD_STORE")
	if store == "" || badStore == "" {
		t.Skip("set SYMVAULT_PASS_GPG_STORE and SYMVAULT_PASS_GPG_BAD_STORE for the opt-in real-GPG compatibility check")
	}
	entries, err := ImportPass(store)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ImportPass(badStore); err == nil {
		t.Fatal("expected wrong-recipient ciphertext decryption to fail")
	}
	projected := make([]map[string]any, len(entries))
	for index, entry := range entries {
		projected[index] = map[string]any{
			"path":     entry.Path,
			"data":     entry.Data,
			"warnings": entry.Warnings,
		}
	}
	encoded, err := json.Marshal(projected)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("PASS_GPG_COMPAT_ORACLE=%s\n", encoded)
}
