package serverbootstrap

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestOAuthClientStore_LoadSaveRoundtrip(t *testing.T) {
	dir := t.TempDir()
	store, err := loadOAuthClientStore(dir)
	if err != nil {
		t.Fatalf("loadOAuthClientStore: %v", err)
	}

	client := &registeredClient{
		ClientID:     "test-client-1",
		RedirectURIs: []string{"http://localhost:3000/callback"},
		CreatedAt:    time.Now(),
	}
	store.put(client)

	filePath := filepath.Join(dir, oauthClientsFileName)
	info, err := os.Stat(filePath)
	if err != nil {
		t.Fatalf("client store file not created: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("file permissions = %o, want 0o600", info.Mode().Perm())
	}

	store2, err := loadOAuthClientStore(dir)
	if err != nil {
		t.Fatalf("loadOAuthClientStore (2nd): %v", err)
	}

	got, ok := store2.get("test-client-1")
	if !ok {
		t.Fatal("fresh store: client not found after Load()")
	}
	if got.ClientID != "test-client-1" {
		t.Errorf("client_id = %q, want %q", got.ClientID, "test-client-1")
	}
	if len(got.RedirectURIs) != 1 || got.RedirectURIs[0] != "http://localhost:3000/callback" {
		t.Errorf("redirect_uris = %v, want [http://localhost:3000/callback]", got.RedirectURIs)
	}
}

func TestOAuthClientStore_SaveDoesNotBlockOnError(t *testing.T) {
	dir := t.TempDir()
	readOnlyDir := filepath.Join(dir, "readonly")
	if err := os.Mkdir(readOnlyDir, 0o555); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}

	roStore, err := loadOAuthClientStore(readOnlyDir)
	if err != nil {
		t.Fatalf("loadOAuthClientStore readonly: %v", err)
	}

	roStore.put(&registeredClient{
		ClientID:     "should-not-fail",
		RedirectURIs: []string{"http://localhost:9999/callback"},
		CreatedAt:    time.Now(),
	})

	_, ok := roStore.get("should-not-fail")
	if !ok {
		t.Fatal("client should be in memory even if save failed")
	}
}

func TestOAuthClientStore_MissingFileIsNoOp(t *testing.T) {
	dir := t.TempDir()
	store, err := loadOAuthClientStore(dir)
	if err != nil {
		t.Fatalf("loadOAuthClientStore on empty dir: %v", err)
	}
	if store == nil {
		t.Fatal("store is nil")
	}
	_, ok := store.get("anything")
	if ok {
		t.Fatal("expected client not found in empty store")
	}
}

func TestOAuthClientStore_InMemoryNoFileCreated(t *testing.T) {
	store := newOAuthClientStore()
	store.put(&registeredClient{
		ClientID:     "mem-only",
		RedirectURIs: []string{"http://localhost:3000/callback"},
		CreatedAt:    time.Now(),
	})
	_, ok := store.get("mem-only")
	if !ok {
		t.Fatal("in-memory store: client not found")
	}
}

func TestOAuthClientStore_SaveWithoutPathIsNoOp(t *testing.T) {
	store := newOAuthClientStore()
	if err := store.Save(); err != nil {
		t.Fatalf("Save() on in-memory store should be no-op: %v", err)
	}
}

func TestOAuthClientStore_FileFormat(t *testing.T) {
	dir := t.TempDir()
	store, err := loadOAuthClientStore(dir)
	if err != nil {
		t.Fatalf("loadOAuthClientStore: %v", err)
	}

	store.put(&registeredClient{
		ClientID:     "fmt-check",
		RedirectURIs: []string{"http://localhost:3000/callback"},
		CreatedAt:    time.Now(),
	})

	filePath := filepath.Join(dir, oauthClientsFileName)
	data, err := os.ReadFile(filePath)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}

	var file struct {
		Version int                            `json:"version"`
		Clients map[string]*registeredClient   `json:"clients"`
	}
	if err := json.Unmarshal(data, &file); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if file.Version != 1 {
		t.Errorf("version = %d, want 1", file.Version)
	}
	if file.Clients == nil {
		t.Fatal("clients field is nil")
	}
	if _, ok := file.Clients["fmt-check"]; !ok {
		t.Error("fmt-check client missing from file")
	}
	if !strings.HasSuffix(string(data), "\n") {
		t.Error("file should end with newline")
	}
}

func TestOAuthClientStore_LoadWithInvalidJSON(t *testing.T) {
	dir := t.TempDir()
	filePath := filepath.Join(dir, oauthClientsFileName)
	if err := os.WriteFile(filePath, []byte("{bad json}"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	_, err := loadOAuthClientStore(dir)
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
	if !strings.Contains(err.Error(), "parse oauth client store") {
		t.Errorf("error = %q, want contains 'parse oauth client store'", err.Error())
	}
}

func TestOAuthClientStore_CleanupExpired(t *testing.T) {
	dir := t.TempDir()
	store, err := loadOAuthClientStore(dir)
	if err != nil {
		t.Fatalf("loadOAuthClientStore: %v", err)
	}

	past := time.Now().Add(-24 * time.Hour)

	store.put(&registeredClient{
		ClientID:  "valid",
		CreatedAt: time.Now(),
	})
	store.put(&registeredClient{
		ClientID:  "expired",
		CreatedAt: past,
		ExpiresAt: &past,
	})

	removed := store.cleanupExpired()
	if removed != 1 {
		t.Errorf("cleanupExpired removed %d, want 1", removed)
	}
	_, ok := store.get("valid")
	if !ok {
		t.Error("valid client was removed")
	}
	_, ok = store.get("expired")
	if ok {
		t.Error("expired client should not be found")
	}

	store2, err := loadOAuthClientStore(dir)
	if err != nil {
		t.Fatalf("loadOAuthClientStore after cleanup: %v", err)
	}
	_, ok = store2.get("expired")
	if ok {
		t.Error("expired client persisted after cleanup")
	}
	_, ok = store2.get("valid")
	if !ok {
		t.Error("valid client missing after reload")
	}
}

func TestOAuthClientStore_ExpiredClientNotReturnedByGet(t *testing.T) {
	dir := t.TempDir()
	store, err := loadOAuthClientStore(dir)
	if err != nil {
		t.Fatalf("loadOAuthClientStore: %v", err)
	}

	past := time.Now().Add(-1 * time.Hour)
	store.put(&registeredClient{
		ClientID:  "old-and-cold",
		CreatedAt: past,
		ExpiresAt: &past,
	})

	_, ok := store.get("old-and-cold")
	if ok {
		t.Error("expired client should not be returned by get()")
	}
}
