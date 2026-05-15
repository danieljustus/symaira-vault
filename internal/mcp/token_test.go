package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestLoadOrCreateTokenCreatesFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mcp-token")

	token, err := LoadOrCreateToken(path)
	if err != nil {
		t.Fatalf("LoadOrCreateToken() error = %v", err)
	}
	if len(token) == 0 {
		t.Fatal("token is empty")
	}

	token2, err := LoadOrCreateToken(path)
	if err != nil {
		t.Fatalf("second LoadOrCreateToken() error = %v", err)
	}
	if token != token2 {
		t.Fatalf("token changed on second load: %q vs %q", token, token2)
	}
}

func TestLoadOrCreateTokenRespectsEnvVar(t *testing.T) {
	t.Setenv("OPENPASS_MCP_TOKEN", "my-custom-token")

	token, err := LoadOrCreateToken("/nonexistent/path")
	if err != nil {
		t.Fatalf("LoadOrCreateToken() error = %v", err)
	}
	if token != "my-custom-token" {
		t.Fatalf("token = %q, want %q", token, "my-custom-token")
	}
}

func TestLoadOrCreateTokenFilePermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on windows: file permissions differ")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "mcp-token")

	_, err := LoadOrCreateToken(path)
	if err != nil {
		t.Fatalf("LoadOrCreateToken() error = %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat() error = %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("file permissions = %o, want 600", perm)
	}
}

func TestLoadOrCreateToken_WhitespaceFile_GeneratesNewToken(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mcp-token")

	if err := os.WriteFile(path, []byte("   \n\t  \n"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	token, err := LoadOrCreateToken(path)
	if err != nil {
		t.Fatalf("LoadOrCreateToken() error = %v", err)
	}
	if token == "" {
		t.Fatal("expected generated token, got empty string")
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if string(data) != token+"\n" {
		t.Fatalf("file content = %q, want %q", string(data), token+"\n")
	}
}

func TestLoadOrCreateToken_FileTokenIgnoresEnv(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mcp-token")

	if err := os.WriteFile(path, []byte("file-token\n"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	t.Setenv("OPENPASS_MCP_TOKEN", "env-token")

	oldStderr := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe() error = %v", err)
	}
	os.Stderr = w

	token, err := LoadOrCreateToken(path)

	os.Stderr = oldStderr
	_ = w.Close()

	var buf bytes.Buffer
	_, _ = buf.ReadFrom(r)

	if err != nil {
		t.Fatalf("LoadOrCreateToken() error = %v", err)
	}
	if token != "file-token" {
		t.Fatalf("token = %q, want %q", token, "file-token")
	}
	if !bytes.Contains(buf.Bytes(), []byte("Warning: OPENPASS_MCP_TOKEN is set")) {
		t.Fatalf("expected stderr warning, got %q", buf.String())
	}
}

func TestLoadOrCreateToken_RandError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mcp-token")

	oldReader := randReader
	randReader = &errorReader{}
	defer func() { randReader = oldReader }()

	_, err := LoadOrCreateToken(path)
	if err == nil {
		t.Fatal("expected error from rand.Reader failure")
	}
}

func TestLoadOrCreateToken_WriteFileError(t *testing.T) {
	t.Setenv("OPENPASS_MCP_TOKEN", "")
	path := filepath.Join("/nonexistent-dir-openpass-test", "mcp-token")
	_, err := LoadOrCreateToken(path)
	if err == nil {
		t.Fatal("expected error from WriteFile failure")
	}
}

type errorReader struct{}

func (e *errorReader) Read(p []byte) (int, error) {
	return 0, errors.New("rand failure")
}

func TestRotateTokenCreatesNewToken(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mcp-token")

	if err := os.WriteFile(path, []byte("old-token\n"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	newToken, err := RotateToken(path)
	if err != nil {
		t.Fatalf("RotateToken() error = %v", err)
	}
	if newToken == "" {
		t.Fatal("new token is empty")
	}
	if newToken == "old-token" {
		t.Fatal("RotateToken should have generated a new token, not returned the old one")
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if string(data) != newToken+"\n" {
		t.Fatalf("file content = %q, want %q", string(data), newToken+"\n")
	}
}

func TestRotateTokenSetsCorrectPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on windows: file permissions differ")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "mcp-token")

	_, err := RotateToken(path)
	if err != nil {
		t.Fatalf("RotateToken() error = %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat() error = %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("file permissions = %o, want 600", perm)
	}
}

func TestRotateTokenGeneratesDifferentTokens(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mcp-token")

	token1, err := RotateToken(path)
	if err != nil {
		t.Fatalf("RotateToken() error = %v", err)
	}

	token2, err := RotateToken(path)
	if err != nil {
		t.Fatalf("RotateToken() error = %v", err)
	}

	if token1 == token2 {
		t.Fatal("consecutive RotateToken calls should generate different tokens")
	}
}

func TestRotateToken_RandError(t *testing.T) {
	oldReader := randReader
	randReader = &errorReader{}
	defer func() { randReader = oldReader }()

	_, err := RotateToken("/nonexistent/path")
	if err == nil {
		t.Fatal("expected error from rand.Reader failure")
	}
}

func TestTokenFilePath(t *testing.T) {
	result := TokenFilePath("/path/to/vault")
	expected := filepath.Join("/path/to/vault", "mcp-token")
	if result != expected {
		t.Errorf("TokenFilePath() = %q, want %q", result, expected)
	}
}

func TestTokenRegistry_CreateLoadSave_Roundtrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mcp-tokens.json")

	reg := NewTokenRegistry(path)

	// Create a token.
	expiry := 1 * time.Hour
	_, raw, err := reg.Create("test-token", []string{"get_entry", "list_entries"}, "claude-code", expiry)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if len(raw) != 64 {
		t.Fatalf("raw token length = %d, want 64", len(raw))
	}

	// Verify persistence.
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("registry file not created: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}

	// Parse the JSON to verify it does NOT contain the raw token.
	var file TokenRegistryFile
	if err := json.Unmarshal(data, &file); err != nil {
		t.Fatalf("unmarshal registry: %v", err)
	}
	if file.Version < 1 || file.Version > 2 {
		t.Errorf("version = %d, want 1 or 2", file.Version)
	}
	if len(file.Tokens) != 1 {
		t.Fatalf("token count = %d, want 1", len(file.Tokens))
	}
	for _, entry := range file.Tokens {
		if entry.Hash == raw {
			t.Fatal("registry file contains raw token — must only contain hash")
		}
		if entry.Prefix != raw[:4] {
			t.Errorf("prefix = %q, want %q", entry.Prefix, raw[:4])
		}
		if len(entry.AllowedTools) != 2 {
			t.Errorf("allowed tools = %v, want [get_entry list_entries]", entry.AllowedTools)
		}
		if entry.AgentName != "claude-code" {
			t.Errorf("agent name = %q, want claude-code", entry.AgentName)
		}
		if entry.ExpiresAt == nil {
			t.Fatal("expires_at should not be nil")
		}
		if entry.Revoked {
			t.Fatal("new token should not be revoked")
		}
	}

	// Load into a fresh registry.
	reg2 := NewTokenRegistry(path)
	if err := reg2.Load(); err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	hash := sha256Hex(raw)
	tok, ok := reg2.Get(hash)
	if !ok {
		t.Fatal("Get() returned false for valid token")
	}
	if tok.ID == "" {
		t.Fatal("token ID is empty")
	}
	if !tok.IsToolAllowed("get_entry") {
		t.Error("token should allow get_entry")
	}
	if tok.IsToolAllowed("delete_entry") {
		t.Error("token should not allow delete_entry")
	}
}

func TestTokenRegistry_CreateTTL(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mcp-tokens.json")

	reg := NewTokenRegistry(path)

	// No expiry (ttl=0).
	st, raw, err := reg.Create("persistent", []string{"*"}, "", 0)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if st.IsExpired() {
		t.Error("token without TTL should not be expired")
	}

	// Short-lived token that expires immediately in practice.
	st2, raw2, err := reg.Create("short-lived", []string{"*"}, "", 1*time.Nanosecond)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	time.Sleep(5 * time.Millisecond)
	if !st2.IsExpired() {
		t.Error("token with 1ns TTL should be expired after sleep")
	}

	// Look up expired token via Get — should not be found.
	hash2 := sha256Hex(raw2)
	if _, ok := reg.Get(hash2); ok {
		t.Error("Get() on expired token should return false")
	}

	// Persistent token should still be found.
	hash := sha256Hex(raw)
	if _, ok := reg.Get(hash); !ok {
		t.Error("Get() on persistent token should return true")
	}
}

func TestTokenRegistry_Revoke(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mcp-tokens.json")

	reg := NewTokenRegistry(path)

	st, raw, err := reg.Create("revoke-me", []string{"*"}, "", 0)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	hash := sha256Hex(raw)

	// Token should be findable before revoke.
	if _, ok := reg.Get(hash); !ok {
		t.Fatal("token should be found before revoke")
	}

	// Revoke.
	if !reg.Revoke(st.ID) {
		t.Fatal("Revoke() returned false for valid token")
	}

	// Double revoke should return false.
	if reg.Revoke(st.ID) {
		t.Error("second Revoke() should return false")
	}

	// Get should not find it.
	if _, ok := reg.Get(hash); ok {
		t.Error("Get() should return false for revoked token")
	}

	// But List should include it (audit trail).
	tokens := reg.List()
	var found bool
	for _, t2 := range tokens {
		if t2.ID == st.ID {
			found = true
			if !t2.Revoked {
				t.Error("revoked token should have Revoked=true")
			}
			if t2.RevokedAt == nil {
				t.Error("revoked token should have RevokedAt set")
			}
		}
	}
	if !found {
		t.Error("List() should include revoked tokens")
	}

	// Revoke non-existent token.
	if reg.Revoke("nonexistent") {
		t.Error("Revoke() on nonexistent ID should return false")
	}
}

func TestTokenRegistry_List_ExcludesExpired(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mcp-tokens.json")

	reg := NewTokenRegistry(path)

	// Create short-lived token that will be expired at List() time.
	_, _, err := reg.Create("short-lived-list", []string{"*"}, "", 1*time.Nanosecond)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	// Create valid token.
	_, _, err = reg.Create("valid-list", []string{"*"}, "", 1*time.Hour)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	time.Sleep(5 * time.Millisecond)
	tokens := reg.List()
	if len(tokens) != 1 {
		t.Errorf("List() count = %d, want 1 (expired token excluded)", len(tokens))
	}
}

func TestTokenRegistry_Get_LazyExpiry(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mcp-tokens.json")

	reg := NewTokenRegistry(path)

	// Create token that expires in 500ms (generous margin for slow CI runners).
	st, raw, err := reg.Create("short-lived", []string{"*"}, "", 500*time.Millisecond)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	_ = st
	hash := sha256Hex(raw)

	// Should be found immediately.
	if _, ok := reg.Get(hash); !ok {
		t.Fatal("token should be found before expiry")
	}

	// Wait for expiry.
	time.Sleep(600 * time.Millisecond)

	// Should NOT be found after expiry — lazy check.
	if _, ok := reg.Get(hash); ok {
		t.Error("Get() should return false for expired token")
	}

	// Verify it was removed from the in-memory map (not just hidden).
	reg.mu.RLock()
	_, inMap := reg.entries[hash]
	reg.mu.RUnlock()
	if inMap {
		t.Error("expired token should be removed from entries map")
	}
}

func TestTokenRegistry_BackgroundCleanup(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mcp-tokens.json")

	reg := NewTokenRegistry(path)

	// Create two tokens: one short-lived, one persistent.
	_, _, err := reg.Create("short-lived", []string{"*"}, "", 100*time.Millisecond)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	_, _, err = reg.Create("persistent", []string{"*"}, "", 1*time.Hour)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	stop := reg.StartCleanup(ctx, 50*time.Millisecond)
	defer stop()

	// Wait for cleanup to run at least once.
	time.Sleep(300 * time.Millisecond)

	reg.mu.RLock()
	count := len(reg.entries)
	reg.mu.RUnlock()

	if count != 1 {
		t.Errorf("entries after cleanup = %d, want 1 (persistent only)", count)
	}
}

func TestTokenRegistry_ConcurrentCreateAndGet(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mcp-tokens.json")

	reg := NewTokenRegistry(path)

	// We'll store raw tokens in a slice to verify get after creation.
	var rawTokens []string
	var rawMu sync.Mutex
	var wg sync.WaitGroup
	var createErrors int32
	const numTokens = 20

	// Concurrent creates.
	for i := 0; i < numTokens; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			st, raw, err := reg.Create(
				fmt.Sprintf("token-%d", idx),
				[]string{"get_entry", "list_entries"},
				"claude-code",
				1*time.Hour,
			)
			if err != nil {
				atomic.AddInt32(&createErrors, 1)
				return
			}
			_ = st
			rawMu.Lock()
			rawTokens = append(rawTokens, raw)
			rawMu.Unlock()
		}(i)
	}
	wg.Wait()

	if int(atomic.LoadInt32(&createErrors)) != 0 {
		t.Fatalf("Create() had %d errors", createErrors)
	}

	// Concurrent gets.
	var getErrors int32
	wg.Add(len(rawTokens))
	for _, raw := range rawTokens {
		go func(rawToken string) {
			defer wg.Done()
			hash := sha256Hex(rawToken)
			tok, ok := reg.Get(hash)
			if !ok {
				atomic.AddInt32(&getErrors, 1)
				return
			}
			if tok.Hash != hash {
				atomic.AddInt32(&getErrors, 1)
			}
		}(raw)
	}
	wg.Wait()

	if int(atomic.LoadInt32(&getErrors)) != 0 {
		t.Fatalf("Get() had %d errors", getErrors)
	}

	// Verify total count.
	tokens := reg.List()
	if len(tokens) != numTokens {
		t.Errorf("List() count = %d, want %d", len(tokens), numTokens)
	}
}

func TestTokenRegistry_GetNotFound(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mcp-tokens.json")
	reg := NewTokenRegistry(path)

	// Empty registry.
	if _, ok := reg.Get("nohash"); ok {
		t.Error("Get() on empty registry should return false")
	}

	// Create a token and look up a different hash.
	reg.Create("t1", []string{"*"}, "", 0)
	if _, ok := reg.Get("wronghash"); ok {
		t.Error("Get() with wrong hash should return false")
	}
}

func TestTokenRegistry_IsToolAllowed_Wildcards(t *testing.T) {
	tok := &ScopedToken{
		AllowedTools: []string{"*"},
	}

	if !tok.IsToolAllowed("any_tool") {
		t.Error("wildcard '*' should allow any tool")
	}
	if !tok.IsToolAllowed("") {
		t.Error("wildcard '*' should allow empty tool name")
	}
}

func TestTokenRegistry_IsToolAllowed_ExactMatch(t *testing.T) {
	tok := &ScopedToken{
		AllowedTools: []string{"get_entry", "list_entries", "find_entries"},
	}

	if !tok.IsToolAllowed("get_entry") {
		t.Error("should allow get_entry")
	}
	if !tok.IsToolAllowed("list_entries") {
		t.Error("should allow list_entries")
	}
	if tok.IsToolAllowed("delete_entry") {
		t.Error("should not allow delete_entry")
	}
	if tok.IsToolAllowed("") {
		t.Error("should not allow empty tool")
	}
}

func TestTokenRegistry_IsToolAllowed_AliasNames(t *testing.T) {
	tok := &ScopedToken{
		AllowedTools: []string{"delete_entry", "openpass_delete"},
	}

	if !tok.IsToolAllowed("delete_entry") {
		t.Error("should allow delete_entry")
	}
	if !tok.IsToolAllowed("openpass_delete") {
		t.Error("should allow openpass_delete")
	}
}

func TestTokenRegistry_IsToolAllowed_EmptyList(t *testing.T) {
	tok := &ScopedToken{
		AllowedTools: []string{},
	}

	if tok.IsToolAllowed("anything") {
		t.Error("empty allowed list should deny everything")
	}
}

func TestTokenRegistry_IsToolAllowed_NilToken(t *testing.T) {
	var tok *ScopedToken
	if tok.IsToolAllowed("anything") {
		t.Error("nil token should deny everything")
	}
}

func TestTokenRegistry_UpdateLastUsed(t *testing.T) {
	tok := &ScopedToken{}
	if tok.LastUsedAt != nil {
		t.Error("LastUsedAt should be nil initially")
	}

	tok.UpdateLastUsed()
	if tok.LastUsedAt == nil {
		t.Fatal("LastUsedAt should be set after UpdateLastUsed")
	}

	// UpdateLastUsed on nil should not panic.
	var nilTok *ScopedToken
	nilTok.UpdateLastUsed()
}

func TestTokenRegistry_NilIsExpired(t *testing.T) {
	var tok *ScopedToken
	if !tok.IsExpired() {
		t.Error("nil token should be considered expired")
	}
}

func TestTokenRegistry_NilUpdateLastUsed(t *testing.T) {
	var tok *ScopedToken
	tok.UpdateLastUsed() // should not panic
}

func TestTokenRegistry_SaveFilePermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on windows: file permissions differ")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "mcp-tokens.json")

	reg := NewTokenRegistry(path)
	if _, _, err := reg.Create("test", []string{"*"}, "", 0); err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat() error = %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("registry file permissions = %o, want 600", perm)
	}
}

func TestTokenRegistry_Load_NonexistentFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mcp-tokens.json")

	reg := NewTokenRegistry(path)
	if err := reg.Load(); err != nil {
		t.Fatalf("Load() on nonexistent file should not error: %v", err)
	}

	if len(reg.List()) != 0 {
		t.Error("Load() on nonexistent file should produce empty registry")
	}
}

func TestTokenRegistry_Load_CorruptFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mcp-tokens.json")

	if err := os.WriteFile(path, []byte("not valid json {{{"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	reg := NewTokenRegistry(path)
	if err := reg.Load(); err == nil {
		t.Fatal("Load() should error on corrupt JSON")
	}
}

func TestTokenRegistry_Create_RandError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mcp-tokens.json")

	oldReader := randReader
	randReader = &errorReader{}
	defer func() { randReader = oldReader }()

	reg := NewTokenRegistry(path)
	_, _, err := reg.Create("test", []string{"*"}, "", 0)
	if err == nil {
		t.Fatal("Create() should error on rand failure")
	}
}

func TestTokenRegistry_Create_WriteError(t *testing.T) {
	path := filepath.Join("/nonexistent-registry-dir-openpass", "mcp-tokens.json")
	reg := NewTokenRegistry(path)

	_, _, err := reg.Create("test", []string{"*"}, "", 0)
	if err == nil {
		t.Fatal("Create() should error on write failure")
	}
}

func TestTokenRegistry_Close(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mcp-tokens.json")

	reg := NewTokenRegistry(path)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	stop := reg.StartCleanup(ctx, time.Hour)
	_ = stop

	if err := reg.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	// Close without cleanup started should not panic.
	reg2 := NewTokenRegistry(path)
	if err := reg2.Close(); err != nil {
		t.Fatalf("Close() on registry without cleanup error = %v", err)
	}
}

func TestTokenRegistry_Load_Tokens(t *testing.T) {
	// Verify that Version field is set on save.
	dir := t.TempDir()
	path := filepath.Join(dir, "mcp-tokens.json")

	reg := NewTokenRegistry(path)
	_, _, err := reg.Create("t1", []string{"*"}, "", 0)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	var file TokenRegistryFile
	if err := json.Unmarshal(data, &file); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if file.Version < 1 || file.Version > 2 {
		t.Errorf("Version = %d, want 1 or 2", file.Version)
	}
}

func TestTokenRegistry_Load_EmptyEntries(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mcp-tokens.json")

	empty := TokenRegistryFile{Version: 1, Tokens: map[string]TokenRegistryEntry{}}
	data, _ := json.Marshal(empty)
	os.WriteFile(path, data, 0o600)

	reg := NewTokenRegistry(path)
	if err := reg.Load(); err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if len(reg.List()) != 0 {
		t.Error("empty file should produce empty registry")
	}
}

func TestTokenRegistryFilePath(t *testing.T) {
	result := TokenRegistryFilePath("/path/to/vault")
	expected := filepath.Join("/path/to/vault", "mcp-tokens.json")
	if result != expected {
		t.Errorf("TokenRegistryFilePath() = %q, want %q", result, expected)
	}
}

func TestLoadTokenSystem_NewRegistry(t *testing.T) {
	dir := t.TempDir()

	// Pre-populate the registry with one token.
	regPath := TokenRegistryFilePath(dir)
	reg := NewTokenRegistry(regPath)
	st, raw, err := reg.Create("test", []string{"get_entry"}, "test-agent", 1*time.Hour)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	// Load via LoadTokenSystem.
	reg2, legacyToken, err := LoadTokenSystem(dir)
	if err != nil {
		t.Fatalf("LoadTokenSystem() error = %v", err)
	}
	if legacyToken != "" {
		t.Errorf("legacyToken should be empty for new registry, got %q", legacyToken)
	}

	hash := sha256Hex(raw)
	tok, ok := reg2.Get(hash)
	if !ok {
		t.Fatal("Get() should find the loaded token")
	}
	if tok.ID != st.ID {
		t.Errorf("token ID = %q, want %q", tok.ID, st.ID)
	}
}

func TestLoadTokenSystem_LegacyFallback(t *testing.T) {
	dir := t.TempDir()

	// Write legacy token file.
	legacyPath := filepath.Join(dir, "mcp-token")
	if err := os.WriteFile(legacyPath, []byte("legacy-token-value-0123456789abcdef\n"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	// Load via LoadTokenSystem — should fall back and seed registry.
	reg, legacyToken, err := LoadTokenSystem(dir)
	if err != nil {
		t.Fatalf("LoadTokenSystem() error = %v", err)
	}
	if legacyToken != "legacy-token-value-0123456789abcdef" {
		t.Errorf("legacyToken = %q, want %q", legacyToken, "legacy-token-value-0123456789abcdef")
	}

	// The legacy token should be in the registry with wildcard access.
	hash := sha256Hex("legacy-token-value-0123456789abcdef")
	tok, ok := reg.Get(hash)
	if !ok {
		t.Fatal("legacy token should be in the registry")
	}
	if !strings.HasPrefix(tok.Label, "legacy") {
		t.Errorf("label = %q, want prefix 'legacy'", tok.Label)
	}
	if !tok.IsToolAllowed("any_tool") {
		t.Error("legacy token should have wildcard access")
	}

	// Verify the registry file was created.
	regPath := TokenRegistryFilePath(dir)
	if _, err := os.Stat(regPath); err != nil {
		t.Logf("registry file may not exist (Save best-effort): %v", err)
	}
}

func TestLoadTokenSystem_LegacyMissingFile(t *testing.T) {
	dir := t.TempDir()

	reg, legacyToken, err := LoadTokenSystem(dir)
	if err != nil {
		t.Fatalf("LoadTokenSystem() error = %v", err)
	}
	// Legacy file doesn't exist, so a new one is created.
	if legacyToken == "" {
		t.Fatal("legacyToken should not be empty (new token generated)")
	}
	if len(legacyToken) != 64 {
		t.Errorf("token length = %d, want 64", len(legacyToken))
	}

	// The generated token should be in registry.
	hash := sha256Hex(legacyToken)
	if _, ok := reg.Get(hash); !ok {
		t.Error("generated legacy token should be in registry")
	}
}

func TestGenerateTokenID_Format(t *testing.T) {
	id := GenerateTokenID()
	if len(id) == 0 {
		t.Fatal("token ID is empty")
	}

	// Format: tok-YYYYMMDD-xxxxxxxx
	if len(id) != 21 { // tok-YYYYMMDD-xxxxxxxx = 4 + 1 + 8 + 1 + 8 = 21
		t.Errorf("token ID length = %d, want 21 (%q)", len(id), id)
	}
	if id[:4] != "tok-" {
		t.Errorf("token ID should start with 'tok-', got %q", id[:4])
	}
}

func TestGenerateTokenID_Uniqueness(t *testing.T) {
	ids := make(map[string]bool)
	for i := 0; i < 100; i++ {
		id := GenerateTokenID()
		if ids[id] {
			t.Errorf("duplicate token ID generated: %q", id)
		}
		ids[id] = true
	}
}

func TestSha256Hex(t *testing.T) {
	result := sha256Hex("hello")
	if len(result) != 64 {
		t.Errorf("sha256 hex length = %d, want 64", len(result))
	}
	// Deterministic.
	result2 := sha256Hex("hello")
	if result != result2 {
		t.Error("sha256Hex should be deterministic")
	}
	// Different input → different hash.
	result3 := sha256Hex("world")
	if result == result3 {
		t.Error("different inputs should produce different hashes")
	}
}

func TestScopedToken_Roundtrip(t *testing.T) {
	now := time.Now().UTC()
	expiry := now.Add(1 * time.Hour)

	original := &ScopedToken{
		ID:           "tok-20260101-abc12345",
		Label:        "my-token",
		Hash:         sha256Hex("dummy"),
		Prefix:       "abcd",
		AllowedTools: []string{"get_entry", "list_entries"},
		AgentName:    "test-agent",
		CreatedAt:    now,
		ExpiresAt:    &expiry,
		LastUsedAt:   &now,
		Revoked:      false,
	}

	entry := original.toEntry()
	restored := entryToScopedToken(entry)

	if restored.ID != original.ID {
		t.Errorf("ID = %q, want %q", restored.ID, original.ID)
	}
	if restored.Label != original.Label {
		t.Errorf("Label = %q, want %q", restored.Label, original.Label)
	}
	if restored.Hash != original.Hash {
		t.Errorf("Hash = %q, want %q", restored.Hash, original.Hash)
	}
	if len(restored.AllowedTools) != 2 {
		t.Errorf("AllowedTools length = %d, want 2", len(restored.AllowedTools))
	}
}

func TestScopedToken_Roundtrip_NilFields(t *testing.T) {
	original := &ScopedToken{
		ID:        "tok-minimal",
		Hash:      sha256Hex("minimal"),
		Prefix:    "mini",
		CreatedAt: time.Now().UTC(),
	}

	// AllowedTools nil → should become empty slice.
	entry := original.toEntry()
	restored := entryToScopedToken(entry)

	if restored.AllowedTools == nil {
		t.Error("AllowedTools should be non-nil empty slice after roundtrip")
	}
	if len(restored.AllowedTools) != 0 {
		t.Errorf("AllowedTools length = %d, want 0", len(restored.AllowedTools))
	}
	if restored.ExpiresAt != nil {
		t.Error("ExpiresAt should be nil")
	}
	if restored.LastUsedAt != nil {
		t.Error("LastUsedAt should be nil")
	}
}

func TestScopedToken_NilToEntry(t *testing.T) {
	var tok *ScopedToken
	entry := tok.toEntry()
	if entry.ID != "" {
		t.Error("nil ScopedToken toEntry should return empty TokenRegistryEntry")
	}
}

func TestLoadTokenSystem_MigrationDeletesLegacyFile(t *testing.T) {
	dir := t.TempDir()

	legacyPath := TokenFilePath(dir)
	regPath := TokenRegistryFilePath(dir)

	if err := os.WriteFile(legacyPath, []byte("migration-legacy-token-1234567890abc\n"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	reg, legacyToken, err := LoadTokenSystem(dir)
	if err != nil {
		t.Fatalf("LoadTokenSystem() error = %v", err)
	}
	if legacyToken != "migration-legacy-token-1234567890abc" {
		t.Errorf("legacyToken = %q, want %q", legacyToken, "migration-legacy-token-1234567890abc")
	}

	if _, err := os.Stat(legacyPath); !os.IsNotExist(err) {
		t.Error("legacy mcp-token file should be deleted after successful migration")
	}

	if _, err := os.Stat(regPath); err != nil {
		t.Fatalf("registry file not created: %v", err)
	}

	hash := sha256Hex("migration-legacy-token-1234567890abc")
	tok, ok := reg.Get(hash)
	if !ok {
		t.Fatal("migrated token not found in registry")
	}
	if !strings.HasPrefix(tok.Label, "legacy") {
		t.Errorf("label = %q, want prefix 'legacy'", tok.Label)
	}
	if !tok.IsToolAllowed("*") {
		t.Error("migrated token should have wildcard access")
	}
}

func TestLoadTokenSystem_MigrationIdempotent(t *testing.T) {
	dir := t.TempDir()

	legacyPath := TokenFilePath(dir)

	if err := os.WriteFile(legacyPath, []byte("idempotent-token-abcdef0123456789\n"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	reg1, token1, err := LoadTokenSystem(dir)
	if err != nil {
		t.Fatalf("first LoadTokenSystem() error = %v", err)
	}
	if token1 != "idempotent-token-abcdef0123456789" {
		t.Errorf("first legacyToken = %q, want %q", token1, "idempotent-token-abcdef0123456789")
	}

	reg2, token2, err := LoadTokenSystem(dir)
	if err != nil {
		t.Fatalf("second LoadTokenSystem() error = %v", err)
	}
	if token2 != "" {
		t.Errorf("second legacyToken = %q, want empty (registry already populated)", token2)
	}

	hash := sha256Hex("idempotent-token-abcdef0123456789")
	tok1, ok1 := reg1.Get(hash)
	tok2, ok2 := reg2.Get(hash)
	if !ok1 || !ok2 {
		t.Fatal("token should be found in both registries")
	}
	if tok1.ID != tok2.ID {
		t.Error("token IDs should match across idempotent loads")
	}
}

func TestLoadTokenSystem_LegacyAuthStillWorks(t *testing.T) {
	dir := t.TempDir()

	legacyPath := TokenFilePath(dir)
	if err := os.WriteFile(legacyPath, []byte("auth-test-token-zyxwvutsrqponmlkji\n"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	reg, legacyToken, err := LoadTokenSystem(dir)
	if err != nil {
		t.Fatalf("LoadTokenSystem() error = %v", err)
	}

	hash := sha256Hex(legacyToken)
	tok, ok := reg.Get(hash)
	if !ok {
		t.Fatal("legacy token should authenticate after migration")
	}

	if !tok.IsToolAllowed("get_entry") {
		t.Error("migrated token should allow get_entry")
	}
	if !tok.IsToolAllowed("delete_entry") {
		t.Error("migrated token should allow delete_entry (wildcard)")
	}
	if !tok.IsToolAllowed("*") {
		t.Error("migrated token should have wildcard access")
	}

	if !reg.Revoke(tok.ID) {
		t.Fatal("Revoke() should work on migrated token")
	}
	if _, ok := reg.Get(hash); ok {
		t.Error("revoked token should not be found via Get()")
	}
}
