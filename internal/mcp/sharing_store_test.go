package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	openpasscrypto "github.com/danieljustus/OpenPass/internal/crypto"
)

func TestShareStore_CreateGet_Roundtrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mcp-shares.json")

	store := NewShareStore(path)

	g, err := store.Create("agent-a", "agent-b", "vault/secret/password", "", 0)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if g.ID == "" {
		t.Fatal("grant ID is empty")
	}
	if g.Status != SharePending {
		t.Errorf("status = %q, want %q", g.Status, SharePending)
	}
	if g.FromAgent != "agent-a" {
		t.Errorf("FromAgent = %q, want %q", g.FromAgent, "agent-a")
	}
	if g.ToAgent != "agent-b" {
		t.Errorf("ToAgent = %q, want %q", g.ToAgent, "agent-b")
	}
	if g.SecretPath != "vault/secret/password" {
		t.Errorf("SecretPath = %q, want %q", g.SecretPath, "vault/secret/password")
	}

	// Get should find it by ID.
	got, ok := store.Get(g.ID)
	if !ok {
		t.Fatal("Get() returned false for valid grant")
	}
	if got.ID != g.ID {
		t.Errorf("Get() ID = %q, want %q", got.ID, g.ID)
	}

	// Get on non-existent ID should return false.
	if _, ok := store.Get("nonexistent"); ok {
		t.Error("Get() should return false for nonexistent ID")
	}
}

func TestShareStore_ApproveWithTTL(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mcp-shares.json")

	store := NewShareStore(path)

	g, err := store.Create("agent-a", "agent-b", "vault/secret/key", "", 5*time.Minute)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	if g.ExpiresAt == nil {
		t.Fatal("ExpiresAt should be set when TTL > 0")
	}
	if g.ExpiresAt.Sub(g.CreatedAt) != 5*time.Minute {
		t.Errorf("ExpiresAt delta = %v, want 5m", g.ExpiresAt.Sub(g.CreatedAt))
	}

	// Approve
	if err := store.Approve(g.ID, "admin"); err != nil {
		t.Fatalf("Approve() error = %v", err)
	}

	got, ok := store.Get(g.ID)
	if !ok {
		t.Fatal("Get() after approve returned false")
	}
	if got.Status != ShareApproved {
		t.Errorf("status after approve = %q, want %q", got.Status, ShareApproved)
	}
	if got.ApprovedAt == nil {
		t.Fatal("ApprovedAt should be set after approve")
	}
	if got.ApprovedBy != "admin" {
		t.Errorf("ApprovedBy = %q, want %q", got.ApprovedBy, "admin")
	}
	// ExpiresAt should be extended from approval time, not creation time.
	if got.ExpiresAt == nil {
		t.Fatal("ExpiresAt should still be set after approve")
	}
	if !got.ApprovedAt.Before(*got.ExpiresAt) {
		t.Error("ApprovedAt should be before ExpiresAt")
	}
}

func TestShareStore_Revoke(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mcp-shares.json")

	store := NewShareStore(path)

	g, err := store.Create("agent-a", "agent-b", "vault/secret/api-key", "", 0)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	// Approve first.
	if err := store.Approve(g.ID, "admin"); err != nil {
		t.Fatalf("Approve() error = %v", err)
	}

	// Revoke.
	if err := store.Revoke(g.ID); err != nil {
		t.Fatalf("Revoke() error = %v", err)
	}

	got, ok := store.Get(g.ID)
	if !ok {
		t.Fatal("Get() after revoke should still find the grant")
	}
	if got.Status != ShareRevoked {
		t.Errorf("status after revoke = %q, want %q", got.Status, ShareRevoked)
	}
	if got.RevokedAt == nil {
		t.Fatal("RevokedAt should be set after revoke")
	}

	// Double revoke should fail.
	if err := store.Revoke(g.ID); err == nil {
		t.Error("second Revoke() should return error")
	}

	// Revoke non-existent grant.
	if err := store.Revoke("nonexistent"); err == nil {
		t.Error("Revoke() on nonexistent ID should return error")
	}
}

func TestShareStore_Reject(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mcp-shares.json")

	store := NewShareStore(path)

	g, err := store.Create("agent-a", "agent-b", "vault/secret/token", "", 0)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	if err := store.Reject(g.ID); err != nil {
		t.Fatalf("Reject() error = %v", err)
	}

	got, ok := store.Get(g.ID)
	if !ok {
		t.Fatal("Get() after reject should still find the grant")
	}
	if got.Status != ShareRejected {
		t.Errorf("status after reject = %q, want %q", got.Status, ShareRejected)
	}

	// Double reject should fail.
	if err := store.Reject(g.ID); err == nil {
		t.Error("second Reject() should return error")
	}

	// Reject non-existent grant.
	if err := store.Reject("nonexistent"); err == nil {
		t.Error("Reject() on nonexistent ID should return error")
	}
}

func TestShareStore_Approve_PendingOnly(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mcp-shares.json")

	store := NewShareStore(path)

	g, err := store.Create("a", "b", "path", "", 0)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	// Approve once.
	if err := store.Approve(g.ID, "admin"); err != nil {
		t.Fatalf("first Approve() error = %v", err)
	}

	// Approve again should fail.
	if err := store.Approve(g.ID, "admin"); err == nil {
		t.Error("second Approve() on already-approved grant should fail")
	}

	// Reject an approved grant should fail.
	if err := store.Reject(g.ID); err == nil {
		t.Error("Reject() on approved grant should fail")
	}
}

func TestShareStore_CleanupExpired(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mcp-shares.json")

	store := NewShareStore(path)

	// Create grant with 1ns TTL (expires immediately).
	g1, err := store.Create("a", "b", "path1", "", 1*time.Nanosecond)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	// Create grant with no TTL (never expires).
	g2, err := store.Create("a", "b", "path2", "", 0)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	// Create grant with long TTL (1 hour).
	g3, err := store.Create("a", "b", "path3", "", 1*time.Hour)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	// Approve g1 so it has a reference point for expiry.
	_ = store.Approve(g1.ID, "admin")

	// Let time pass so g1 expires.
	time.Sleep(5 * time.Millisecond)

	removed := store.CleanupExpired()
	if removed != 1 {
		t.Errorf("CleanupExpired() removed = %d, want 1", removed)
	}

	// g1 should be gone.
	if _, ok := store.Get(g1.ID); ok {
		t.Error("expired grant g1 should be removed")
	}

	// g2 (no TTL) should still exist.
	if _, ok := store.Get(g2.ID); !ok {
		t.Error("grant without TTL should still exist")
	}

	// g3 (future expiry) should still exist.
	if _, ok := store.Get(g3.ID); !ok {
		t.Error("grant with future expiry should still exist")
	}

	// Second cleanup should remove 0.
	removed = store.CleanupExpired()
	if removed != 0 {
		t.Errorf("second CleanupExpired() removed = %d, want 0", removed)
	}
}

func TestShareStore_ConcurrentCreateAndApprove(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mcp-shares.json")

	store := NewShareStore(path)

	var wg sync.WaitGroup
	var createErrors int32
	var approveErrors int32
	const numGrants = 20

	// Store grant IDs for later verification.
	var grantIDs []string
	var idMu sync.Mutex

	// Concurrent creates.
	for i := 0; i < numGrants; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			g, err := store.Create(
				fmt.Sprintf("agent-from-%d", idx),
				"agent-target",
				fmt.Sprintf("vault/secret/%d", idx),
				"",
				1*time.Hour,
			)
			if err != nil {
				atomic.AddInt32(&createErrors, 1)
				return
			}
			idMu.Lock()
			grantIDs = append(grantIDs, g.ID)
			idMu.Unlock()
		}(i)
	}
	wg.Wait()

	if int(atomic.LoadInt32(&createErrors)) != 0 {
		t.Fatalf("Create() had %d errors", createErrors)
	}

	// Concurrent approves.
	wg.Add(len(grantIDs))
	for _, id := range grantIDs {
		go func(gid string) {
			defer wg.Done()
			if err := store.Approve(gid, "admin"); err != nil {
				atomic.AddInt32(&approveErrors, 1)
			}
		}(id)
	}
	wg.Wait()

	if int(atomic.LoadInt32(&approveErrors)) != 0 {
		t.Fatalf("Approve() had %d errors", approveErrors)
	}

	// Verify all grants were approved.
	grants := store.List()
	if len(grants) != numGrants {
		t.Errorf("List() count = %d, want %d", len(grants), numGrants)
	}
	for _, g := range grants {
		if g.Status != ShareApproved {
			t.Errorf("grant %s status = %q, want %q", g.ID, g.Status, ShareApproved)
		}
	}
}

func TestShareStore_JSONRoundtrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mcp-shares.json")

	store := NewShareStore(path)

	g, err := store.Create("agent-a", "agent-b", "vault/secret/password", "password_field", 30*time.Minute)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	// Approve the grant.
	if err := store.Approve(g.ID, "admin"); err != nil {
		t.Fatalf("Approve() error = %v", err)
	}

	// Read the file and verify format.
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}

	var file shareStoreFile
	if err := json.Unmarshal(data, &file); err != nil {
		t.Fatalf("unmarshal store file: %v", err)
	}
	if file.Version != shareStoreVersion {
		t.Errorf("version = %d, want %d", file.Version, shareStoreVersion)
	}
	if len(file.Grants) != 1 {
		t.Fatalf("grants count = %d, want 1", len(file.Grants))
	}

	entry := file.Grants[0]
	if entry.ID != g.ID {
		t.Errorf("entry ID = %q, want %q", entry.ID, g.ID)
	}
	if entry.SecretField != "password_field" {
		t.Errorf("SecretField = %q, want %q", entry.SecretField, "password_field")
	}
	if entry.Status != ShareApproved {
		t.Errorf("status = %q, want %q", entry.Status, ShareApproved)
	}
	if entry.ApprovedAt == nil {
		t.Fatal("ApprovedAt should be set")
	}
	if entry.ExpiresAt == nil {
		t.Fatal("ExpiresAt should be set when TTL > 0")
	}

	// Load into a fresh store and verify roundtrip.
	store2 := NewShareStore(path)
	if err := store2.Load(); err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	got, ok := store2.Get(g.ID)
	if !ok {
		t.Fatal("Get() after Load() returned false")
	}
	if got.FromAgent != "agent-a" {
		t.Errorf("FromAgent = %q, want %q", got.FromAgent, "agent-a")
	}
	if got.ToAgent != "agent-b" {
		t.Errorf("ToAgent = %q, want %q", got.ToAgent, "agent-b")
	}
	if got.SecretPath != "vault/secret/password" {
		t.Errorf("SecretPath = %q, want %q", got.SecretPath, "vault/secret/password")
	}
	if got.SecretField != "password_field" {
		t.Errorf("SecretField = %q, want %q", got.SecretField, "password_field")
	}
	if got.Status != ShareApproved {
		t.Errorf("status = %q, want %q", got.Status, ShareApproved)
	}
	if got.ApprovedBy != "admin" {
		t.Errorf("ApprovedBy = %q, want %q", got.ApprovedBy, "admin")
	}
	if got.ExpiresAt == nil {
		t.Error("ExpiresAt should be preserved through roundtrip")
	}
}

func TestShareStore_CheckAccess(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mcp-shares.json")

	store := NewShareStore(path)

	// Approved grant (no TTL).
	g1, err := store.Create("alice", "bob", "vault/secret/api-key", "", 0)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if err := store.Approve(g1.ID, "alice"); err != nil {
		t.Fatalf("Approve() error = %v", err)
	}

	// Pending grant.
	_, err = store.Create("alice", "bob", "vault/secret/pending-key", "", 0)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	// Approved grant with short TTL (will expire).
	g3, err := store.Create("alice", "bob", "vault/secret/short-lived", "", 1*time.Nanosecond)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if err := store.Approve(g3.ID, "alice"); err != nil {
		t.Fatalf("Approve() error = %v", err)
	}

	// Approved grant for different agent.
	g4, err := store.Create("alice", "charlie", "vault/secret/api-key", "", 0)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if err := store.Approve(g4.ID, "alice"); err != nil {
		t.Fatalf("Approve() error = %v", err)
	}

	// Let short-lived grant expire.
	time.Sleep(5 * time.Millisecond)

	// Bob should have access to api-key (approved, no TTL).
	grant, ok := store.CheckAccess("bob", "vault/secret/api-key")
	if !ok {
		t.Fatal("CheckAccess should find approved grant for bob")
	}
	if grant.ID != g1.ID {
		t.Errorf("grant ID = %q, want %q", grant.ID, g1.ID)
	}

	// Bob should NOT have access to pending-key (pending).
	if _, ok := store.CheckAccess("bob", "vault/secret/pending-key"); ok {
		t.Error("CheckAccess should not find pending grant")
	}

	// Bob should NOT have access to short-lived (expired).
	if _, ok := store.CheckAccess("bob", "vault/secret/short-lived"); ok {
		t.Error("CheckAccess should not find expired grant")
	}

	// Charlie should have access to api-key (different agent, different grant).
	if _, ok := store.CheckAccess("charlie", "vault/secret/api-key"); !ok {
		t.Error("CheckAccess should find approved grant for charlie")
	}

	// Non-existent path.
	if _, ok := store.CheckAccess("bob", "vault/secret/nonexistent"); ok {
		t.Error("CheckAccess should not find non-existent path")
	}

	// Non-existent agent.
	if _, ok := store.CheckAccess("unknown", "vault/secret/api-key"); ok {
		t.Error("CheckAccess should not find unknown agent")
	}
}

func TestShareStore_Load_NonexistentFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mcp-shares.json")

	store := NewShareStore(path)
	if err := store.Load(); err != nil {
		t.Fatalf("Load() on nonexistent file should not error: %v", err)
	}
	if len(store.List()) != 0 {
		t.Error("Load() on nonexistent file should produce empty store")
	}
}

func TestShareStore_Load_CorruptFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mcp-shares.json")

	if err := os.WriteFile(path, []byte("not valid json {{{"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	store := NewShareStore(path)
	if err := store.Load(); err == nil {
		t.Fatal("Load() should error on corrupt JSON")
	}
}

func TestShareStore_Load_EmptyFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mcp-shares.json")

	empty := shareStoreFile{Version: shareStoreVersion, Grants: []ShareGrant{}}
	data, _ := json.Marshal(empty)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	store := NewShareStore(path)
	if err := store.Load(); err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if len(store.List()) != 0 {
		t.Error("empty file should produce empty store")
	}
}

func TestShareStore_List(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mcp-shares.json")

	store := NewShareStore(path)

	// Create grants with different attributes.
	g1, _ := store.Create("alice", "bob", "path/a", "", 0)
	_, _ = store.Create("alice", "charlie", "path/b", "", 0)
	_, _ = store.Create("bob", "alice", "path/c", "", 0)

	// List all.
	all := store.List()
	if len(all) != 3 {
		t.Errorf("List() count = %d, want 3", len(all))
	}

	// Filter by FromAgent.
	pending := SharePending
	filtered := store.List(ShareFilter{FromAgent: "alice"})
	if len(filtered) != 2 {
		t.Errorf("List(filter by FromAgent=alice) count = %d, want 2", len(filtered))
	}
	for _, g := range filtered {
		if g.FromAgent != "alice" {
			t.Errorf("expected FromAgent=alice, got %q", g.FromAgent)
		}
	}

	// Filter by ToAgent.
	filtered = store.List(ShareFilter{ToAgent: "charlie"})
	if len(filtered) != 1 {
		t.Errorf("List(filter by ToAgent=charlie) count = %d, want 1", len(filtered))
	}

	// Filter by status.
	filtered = store.List(ShareFilter{Status: &pending})
	if len(filtered) != 3 {
		t.Errorf("List(filter by Status=pending) count = %d, want 3", len(filtered))
	}

	// Approve g1 and filter by approved.
	_ = store.Approve(g1.ID, "admin")
	approved := ShareApproved
	filtered = store.List(ShareFilter{Status: &approved})
	if len(filtered) != 1 {
		t.Errorf("List(filter by Status=approved) count = %d, want 1", len(filtered))
	}

	// Filter by SecretPath.
	filtered = store.List(ShareFilter{SecretPath: "path/a"})
	if len(filtered) != 1 {
		t.Errorf("List(filter by SecretPath=path/a) count = %d, want 1", len(filtered))
	}

	// Combined filter.
	filtered = store.List(ShareFilter{
		FromAgent:  "alice",
		SecretPath: "path/a",
		Status:     &approved,
	})
	if len(filtered) != 1 {
		t.Errorf("List(combined filter) count = %d, want 1", len(filtered))
	}
}

func TestShareStore_ListForAgent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mcp-shares.json")

	store := NewShareStore(path)

	store.Create("alice", "bob", "path/a", "", 0)
	store.Create("bob", "alice", "path/b", "", 0)
	store.Create("charlie", "dave", "path/c", "", 0)

	// Alice is From or To in 2 grants.
	grants := store.ListForAgent("alice")
	if len(grants) != 2 {
		t.Errorf("ListForAgent(alice) count = %d, want 2", len(grants))
	}

	// Bob is From or To in 2 grants.
	grants = store.ListForAgent("bob")
	if len(grants) != 2 {
		t.Errorf("ListForAgent(bob) count = %d, want 2", len(grants))
	}

	// Unknown agent returns empty.
	grants = store.ListForAgent("unknown")
	if len(grants) != 0 {
		t.Errorf("ListForAgent(unknown) count = %d, want 0", len(grants))
	}
}

func TestShareStore_BackgroundCleanup(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mcp-shares.json")

	store := NewShareStore(path)

	// Create short-lived grant.
	g1, err := store.Create("a", "b", "path1", "", 50*time.Millisecond)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	_ = store.Approve(g1.ID, "admin")

	// Create persistent grant (no TTL).
	_, err = store.Create("a", "b", "path2", "", 0)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	stop := store.StartCleanup(ctx, 30*time.Millisecond)
	defer stop()

	// Wait for cleanup to run and remove the expired grant.
	time.Sleep(200 * time.Millisecond)

	// g1 should be gone (expired), path2 should remain.
	if _, ok := store.Get(g1.ID); ok {
		t.Error("short-lived grant should be removed by background cleanup")
	}

	grants := store.List()
	if len(grants) != 1 {
		t.Errorf("grants after cleanup = %d, want 1 (persistent only)", len(grants))
	}
}

func TestShareStore_Close(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mcp-shares.json")

	store := NewShareStore(path)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	stop := store.StartCleanup(ctx, time.Hour)
	_ = stop

	if err := store.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	// Close without cleanup should not panic.
	store2 := NewShareStore(path)
	if err := store2.Close(); err != nil {
		t.Fatalf("Close() on store without cleanup error = %v", err)
	}
}

func TestShareStore_SaveFilePermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on windows: file permissions behave differently")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "mcp-shares.json")

	store := NewShareStore(path)
	if _, err := store.Create("a", "b", "path", "", 0); err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat() error = %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("store file permissions = %o, want 600", perm)
	}
}

func TestShareStore_Create_WriteError(t *testing.T) {
	path := filepath.Join("/nonexistent-share-store-dir-openpass", "mcp-shares.json")
	store := NewShareStore(path)

	_, err := store.Create("a", "b", "path", "", 0)
	if err == nil {
		t.Fatal("Create() should error on write failure")
	}
}

func TestShareStore_ApproveNonExistent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mcp-shares.json")

	store := NewShareStore(path)
	if err := store.Approve("nonexistent", "admin"); err == nil {
		t.Error("Approve() on nonexistent ID should return error")
	}
}

func TestShareStore_RevokeFromPending(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mcp-shares.json")

	store := NewShareStore(path)

	g, err := store.Create("a", "b", "path", "", 0)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	// Revoke directly from pending (not approved first).
	if err := store.Revoke(g.ID); err != nil {
		t.Fatalf("Revoke() from pending should succeed: %v", err)
	}

	got, _ := store.Get(g.ID)
	if got.Status != ShareRevoked {
		t.Errorf("status = %q, want %q", got.Status, ShareRevoked)
	}
}

func TestShareStore_RejectAfterRevokeError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mcp-shares.json")

	store := NewShareStore(path)

	g, err := store.Create("a", "b", "path", "", 0)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	// Revoke first.
	if err := store.Revoke(g.ID); err != nil {
		t.Fatalf("Revoke() error = %v", err)
	}

	// Reject after revoke should fail.
	if err := store.Reject(g.ID); err == nil {
		t.Error("Reject() after revoke should fail")
	}
}

func TestShareStore_NilIsExpired(t *testing.T) {
	var g *ShareGrant
	if !g.IsExpired() {
		t.Error("nil grant should be considered expired")
	}
}

func TestShareStore_GrantIsExpired(t *testing.T) {
	g := &ShareGrant{ExpiresAt: nil}
	if g.IsExpired() {
		t.Error("grant without ExpiresAt should not be expired")
	}

	future := time.Now().Add(1 * time.Hour)
	g.ExpiresAt = &future
	if g.IsExpired() {
		t.Error("grant with future ExpiresAt should not be expired")
	}

	past := time.Now().Add(-1 * time.Hour)
	g.ExpiresAt = &past
	if !g.IsExpired() {
		t.Error("grant with past ExpiresAt should be expired")
	}
}

func TestShareStoreFilePath(t *testing.T) {
	result := ShareStoreFilePath("/path/to/vault")
	expected := filepath.Join("/path/to/vault", "mcp-shares.json")
	if result != expected {
		t.Errorf("ShareStoreFilePath() = %q, want %q", result, expected)
	}
}

func TestShareStore_ConcurrentReadWrite(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mcp-shares.json")

	store := NewShareStore(path)

	// Create initial grant.
	g, err := store.Create("a", "b", "path", "", 0)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	var wg sync.WaitGroup
	var readErrors int32

	// Start concurrent readers while we modify.
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				if _, ok := store.Get(g.ID); !ok {
					atomic.AddInt32(&readErrors, 1)
				}
				_ = store.List()
			}
		}()
	}

	// Writer modifies the grant.
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// Create new grants concurrently.
			_, err := store.Create("a", "b", "path", "", 0)
			if err != nil {
				atomic.AddInt32(&readErrors, 1)
			}
		}()
	}

	wg.Wait()

	if int(atomic.LoadInt32(&readErrors)) != 0 {
		t.Fatalf("concurrent reads had %d errors (likely data race)", readErrors)
	}
}

// ---------------------------------------------------------------------------
// Edge case: CheckAccess with trailing slash and path normalization
// ---------------------------------------------------------------------------

func TestShareStore_CheckAccess_PathNormalization(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mcp-shares.json")
	store := NewShareStore(path)

	g, err := store.Create("alice", "bob", "vault/secret/api-key", "", 0)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if err := store.Approve(g.ID, "admin"); err != nil {
		t.Fatalf("Approve() error = %v", err)
	}

	// Exact match should work.
	if _, ok := store.CheckAccess("bob", "vault/secret/api-key"); !ok {
		t.Error("CheckAccess should match exact path")
	}

	// Different path with same prefix should NOT match (not a prefix check).
	if _, ok := store.CheckAccess("bob", "vault/secret/api-key/sub"); ok {
		t.Error("CheckAccess should not match subpath of grant path")
	}

	// Different path entirely.
	if _, ok := store.CheckAccess("bob", "vault/secret/other"); ok {
		t.Error("CheckAccess should not match different path")
	}

	// Trailing slash variant.
	if _, ok := store.CheckAccess("bob", "vault/secret/api-key/"); ok {
		t.Error("CheckAccess should not match with trailing slash")
	}
}

// ---------------------------------------------------------------------------
// CheckAccess: multiple matching grants
// ---------------------------------------------------------------------------

func TestShareStore_CheckAccess_MultipleMatchingGrants(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mcp-shares.json")
	store := NewShareStore(path)

	// Two different FromAgents sharing the same path to bob.
	g1, err := store.Create("alice", "bob", "shared/path", "", 0)
	if err != nil {
		t.Fatal(err)
	}
	g2, err := store.Create("charlie", "bob", "shared/path", "", 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Approve(g1.ID, "admin"); err != nil {
		t.Fatal(err)
	}
	if err := store.Approve(g2.ID, "admin"); err != nil {
		t.Fatal(err)
	}

	// CheckAccess should find the first matching grant.
	grant, ok := store.CheckAccess("bob", "shared/path")
	if !ok {
		t.Fatal("CheckAccess should find a grant")
	}
	if grant.ID != g1.ID && grant.ID != g2.ID {
		t.Errorf("unexpected grant ID: %q", grant.ID)
	}
}

func TestShareStore_ConcurrentApproveRevoke_DifferentGrants(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mcp-shares.json")
	store := NewShareStore(path)

	grants := make([]*ShareGrant, 10)
	for i := 0; i < 10; i++ {
		g, err := store.Create("alice", "bob", "vault/secret/key", "", 0)
		if err != nil {
			t.Fatalf("Create() error = %v", err)
		}
		grants[i] = g
	}

	var wg sync.WaitGroup
	results := make(chan string, 20)

	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			if err := store.Approve(grants[idx].ID, "admin"); err == nil {
				results <- "approved"
			}
		}(i)
	}
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			if err := store.Revoke(grants[idx].ID); err == nil {
				results <- "revoked"
			}
		}(i)
	}
	wg.Wait()
	close(results)

	var approvals, revocations int
	for r := range results {
		switch r {
		case "approved":
			approvals++
		case "revoked":
			revocations++
		}
	}

	if revocations != 10 {
		t.Errorf("expected 10 revocations, got %d", revocations)
	}

	for _, g := range grants {
		grant, ok := store.Get(g.ID)
		if !ok {
			t.Fatal("grant not found after concurrent operations")
		}
		if grant.Status != ShareRevoked {
			t.Errorf("grant %s status = %q, want revoked", g.ID, grant.Status)
		}
	}
}

func TestShareStore_ConcurrentApproveOnly(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mcp-shares.json")
	store := NewShareStore(path)

	grants := make([]*ShareGrant, 10)
	for i := 0; i < 10; i++ {
		g, err := store.Create("alice", "bob", "vault/secret/key", "", 0)
		if err != nil {
			t.Fatalf("Create() error = %v", err)
		}
		grants[i] = g
	}

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			if err := store.Approve(grants[idx].ID, "admin"); err != nil {
				t.Errorf("Approve() error = %v", err)
			}
		}(i)
	}
	wg.Wait()

	for _, g := range grants {
		grant, ok := store.Get(g.ID)
		if !ok {
			t.Fatal("grant not found after concurrent operations")
		}
		if grant.Status != ShareApproved {
			t.Errorf("grant %s status = %q, want approved", g.ID, grant.Status)
		}
	}
}

func TestShareStore_CheckAccess_ApprovedThenExpired(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mcp-shares.json")
	store := NewShareStore(path)

	g, err := store.Create("alice", "bob", "vault/secret/ephemeral", "", 100*time.Millisecond)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if err := store.Approve(g.ID, "admin"); err != nil {
		t.Fatalf("Approve() error = %v", err)
	}

	// Should be accessible immediately.
	if _, ok := store.CheckAccess("bob", "vault/secret/ephemeral"); !ok {
		t.Error("grant should be accessible right after approval")
	}

	// Wait for expiry.
	time.Sleep(200 * time.Millisecond)

	// Should NOT be accessible after expiry.
	if _, ok := store.CheckAccess("bob", "vault/secret/ephemeral"); ok {
		t.Error("expired grant should not be accessible")
	}
}

// ---------------------------------------------------------------------------
// CheckAccess: revoked grant
// ---------------------------------------------------------------------------

func TestShareStore_CheckAccess_RevokedGrant(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mcp-shares.json")
	store := NewShareStore(path)

	g, err := store.Create("alice", "bob", "vault/secret/key", "", 0)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if err := store.Approve(g.ID, "admin"); err != nil {
		t.Fatalf("Approve() error = %v", err)
	}
	if err := store.Revoke(g.ID); err != nil {
		t.Fatalf("Revoke() error = %v", err)
	}

	if _, ok := store.CheckAccess("bob", "vault/secret/key"); ok {
		t.Error("revoked grant should not be accessible")
	}
}

// ---------------------------------------------------------------------------
// JSON: version mismatch should still load grants
// ---------------------------------------------------------------------------

func TestShareStore_JSON_VersionMismatch(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mcp-shares.json")

	store := NewShareStore(path)
	g, err := store.Create("alice", "bob", "path", "", 0)
	if err != nil {
		t.Fatal(err)
	}

	// Manually rewrite with a different version.
	data, _ := os.ReadFile(path)
	var file shareStoreFile
	json.Unmarshal(data, &file)
	file.Version = 999
	modified, _ := json.MarshalIndent(file, "", "  ")
	os.WriteFile(path, append(modified, '\n'), 0o600)

	store2 := NewShareStore(path)
	if err := store2.Load(); err != nil {
		t.Fatalf("Load() with version mismatch should succeed: %v", err)
	}
	if _, ok := store2.Get(g.ID); !ok {
		t.Error("grant should be loaded despite version mismatch")
	}
}

// ---------------------------------------------------------------------------
// JSON: field ordering and extra fields (forward compatibility)
// ---------------------------------------------------------------------------

func TestShareStore_JSON_ExtraFields(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mcp-shares.json")

	// Write JSON with extra unknown fields (simulates forward compat).
	raw := `{
		"version": 1,
		"grants": [
			{
				"id": "test-id-001",
				"from_agent": "alice",
				"to_agent": "bob",
				"secret_path": "path/to/secret",
				"status": "approved",
				"created_at": "2025-01-01T00:00:00Z",
				"future_field": "should_not_cause_errors",
				"unknown_nested": {"keep": "going"}
			}
		]
	}`
	if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}

	store := NewShareStore(path)
	if err := store.Load(); err != nil {
		t.Fatalf("Load() with extra fields should succeed: %v", err)
	}
	grants := store.List()
	if len(grants) != 1 {
		t.Fatalf("expected 1 grant, got %d", len(grants))
	}
	g := grants[0]
	if g.ID != "test-id-001" {
		t.Errorf("ID = %q, want test-id-001", g.ID)
	}
	if g.Status != ShareApproved {
		t.Errorf("status = %q, want approved", g.Status)
	}
}

// ---------------------------------------------------------------------------
// JSON: multiple sequential save/load cycles
// ---------------------------------------------------------------------------

func TestShareStore_JSON_MultipleCycles(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mcp-shares.json")

	store := NewShareStore(path)

	// Cycle 1.
	g1, _ := store.Create("a", "b", "path1", "", 0)
	store.Approve(g1.ID, "admin")

	// Cycle 2: reload and add another.
	store2 := NewShareStore(path)
	store2.Load()
	g2, _ := store2.Create("c", "d", "path2", "", 5*time.Minute)
	store2.Approve(g2.ID, "admin")

	// Cycle 3: reload and verify both exist.
	store3 := NewShareStore(path)
	store3.Load()
	grants := store3.List()
	if len(grants) != 2 {
		t.Fatalf("expected 2 grants after 3 cycles, got %d", len(grants))
	}

	g1loaded, ok := store3.Get(g1.ID)
	if !ok {
		t.Error("g1 should survive multiple cycles")
	}
	if g1loaded.Status != ShareApproved {
		t.Errorf("g1 status = %q, want approved", g1loaded.Status)
	}

	g2loaded, ok := store3.Get(g2.ID)
	if !ok {
		t.Error("g2 should survive multiple cycles")
	}
	if g2loaded.Status != ShareApproved {
		t.Errorf("g2 status = %q, want approved", g2loaded.Status)
	}
}

// ---------------------------------------------------------------------------
// HMAC grant ID tests
// ---------------------------------------------------------------------------

func testGrantSigningKey() []byte {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	return key
}

func TestShareStore_CreateWithHMAC(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mcp-shares.json")

	store := NewShareStore(path)
	store.SetSigningKey(testGrantSigningKey())

	g, err := store.Create("alice", "bob", "vault/secret/password", "", 0)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	// ID should be in HMAC format (contains ":").
	if !strings.Contains(g.ID, ":") {
		t.Fatalf("grant ID %q should be in HMAC format (nonce:hmac)", g.ID)
	}

	// Nonce should be stored on the grant.
	if g.Nonce == "" {
		t.Error("Nonce should be set on HMAC grants")
	}

	// Should be retrievable by ID.
	got, ok := store.Get(g.ID)
	if !ok {
		t.Fatal("Get() should find HMAC grant by ID")
	}
	if got.ID != g.ID {
		t.Errorf("ID mismatch: %q vs %q", got.ID, g.ID)
	}
}

func TestShareStore_CreateWithHMAC_ApproveAndCheckAccess(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mcp-shares.json")

	store := NewShareStore(path)
	store.SetSigningKey(testGrantSigningKey())

	g, err := store.Create("alice", "bob", "vault/secret/api-key", "", 0)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	if err := store.Approve(g.ID, "admin"); err != nil {
		t.Fatalf("Approve() error = %v", err)
	}

	// CheckAccess should find the HMAC grant.
	grant, ok := store.CheckAccess("bob", "vault/secret/api-key")
	if !ok {
		t.Fatal("CheckAccess should find approved HMAC grant")
	}
	if grant.ID != g.ID {
		t.Errorf("grant ID = %q, want %q", grant.ID, g.ID)
	}
}

func TestShareStore_CheckAccess_RejectsForgedGrant(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mcp-shares.json")

	store := NewShareStore(path)
	store.SetSigningKey(testGrantSigningKey())

	g, err := store.Create("alice", "bob", "vault/secret/api-key", "", 0)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	if err := store.Approve(g.ID, "admin"); err != nil {
		t.Fatalf("Approve() error = %v", err)
	}

	// Manually forge a grant in the store with a different path but same ID.
	store.mu.Lock()
	store.grants[g.ID] = &ShareGrant{
		ID:         g.ID,
		FromAgent:  "alice",
		ToAgent:    "bob",
		SecretPath: "vault/secret/forged-path",
		Status:     ShareApproved,
		CreatedAt:  g.CreatedAt,
		Nonce:      g.Nonce,
	}
	store.mu.Unlock()

	// CheckAccess should NOT find the grant because HMAC won't verify
	// (the secret_path in the stored grant doesn't match the HMAC).
	grant, ok := store.CheckAccess("bob", "vault/secret/forged-path")
	if ok {
		t.Fatal("CheckAccess should reject forged grant with mismatched HMAC")
	}
	if grant != nil {
		t.Fatal("forged grant should return nil")
	}
}

func TestShareStore_CheckAccess_RejectsForgedFromAgent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mcp-shares.json")

	store := NewShareStore(path)
	store.SetSigningKey(testGrantSigningKey())

	// Alice shares a secret with bob.
	g, err := store.Create("alice", "bob", "vault/secret/key", "", 0)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if err := store.Approve(g.ID, "admin"); err != nil {
		t.Fatalf("Approve() error = %v", err)
	}

	// Mallory tries to modify the grant to be from her instead.
	store.mu.Lock()
	store.grants[g.ID].FromAgent = "mallory"
	store.mu.Unlock()

	// bob/forged-path shouldn't match, but let's test the original path.
	_, ok := store.CheckAccess("bob", "vault/secret/key")
	if ok {
		t.Fatal("CheckAccess should reject grant with tampered FromAgent")
	}
}

func TestShareStore_CheckAccess_LegacyUUIDGrantStillWorks(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mcp-shares.json")

	store := NewShareStore(path)
	// Store has a signing key, but we manually inject a legacy UUID grant
	// to test backward compatibility.
	store.SetSigningKey(testGrantSigningKey())

	// Inject a legacy UUID-format grant directly.
	legacyID := "550e8400-e29b-41d4-a716-446655440000"
	store.mu.Lock()
	store.grants[legacyID] = &ShareGrant{
		ID:         legacyID,
		FromAgent:  "alice",
		ToAgent:    "bob",
		SecretPath: "vault/secret/legacy",
		Status:     ShareApproved,
		CreatedAt:  time.Now().UTC(),
	}
	store.mu.Unlock()

	// Legacy UUID grants should still be accessible.
	grant, ok := store.CheckAccess("bob", "vault/secret/legacy")
	if !ok {
		t.Fatal("CheckAccess should find legacy UUID grants")
	}
	if grant.ID != legacyID {
		t.Errorf("grant ID = %q, want %q", grant.ID, legacyID)
	}
}

func TestShareStore_CheckAccess_HybridStore(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mcp-shares.json")

	store := NewShareStore(path)
	store.SetSigningKey(testGrantSigningKey())

	// Create an HMAC grant.
	hmacGrant, err := store.Create("alice", "bob", "vault/secret/hmac-path", "", 0)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if err := store.Approve(hmacGrant.ID, "admin"); err != nil {
		t.Fatalf("Approve() error = %v", err)
	}

	// Inject a legacy UUID grant.
	legacyID := "550e8400-e29b-41d4-a716-446655440001"
	store.mu.Lock()
	store.grants[legacyID] = &ShareGrant{
		ID:         legacyID,
		FromAgent:  "alice",
		ToAgent:    "bob",
		SecretPath: "vault/secret/legacy-path",
		Status:     ShareApproved,
		CreatedAt:  time.Now().UTC(),
	}
	store.mu.Unlock()

	// Both should be accessible.
	hmacResult, ok := store.CheckAccess("bob", "vault/secret/hmac-path")
	if !ok {
		t.Fatal("HMAC grant should be accessible")
	}
	if hmacResult.ID != hmacGrant.ID {
		t.Errorf("HMAC grant ID = %q, want %q", hmacResult.ID, hmacGrant.ID)
	}

	legacyResult, ok := store.CheckAccess("bob", "vault/secret/legacy-path")
	if !ok {
		t.Fatal("Legacy UUID grant should be accessible")
	}
	if legacyResult.ID != legacyID {
		t.Errorf("legacy grant ID = %q, want %q", legacyResult.ID, legacyID)
	}
}

func TestShareStore_HMACGrant_JSONRoundtrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mcp-shares.json")

	store := NewShareStore(path)
	store.SetSigningKey(testGrantSigningKey())

	g, err := store.Create("alice", "bob", "vault/secret/password", "password_field", 30*time.Minute)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if err := store.Approve(g.ID, "admin"); err != nil {
		t.Fatalf("Approve() error = %v", err)
	}

	// Load into a fresh store with the same key.
	store2 := NewShareStore(path)
	store2.SetSigningKey(testGrantSigningKey())
	if err := store2.Load(); err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	// Grant should be retrievable.
	got, ok := store2.Get(g.ID)
	if !ok {
		t.Fatal("Get() after Load() returned false")
	}
	if got.ID != g.ID {
		t.Errorf("ID = %q, want %q", got.ID, g.ID)
	}
	if got.FromAgent != "alice" {
		t.Errorf("FromAgent = %q, want alice", got.FromAgent)
	}
	if got.ToAgent != "bob" {
		t.Errorf("ToAgent = %q, want bob", got.ToAgent)
	}

	// CheckAccess should still work after reload.
	grant, ok := store2.CheckAccess("bob", "vault/secret/password")
	if !ok {
		t.Fatal("CheckAccess should work after JSON roundtrip")
	}
	if grant.ID != g.ID {
		t.Errorf("grant ID = %q, want %q", grant.ID, g.ID)
	}
}

func TestShareStore_HMACGrant_WrongKeyFailsCheckAccess(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mcp-shares.json")

	store := NewShareStore(path)
	store.SetSigningKey(testGrantSigningKey())

	g, err := store.Create("alice", "bob", "vault/secret/key", "", 0)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if err := store.Approve(g.ID, "admin"); err != nil {
		t.Fatalf("Approve() error = %v", err)
	}

	// Create a store with a DIFFERENT key and load the same grants.
	store2 := NewShareStore(path)
	differentKey := make([]byte, 32)
	for i := range differentKey {
		differentKey[i] = byte(255 - i)
	}
	store2.SetSigningKey(differentKey)
	if err := store2.Load(); err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	// CheckAccess should NOT work with a different key.
	_, ok := store2.CheckAccess("bob", "vault/secret/key")
	if ok {
		t.Fatal("CheckAccess should fail when signing key is different")
	}
}

func TestShareStore_HMACGrant_NoKeyFailsCheckAccess(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mcp-shares.json")

	store := NewShareStore(path)
	store.SetSigningKey(testGrantSigningKey())

	g, err := store.Create("alice", "bob", "vault/secret/key", "", 0)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if err := store.Approve(g.ID, "admin"); err != nil {
		t.Fatalf("Approve() error = %v", err)
	}

	// Create a store with NO signing key and load the same grants.
	store2 := NewShareStore(path)
	if err := store2.Load(); err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	// CheckAccess should NOT work because HMAC grants need a key for verification.
	_, ok := store2.CheckAccess("bob", "vault/secret/key")
	if ok {
		t.Fatal("CheckAccess should fail when no signing key is configured")
	}
}

func TestShareStore_NoSigningKey_UsesRandomID(t *testing.T) {
	// Verify that when no signing key is set, grants use random IDs (legacy mode).
	dir := t.TempDir()
	path := filepath.Join(dir, "mcp-shares.json")

	store := NewShareStore(path)

	g, err := store.Create("alice", "bob", "vault/secret/password", "", 0)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	// ID should NOT be in HMAC format when no key is set.
	if strings.Contains(g.ID, ":") {
		t.Fatalf("grant ID %q should NOT be in HMAC format when no key is set", g.ID)
	}

	// ID should be non-empty.
	if g.ID == "" {
		t.Fatal("grant ID must not be empty")
	}

	// Nonce should be empty when no key.
	if g.Nonce != "" {
		t.Error("Nonce should be empty when no signing key")
	}
}

func TestShareStore_InitSigningKey(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mcp-shares.json")

	store := NewShareStore(path)

	// InitSigningKey should work (uses memory fallback in CI).
	key, err := store.InitSigningKey(dir, nil)
	if err != nil {
		t.Fatalf("InitSigningKey() error = %v", err)
	}
	if len(key) != 32 {
		t.Fatalf("key length = %d, want 32", len(key))
	}

	// Now Create should produce HMAC-format IDs.
	g, err := store.Create("alice", "bob", "vault/secret/key", "", 0)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if !openpasscrypto.IsHMACFormat(g.ID) {
		t.Errorf("grant ID %q should be in HMAC format", g.ID)
	}
	if g.Nonce == "" {
		t.Error("Nonce should be set")
	}
}
