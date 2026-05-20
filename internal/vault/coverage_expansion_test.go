package vault

import (
	"testing"
)

func TestEntry_RemoveTag(t *testing.T) {
	e := &Entry{}
	e.AddTag("tag1")
	e.AddTag("tag2")
	e.AddTag("tag3")
	e.RemoveTag("tag2")
	if e.HasTag("tag2") {
		t.Error("tag2 should have been removed")
	}
	if !e.HasTag("tag1") || !e.HasTag("tag3") {
		t.Error("other tags should still exist")
	}
}

func TestEntry_HasTag(t *testing.T) {
	e := &Entry{}
	e.AddTag("foo")
	if !e.HasTag("foo") {
		t.Error("HasTag('foo') should be true")
	}
	if e.HasTag("baz") {
		t.Error("HasTag('baz') should be false")
	}
}

func TestEntry_RemoveTag_NotFound(t *testing.T) {
	e := &Entry{}
	e.AddTag("tag1")
	e.AddTag("tag2")
	e.RemoveTag("nonexistent")
	if len(e.Metadata.Tags) != 2 {
		t.Errorf("expected 2 tags unchanged, got %d", len(e.Metadata.Tags))
	}
}

func TestEntry_WithoutCanary(t *testing.T) {
	e := &Entry{Canary: true, Path: "test/entry"}
	cp := e.WithoutCanary()
	if cp == nil {
		t.Fatal("WithoutCanary returned nil")
	}
	if cp.Canary {
		t.Error("WithoutCanary should clear canary flag")
	}
	if !e.Canary {
		t.Error("original entry should preserve canary flag")
	}
}

func TestEntry_WithoutCanary_Nil(t *testing.T) {
	var e *Entry
	if cp := e.WithoutCanary(); cp != nil {
		t.Fatal("WithoutCanary on nil should return nil")
	}
}

func TestEntry_IsCanary(t *testing.T) {
	if !(&Entry{Canary: true}).IsCanary() {
		t.Error("IsCanary should return true for canary entry")
	}
	if (&Entry{Canary: false}).IsCanary() {
		t.Error("IsCanary should return false for non-canary entry")
	}
}

func TestEntry_IsCanary_Nil(t *testing.T) {
	var e *Entry
	if e.IsCanary() {
		t.Error("IsCanary on nil should return false")
	}
}

func TestCanaryPath_Roundtrip(t *testing.T) {
	defer func() {
		canaryPaths.mu.Lock()
		canaryPaths.paths = make(map[string]bool)
		canaryPaths.mu.Unlock()
	}()

	if IsCanaryPath("test/path") {
		t.Fatal("IsCanaryPath should be false before MarkCanaryPath")
	}

	MarkCanaryPath("test/path")
	if !IsCanaryPath("test/path") {
		t.Fatal("IsCanaryPath should be true after MarkCanaryPath")
	}

	UnmarkCanaryPath("test/path")
	if IsCanaryPath("test/path") {
		t.Fatal("IsCanaryPath should be false after UnmarkCanaryPath")
	}
}

func TestDefaultCanaryEntries_NotEmpty(t *testing.T) {
	entries := DefaultCanaryEntries()
	if len(entries) == 0 {
		t.Fatal("DefaultCanaryEntries() returned empty slice")
	}
	for _, e := range entries {
		if e.Path == "" {
			t.Error("canary entry has empty path")
		}
		if len(e.Data) == 0 {
			t.Errorf("canary entry %q has no data", e.Path)
		}
	}
}

func TestSetEntryCanary_NilIdentity(t *testing.T) {
	err := SetEntryCanary(t.TempDir(), "test/path", nil, true)
	if err == nil {
		t.Fatal("SetEntryCanary with nil identity should return error")
	}
}

func TestInvalidateConfigCache(t *testing.T) {
	InvalidateConfigCache(t.TempDir())
}

func TestCurrentSearchIdentity_InitialNil(t *testing.T) {
	id := currentSearchIdentity()
	if id != nil {
		t.Error("currentSearchIdentity() should be nil initially")
	}
}

func TestHasField_Basic(t *testing.T) {
	if !hasField([]string{"name", "path"}, "name") {
		t.Error("hasField should find 'name'")
	}
	if hasField([]string{"name", "path"}, "") {
		t.Error("hasField should not find empty string")
	}
}
