package file

import (
	"os"
	"path/filepath"
	"testing"
)

func resetGetFlags(t *testing.T) {
	t.Helper()
	origField, origOut := GetField, GetOut
	t.Cleanup(func() {
		GetField, GetOut = origField, origOut
	})
}

// addFixtureAttachment stores content under elster/cert#cert_p12 using
// runFileAdd, so get/use tests exercise the real round trip instead of
// hand-building entries.
func addFixtureAttachment(t *testing.T, content []byte) {
	t.Helper()
	resetAddFlags(t)

	srcPath := filepath.Join(t.TempDir(), "fixture.bin")
	if err := os.WriteFile(srcPath, content, 0o600); err != nil {
		t.Fatalf("write fixture source: %v", err)
	}

	AddField = "cert_p12"
	AddFrom = srcPath
	AddMaxSize = DefaultMaxAttachmentSize
	AddShred = false

	if err := runFileAdd(nil, []string{"elster/cert"}); err != nil {
		t.Fatalf("seed fixture via runFileAdd: %v", err)
	}
}

func TestRunFileGet_ExportsStoredAttachment(t *testing.T) {
	setupTestVault(t)
	content := []byte("elster-cert-bytes")
	addFixtureAttachment(t, content)

	resetGetFlags(t)
	outPath := filepath.Join(t.TempDir(), "exported.pfx")
	GetField = ""
	GetOut = outPath

	if err := runFileGet(nil, []string{"elster/cert#cert_p12"}); err != nil {
		t.Fatalf("runFileGet: %v", err)
	}

	got, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read exported file: %v", err)
	}
	if string(got) != string(content) {
		t.Errorf("exported content = %q, want %q", got, content)
	}
}

func TestRunFileGet_AutoDetectsSingleAttachment(t *testing.T) {
	setupTestVault(t)
	content := []byte("only-attachment")
	addFixtureAttachment(t, content)

	resetGetFlags(t)
	outPath := filepath.Join(t.TempDir(), "exported.pfx")
	GetField = ""
	GetOut = outPath

	// No "#field" suffix and no --field: must auto-select the sole attachment.
	if err := runFileGet(nil, []string{"elster/cert"}); err != nil {
		t.Fatalf("runFileGet: %v", err)
	}

	got, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read exported file: %v", err)
	}
	if string(got) != string(content) {
		t.Errorf("exported content = %q, want %q", got, content)
	}
}

func TestRunFileGet_MissingOutFlag(t *testing.T) {
	setupTestVault(t)
	addFixtureAttachment(t, []byte("data"))

	resetGetFlags(t)
	GetOut = ""

	if err := runFileGet(nil, []string{"elster/cert#cert_p12"}); err == nil {
		t.Fatal("expected error for missing --out, got nil")
	}
}

func TestRunFileGet_FieldNotFound(t *testing.T) {
	setupTestVault(t)
	addFixtureAttachment(t, []byte("data"))

	resetGetFlags(t)
	GetOut = filepath.Join(t.TempDir(), "out.bin")

	if err := runFileGet(nil, []string{"elster/cert#nonexistent"}); err == nil {
		t.Fatal("expected error for nonexistent field, got nil")
	}
}

func TestRunFileGet_EntryNotFound(t *testing.T) {
	setupTestVault(t)

	resetGetFlags(t)
	GetOut = filepath.Join(t.TempDir(), "out.bin")

	if err := runFileGet(nil, []string{"does/not-exist#field"}); err == nil {
		t.Fatal("expected error for missing entry, got nil")
	}
}
