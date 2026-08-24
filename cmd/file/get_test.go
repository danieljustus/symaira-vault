package file

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"

	cli "github.com/danieljustus/symaira-vault/internal/cli"
	vaultpkg "github.com/danieljustus/symaira-vault/internal/vault"
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

func writeChunkedTestEntry(t *testing.T, path, field string, data map[string]any, info *vaultpkg.AttachmentInfo) {
	t.Helper()
	err := cli.WithVaultRaw(func(_ *vaultpkg.Vault, vs *cli.VaultService) error {
		entry := &vaultpkg.Entry{
			Path: path,
			Data: data,
		}
		if info != nil {
			entry.SecretMetadata.Attachments = map[string]vaultpkg.AttachmentInfo{
				field: *info,
			}
		}
		return vs.WriteEntry(path, entry)
	})
	if err != nil {
		t.Fatalf("write chunked test entry %q: %v", path, err)
	}
}

func TestRunFileGet_ChunkedV1_Success(t *testing.T) {
	setupTestVault(t)
	content := []byte("known-binary-content-for-chunked-v1-test-1234567890")
	fullB64 := base64.StdEncoding.EncodeToString(content)
	splitIdx := len(fullB64) / 2
	chunk0 := fullB64[:splitIdx]
	chunk1 := fullB64[splitIdx:]

	path := "apple-developer/certificate-p12"
	field := "cert_p12"
	data := map[string]any{
		field:               "chunked-v1:cert_p12_b64_0000,cert_p12_b64_0001",
		"cert_p12_b64_0000": chunk0,
		"cert_p12_b64_0001": chunk1,
	}
	info := &vaultpkg.AttachmentInfo{
		Filename: "certificate.p12",
		Size:     int64(len(content)),
		SHA256:   vaultpkg.HashAttachmentSHA256(content),
	}
	writeChunkedTestEntry(t, path, field, data, info)

	resetGetFlags(t)
	outPath := filepath.Join(t.TempDir(), "out.p12")
	GetField = ""
	GetOut = outPath

	if err := runFileGet(nil, []string{path + "#" + field}); err != nil {
		t.Fatalf("runFileGet on chunked entry: %v", err)
	}

	got, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read exported file: %v", err)
	}
	if string(got) != string(content) {
		t.Errorf("got %q, want %q", got, content)
	}
}

func TestRunFileGet_ChunkedV1_MissingChunk(t *testing.T) {
	setupTestVault(t)
	path := "apple-developer/missing-chunk"
	field := "cert_p12"
	data := map[string]any{
		field:               "chunked-v1:cert_p12_b64_0000,cert_p12_b64_0001",
		"cert_p12_b64_0000": "c29tZS1kYXRh",
		// cert_p12_b64_0001 is missing
	}
	writeChunkedTestEntry(t, path, field, data, nil)

	resetGetFlags(t)
	GetOut = filepath.Join(t.TempDir(), "out.p12")

	if err := runFileGet(nil, []string{path + "#" + field}); err == nil {
		t.Fatal("expected error for missing chunk field, got nil")
	}
}

func TestRunFileGet_ChunkedV1_ChunkCountMismatch(t *testing.T) {
	setupTestVault(t)
	path := "apple-developer/count-mismatch"
	field := "cert_p12"
	data := map[string]any{
		field:               "chunked-v1:cert_p12_b64_0000,cert_p12_b64_0001",
		"cert_p12_b64_0000": "c29tZS1kYXRh",
		"cert_p12_b64_0001": "bW9yZS1kYXRh",
		"chunk_count":       3, // Mismatch: manifest has 2, entry specifies 3
	}
	writeChunkedTestEntry(t, path, field, data, nil)

	resetGetFlags(t)
	GetOut = filepath.Join(t.TempDir(), "out.p12")

	if err := runFileGet(nil, []string{path + "#" + field}); err == nil {
		t.Fatal("expected error for chunk count mismatch, got nil")
	}
}

func TestRunFileGet_ChunkedV1_InvalidBase64Chunk(t *testing.T) {
	setupTestVault(t)
	path := "apple-developer/invalid-b64"
	field := "cert_p12"
	data := map[string]any{
		field:               "chunked-v1:cert_p12_b64_0000",
		"cert_p12_b64_0000": "not-valid-base64!@#$",
	}
	writeChunkedTestEntry(t, path, field, data, nil)

	resetGetFlags(t)
	GetOut = filepath.Join(t.TempDir(), "out.p12")

	if err := runFileGet(nil, []string{path + "#" + field}); err == nil {
		t.Fatal("expected error for invalid base64 in chunk, got nil")
	}
}
