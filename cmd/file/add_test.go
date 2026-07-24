package file

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"

	vaultpkg "github.com/danieljustus/symaira-vault/internal/vault"
)

func resetAddFlags(t *testing.T) {
	t.Helper()
	origField, origFrom, origType, origMaxSize, origShred := AddField, AddFrom, AddType, AddMaxSize, AddShred
	t.Cleanup(func() {
		AddField, AddFrom, AddType, AddMaxSize, AddShred = origField, origFrom, origType, origMaxSize, origShred
	})
}

func TestRunFileAdd_StoresAttachmentWithMetadata(t *testing.T) {
	setupTestVault(t)
	resetAddFlags(t)

	srcPath := filepath.Join(t.TempDir(), "cert.pfx")
	content := []byte("fake-certificate-bytes")
	if err := os.WriteFile(srcPath, content, 0o600); err != nil {
		t.Fatalf("write source file: %v", err)
	}

	AddField = "cert_p12"
	AddFrom = srcPath
	AddType = string(vaultpkg.SecretTypeCertificate)
	AddMaxSize = DefaultMaxAttachmentSize
	AddShred = false

	if err := runFileAdd(nil, []string{"elster/cert"}); err != nil {
		t.Fatalf("runFileAdd: %v", err)
	}

	entry := getTestEntry(t, "elster/cert")
	encoded, ok := entry.Data["cert_p12"].(string)
	if !ok {
		t.Fatalf("entry.Data[cert_p12] = %v (%T), want string", entry.Data["cert_p12"], entry.Data["cert_p12"])
	}
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("decode stored content: %v", err)
	}
	if string(decoded) != string(content) {
		t.Errorf("stored content = %q, want %q", decoded, content)
	}

	attachment, ok := entry.SecretMetadata.Attachments["cert_p12"]
	if !ok {
		t.Fatal("expected attachment metadata for cert_p12")
	}
	if attachment.Filename != "cert.pfx" {
		t.Errorf("attachment.Filename = %q, want %q", attachment.Filename, "cert.pfx")
	}
	if attachment.Size != int64(len(content)) {
		t.Errorf("attachment.Size = %d, want %d", attachment.Size, len(content))
	}
	wantSHA := vaultpkg.HashAttachmentSHA256(content)
	if attachment.SHA256 != wantSHA {
		t.Errorf("attachment.SHA256 = %q, want %q", attachment.SHA256, wantSHA)
	}
	if entry.SecretMetadata.Type != vaultpkg.SecretTypeCertificate {
		t.Errorf("entry type = %q, want %q", entry.SecretMetadata.Type, vaultpkg.SecretTypeCertificate)
	}
}

func TestRunFileAdd_MissingFieldFlag(t *testing.T) {
	setupTestVault(t)
	resetAddFlags(t)

	AddField = ""
	AddFrom = filepath.Join(t.TempDir(), "unused")

	if err := runFileAdd(nil, []string{"elster/cert"}); err == nil {
		t.Fatal("expected error for missing --field, got nil")
	}
}

func TestRunFileAdd_MissingFromFlag(t *testing.T) {
	setupTestVault(t)
	resetAddFlags(t)

	AddField = "cert_p12"
	AddFrom = ""

	if err := runFileAdd(nil, []string{"elster/cert"}); err == nil {
		t.Fatal("expected error for missing --from, got nil")
	}
}

func TestRunFileAdd_SourceExceedsMaxSize(t *testing.T) {
	setupTestVault(t)
	resetAddFlags(t)

	srcPath := filepath.Join(t.TempDir(), "big.bin")
	if err := os.WriteFile(srcPath, []byte("0123456789"), 0o600); err != nil {
		t.Fatalf("write source file: %v", err)
	}

	AddField = "cert_p12"
	AddFrom = srcPath
	AddMaxSize = 5 // smaller than the 10-byte source file

	if err := runFileAdd(nil, []string{"elster/cert"}); err == nil {
		t.Fatal("expected error for oversized source file, got nil")
	}
}

func TestRunFileAdd_SourceFileMissing(t *testing.T) {
	setupTestVault(t)
	resetAddFlags(t)

	AddField = "cert_p12"
	AddFrom = filepath.Join(t.TempDir(), "does-not-exist.pfx")
	AddMaxSize = DefaultMaxAttachmentSize

	if err := runFileAdd(nil, []string{"elster/cert"}); err == nil {
		t.Fatal("expected error for missing source file, got nil")
	}
}
