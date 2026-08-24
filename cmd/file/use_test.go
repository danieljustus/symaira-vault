package file

import (
	"encoding/base64"
	"runtime"
	"strings"
	"testing"
	"time"

	vaultpkg "github.com/danieljustus/symaira-vault/internal/vault"
)

func resetUseFlags(t *testing.T) {
	t.Helper()
	origField, origAs, origTimeout := UseField, UseAs, UseTimeout
	t.Cleanup(func() {
		UseField, UseAs, UseTimeout = origField, origAs, origTimeout
	})
}

func TestRunFileUse_MaterializesAttachmentForCommand(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on windows: relies on a POSIX shell")
	}
	setupTestVault(t)
	content := []byte("elster-cert-bytes")
	addFixtureAttachment(t, content)

	resetUseFlags(t)
	UseField = ""
	UseAs = ""
	UseTimeout = 5 * time.Second

	args := []string{"elster/cert#cert_p12", "sh", "-c", `cat "$SYMVAULT_FILE_CERT_P12"`}
	if err := runFileUse(nil, args); err != nil {
		t.Fatalf("runFileUse: %v", err)
	}
}

func TestRunFileUse_CustomExposedName(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on windows: relies on a POSIX shell")
	}
	setupTestVault(t)
	addFixtureAttachment(t, []byte("data"))

	resetUseFlags(t)
	UseField = ""
	UseAs = "MYCERT"
	UseTimeout = 5 * time.Second

	args := []string{"elster/cert#cert_p12", "sh", "-c", `test -n "$SYMVAULT_FILE_MYCERT"`}
	if err := runFileUse(nil, args); err != nil {
		t.Fatalf("runFileUse with custom --as name: %v", err)
	}
}

func TestRunFileUse_NonZeroExitPropagates(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on windows: relies on a POSIX shell")
	}
	setupTestVault(t)
	addFixtureAttachment(t, []byte("data"))

	resetUseFlags(t)
	UseField = ""
	UseTimeout = 5 * time.Second

	args := []string{"elster/cert#cert_p12", "sh", "-c", "exit 7"}
	err := runFileUse(nil, args)
	if err == nil {
		t.Fatal("expected error for non-zero command exit, got nil")
	}
	if !strings.Contains(err.Error(), "7") {
		t.Errorf("error %q does not mention the exit code", err.Error())
	}
}

func TestRunFileUse_FieldNotFound(t *testing.T) {
	setupTestVault(t)
	addFixtureAttachment(t, []byte("data"))

	resetUseFlags(t)
	UseField = ""

	args := []string{"elster/cert#missing", "true"}
	if err := runFileUse(nil, args); err == nil {
		t.Fatal("expected error for nonexistent field, got nil")
	}
}

func TestRunFileUse_EntryNotFound(t *testing.T) {
	setupTestVault(t)

	resetUseFlags(t)
	UseField = ""

	args := []string{"does/not-exist#field", "true"}
	if err := runFileUse(nil, args); err == nil {
		t.Fatal("expected error for missing entry, got nil")
	}
}

func TestRunFileUse_ChunkedV1(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on windows: relies on a POSIX shell")
	}
	setupTestVault(t)
	content := []byte("chunked-v1-test-bytes-for-use")
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

	resetUseFlags(t)
	UseField = ""
	UseAs = ""
	UseTimeout = 5 * time.Second

	args := []string{path + "#" + field, "sh", "-c", `test "$(cat "$SYMVAULT_FILE_CERT_P12")" = "chunked-v1-test-bytes-for-use"`}
	if err := runFileUse(nil, args); err != nil {
		t.Fatalf("runFileUse with chunked attachment: %v", err)
	}
}
