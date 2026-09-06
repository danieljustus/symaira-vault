package file

import (
	"encoding/base64"
	"io"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"

	vaultpkg "github.com/danieljustus/symaira-vault/internal/vault"
)

func captureUseStdout(t *testing.T, fn func()) string {
	t.Helper()
	original := os.Stdout
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	os.Stdout = writer
	defer func() { os.Stdout = original }()

	fn()
	if err := writer.Close(); err != nil {
		t.Fatalf("close stdout writer: %v", err)
	}
	output, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("read stdout: %v", err)
	}
	if err := reader.Close(); err != nil {
		t.Fatalf("close stdout reader: %v", err)
	}
	return string(output)
}

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
	output := captureUseStdout(t, func() {
		if err := runFileUse(nil, args); err != nil {
			t.Fatalf("runFileUse: %v", err)
		}
	})
	if strings.Contains(output, string(content)) || !strings.Contains(output, "***") {
		t.Fatalf("stdout = %q, want attachment content redacted", output)
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

func TestAttachmentKnownSecretsIncludesContentAndCanonicalBase64(t *testing.T) {
	content := []byte("binary attachment content")
	got := attachmentKnownSecrets("CERT", content)
	if got["CERT:content"] != string(content) {
		t.Fatal("known secrets omit decoded attachment content")
	}
	if got["CERT:base64"] != base64.StdEncoding.EncodeToString(content) {
		t.Fatal("known secrets omit canonical base64 attachment content")
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
