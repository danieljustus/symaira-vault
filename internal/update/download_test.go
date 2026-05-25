package update

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestArchiveName(t *testing.T) {
	tests := []struct {
		version  string
		os       string
		arch     string
		expected string
	}{
		{"0.5.0", "darwin", "arm64", "symvault_0.5.0_darwin_arm64.tar.gz"},
		{"v1.2.0", "linux", "amd64", "symvault_1.2.0_linux_amd64.tar.gz"},
		{"2.0.0", "windows", "amd64", "symvault_2.0.0_windows_amd64.zip"},
		{"v0.1.0", "freebsd", "arm64", "symvault_0.1.0_freebsd_arm64.tar.gz"},
		{"v0.5.0", "windows", "arm64", "symvault_0.5.0_windows_arm64.zip"},
	}
	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			got := archiveName(tt.version, tt.os, tt.arch)
			if got != tt.expected {
				t.Fatalf("archiveName(%q, %q, %q) = %q, want %q",
					tt.version, tt.os, tt.arch, got, tt.expected)
			}
		})
	}
}

func TestChecksumsFileName(t *testing.T) {
	tests := []struct {
		version  string
		expected string
	}{
		{"0.5.0", "symvault_0.5.0_checksums.txt"},
		{"v1.2.0", "symvault_1.2.0_checksums.txt"},
	}
	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			got := checksumsFileName(tt.version)
			if got != tt.expected {
				t.Fatalf("checksumsFileName(%q) = %q, want %q",
					tt.version, got, tt.expected)
			}
		})
	}
}

func TestDownloadArchive_Success(t *testing.T) {
	expectedBody := []byte("fake-archive-content")
	mu.Lock()
	testHTTPClient = stubHTTPDoer{
		do: func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader(string(expectedBody))),
				Header:     make(http.Header),
			}, nil
		},
	}
	mu.Unlock()
	t.Cleanup(func() {
		mu.Lock()
		testHTTPClient = nil
		mu.Unlock()
	})

	data, err := DownloadArchive(context.Background(), "0.5.0", "darwin", "arm64")
	if err != nil {
		t.Fatalf("DownloadArchive() error = %v", err)
	}
	if string(data) != string(expectedBody) {
		t.Fatalf("got body %q, want %q", string(data), string(expectedBody))
	}
}

func TestDownloadArchive_HTTPError(t *testing.T) {
	mu.Lock()
	testHTTPClient = stubHTTPDoer{
		do: func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusNotFound,
				Body:       io.NopCloser(strings.NewReader("not found")),
				Header:     make(http.Header),
			}, nil
		},
	}
	mu.Unlock()
	t.Cleanup(func() {
		mu.Lock()
		testHTTPClient = nil
		mu.Unlock()
	})

	_, err := DownloadArchive(context.Background(), "0.5.0", "darwin", "arm64")
	if err == nil {
		t.Fatal("expected HTTP error")
	}
	if !strings.Contains(err.Error(), "HTTP 404") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDownloadArchive_EmptyVersion(t *testing.T) {
	_, err := DownloadArchive(context.Background(), "", "darwin", "arm64")
	if err == nil {
		t.Fatal("expected empty version error")
	}
	if !strings.Contains(err.Error(), "version must not be empty") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDownloadArchive_URLScheme(t *testing.T) {
	origURL := DefaultDownloadBaseURL
	DefaultDownloadBaseURL = "http://example.com/fake"
	t.Cleanup(func() { DefaultDownloadBaseURL = origURL })

	_, err := DownloadArchive(context.Background(), "0.5.0", "darwin", "arm64")
	if err == nil {
		t.Fatal("expected HTTPS enforcement error")
	}
	if !strings.Contains(err.Error(), "must use HTTPS") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDownloadArchive_NetworkError(t *testing.T) {
	mu.Lock()
	testHTTPClient = stubHTTPDoer{
		do: func(req *http.Request) (*http.Response, error) {
			return nil, fmt.Errorf("connection refused")
		},
	}
	mu.Unlock()
	t.Cleanup(func() {
		mu.Lock()
		testHTTPClient = nil
		mu.Unlock()
	})

	_, err := DownloadArchive(context.Background(), "0.5.0", "darwin", "arm64")
	if err == nil {
		t.Fatal("expected network error")
	}
	if !strings.Contains(err.Error(), "download archive") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestFetchChecksums_Success(t *testing.T) {
	checksumsBody := "sha256hash  symvault_0.5.0_darwin_arm64.tar.gz\n"
	mu.Lock()
	testHTTPClient = stubHTTPDoer{
		do: func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader(checksumsBody)),
				Header:     make(http.Header),
			}, nil
		},
	}
	mu.Unlock()
	t.Cleanup(func() {
		mu.Lock()
		testHTTPClient = nil
		mu.Unlock()
	})

	content, err := FetchChecksums(context.Background(), "0.5.0")
	if err != nil {
		t.Fatalf("FetchChecksums() error = %v", err)
	}
	if content != checksumsBody {
		t.Fatalf("got body %q, want %q", content, checksumsBody)
	}
}

func TestFetchChecksums_HTTPError(t *testing.T) {
	mu.Lock()
	testHTTPClient = stubHTTPDoer{
		do: func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusForbidden,
				Body:       io.NopCloser(strings.NewReader("forbidden")),
				Header:     make(http.Header),
			}, nil
		},
	}
	mu.Unlock()
	t.Cleanup(func() {
		mu.Lock()
		testHTTPClient = nil
		mu.Unlock()
	})

	_, err := FetchChecksums(context.Background(), "0.5.0")
	if err == nil {
		t.Fatal("expected HTTP error")
	}
	if !strings.Contains(err.Error(), "HTTP 403") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestFetchChecksums_EmptyVersion(t *testing.T) {
	_, err := FetchChecksums(context.Background(), "")
	if err == nil {
		t.Fatal("expected empty version error")
	}
	if !strings.Contains(err.Error(), "version must not be empty") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestFetchChecksums_URLScheme(t *testing.T) {
	origURL := DefaultDownloadBaseURL
	DefaultDownloadBaseURL = "http://example.com/fake"
	t.Cleanup(func() { DefaultDownloadBaseURL = origURL })

	_, err := FetchChecksums(context.Background(), "0.5.0")
	if err == nil {
		t.Fatal("expected HTTPS enforcement error")
	}
	if !strings.Contains(err.Error(), "must use HTTPS") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestVerifyChecksum_Success(t *testing.T) {
	data := []byte("test-archive-content")
	hash := sha256.Sum256(data)
	hashStr := hex.EncodeToString(hash[:])
	archiveName := "symvault_0.5.0_darwin_arm64.tar.gz"
	checksums := fmt.Sprintf("%s  %s\n", hashStr, archiveName)

	if err := VerifyChecksum(data, checksums, archiveName); err != nil {
		t.Fatalf("VerifyChecksum() error = %v", err)
	}
}

func TestVerifyChecksum_Mismatch(t *testing.T) {
	data := []byte("test-archive-content")
	checksums := "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef  symvault_0.5.0_darwin_arm64.tar.gz\n"
	archiveName := "symvault_0.5.0_darwin_arm64.tar.gz"

	err := VerifyChecksum(data, checksums, archiveName)
	if err == nil {
		t.Fatal("expected checksum mismatch error")
	}
	if !strings.Contains(err.Error(), "checksum mismatch") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestVerifyChecksum_NotFound(t *testing.T) {
	data := []byte("test-archive-content")
	checksums := "deadbeef  SomeOtherFile.tar.gz\n"
	archiveName := "symvault_0.5.0_darwin_arm64.tar.gz"

	err := VerifyChecksum(data, checksums, archiveName)
	if err == nil {
		t.Fatal("expected checksum not found error")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestVerifyChecksum_CaseInsensitive(t *testing.T) {
	data := []byte("test-archive-content")
	hash := sha256.Sum256(data)
	hashStr := strings.ToUpper(hex.EncodeToString(hash[:]))
	archiveName := "symvault_0.5.0_darwin_arm64.tar.gz"
	checksums := fmt.Sprintf("%s  %s\n", hashStr, archiveName)

	if err := VerifyChecksum(data, checksums, archiveName); err != nil {
		t.Fatalf("VerifyChecksum() with uppercase hash error = %v", err)
	}
}

func TestVerifyChecksum_IgnoresExtraLines(t *testing.T) {
	data := []byte("test-archive-content")
	hash := sha256.Sum256(data)
	hashStr := hex.EncodeToString(hash[:])
	archiveName := "symvault_0.5.0_darwin_arm64.tar.gz"
	checksums := fmt.Sprintf("aaaa  other1.tar.gz\n%s  %s\nbbbb  other2.tar.gz\n", hashStr, archiveName)

	if err := VerifyChecksum(data, checksums, archiveName); err != nil {
		t.Fatalf("VerifyChecksum() with extra lines error = %v", err)
	}
}

func TestVerifyChecksum_EmptyContent(t *testing.T) {
	err := VerifyChecksum([]byte("data"), "", "archive.tar.gz")
	if err == nil {
		t.Fatal("expected error with empty checksums content")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Fatalf("unexpected error: %v", err)
	}
}
