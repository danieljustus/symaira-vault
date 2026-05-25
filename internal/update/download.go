// Package update provides functionality for checking, downloading, and
// applying Symaira Vault updates.
package update

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

var (
	// DefaultDownloadBaseURL is the base URL for GitHub release downloads.
	DefaultDownloadBaseURL = "https://github.com/danieljustus/symaira-vault/releases/download"

	// testHTTPClient is used by tests to inject a mock HTTP client, bypassing
	// the default clients created by newDownloadClient and newSecureClient.
	testHTTPClient httpDoer
	mu             sync.Mutex
)

const (
	downloadTimeout = 60 * time.Second
	windowsOS       = "windows"
)

// archiveName returns the release archive filename for the given version, OS,
// and architecture. Matches the GoReleaser name_template convention.
func archiveName(version, os, arch string) string {
	v := strings.TrimPrefix(version, "v")
	ext := "tar.gz"
	if os == windowsOS {
		ext = "zip"
	}
	return fmt.Sprintf("symvault_%s_%s_%s.%s", v, os, arch, ext)
}

// checksumsFileName returns the checksums filename for the given version.
func checksumsFileName(version string) string {
	v := strings.TrimPrefix(version, "v")
	return fmt.Sprintf("symvault_%s_checksums.txt", v)
}

// newDownloadClient returns an HTTP client with TLS 1.3 minimum and a longer
// timeout suitable for downloading release archives.
func newDownloadClient() *http.Client {
	return &http.Client{
		Timeout: downloadTimeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				MinVersion: tls.VersionTLS13,
			},
		},
	}
}

// downloadClient returns a test-injected client if set, otherwise falls back
// to newDownloadClient.
func downloadClient() httpDoer {
	mu.Lock()
	defer mu.Unlock()
	if testHTTPClient != nil {
		return testHTTPClient
	}
	return newDownloadClient()
}

// checksumsClient returns a test-injected client if set, otherwise falls back
// to newSecureClient (shorter timeout for small checksum files).
func checksumsClient() httpDoer {
	mu.Lock()
	defer mu.Unlock()
	if testHTTPClient != nil {
		return testHTTPClient
	}
	return newSecureClient()
}

// DownloadArchive downloads a release archive from GitHub for the given
// version, operating system, and architecture. It enforces HTTPS and uses a
// secure TLS 1.3-only client with a 60-second timeout.
func DownloadArchive(ctx context.Context, version, os, arch string) ([]byte, error) {
	v := strings.TrimPrefix(version, "v")
	if v == "" {
		return nil, fmt.Errorf("version must not be empty")
	}

	name := archiveName(version, os, arch)
	u := fmt.Sprintf("%s/v%s/%s", DefaultDownloadBaseURL, v, name)

	parsed, err := url.Parse(u)
	if err != nil {
		return nil, fmt.Errorf("invalid download URL: %w", err)
	}
	if parsed.Scheme != "https" {
		return nil, fmt.Errorf("download URL must use HTTPS, got %q", parsed.Scheme)
	}

	client := downloadClient()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, fmt.Errorf("create download request: %w", err)
	}

	resp, err := client.Do(req) // #nosec G107 — URL is constructed from controlled inputs
	if err != nil {
		return nil, fmt.Errorf("download archive: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("download archive: HTTP %d", resp.StatusCode)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read archive response: %w", err)
	}

	return data, nil
}

// FetchChecksums downloads the SHA256 checksums file for the given release
// version. The content is returned as a string for use with VerifyChecksum.
func FetchChecksums(ctx context.Context, version string) (string, error) {
	v := strings.TrimPrefix(version, "v")
	if v == "" {
		return "", fmt.Errorf("version must not be empty")
	}

	name := checksumsFileName(version)
	u := fmt.Sprintf("%s/v%s/%s", DefaultDownloadBaseURL, v, name)

	parsed, err := url.Parse(u)
	if err != nil {
		return "", fmt.Errorf("invalid checksums URL: %w", err)
	}
	if parsed.Scheme != "https" {
		return "", fmt.Errorf("checksums URL must use HTTPS, got %q", parsed.Scheme)
	}

	client := checksumsClient()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return "", fmt.Errorf("create checksums request: %w", err)
	}

	resp, err := client.Do(req) // #nosec G107 — URL is constructed from controlled inputs
	if err != nil {
		return "", fmt.Errorf("fetch checksums: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("fetch checksums: HTTP %d", resp.StatusCode)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("read checksums response: %w", err)
	}

	return string(data), nil
}

// VerifyChecksum verifies that archiveData matches the SHA256 checksum
// listed in checksumsContent for the given archiveName. The checksumsContent
// is expected to follow the GoReleaser format: one "<sha256>  <filename>"
// entry per line.
func VerifyChecksum(archiveData []byte, checksumsContent, archiveName string) error {
	lines := strings.Split(strings.TrimSpace(checksumsContent), "\n")

	var expectedHash string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}

		if parts[1] == archiveName {
			expectedHash = parts[0]
			break
		}
	}

	if expectedHash == "" {
		return fmt.Errorf("checksum for %q not found in checksums file", archiveName)
	}

	hash := sha256.Sum256(archiveData)
	actualHash := hex.EncodeToString(hash[:])

	if !strings.EqualFold(actualHash, expectedHash) {
		return fmt.Errorf(
			"checksum mismatch for %q: expected %s, got %s",
			archiveName, expectedHash, actualHash,
		)
	}

	return nil
}
