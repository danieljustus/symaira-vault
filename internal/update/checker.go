package update

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/danieljustus/symaira-vault/internal/metrics"
)

const DefaultLatestReleaseURL = "https://api.github.com/repos/danieljustus/Symaira Vault/releases/latest"

// newSecureClient returns an HTTP client with TLS 1.3 minimum version.
func newSecureClient() *http.Client {
	return &http.Client{
		Timeout: 3 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				MinVersion: tls.VersionTLS13,
			},
		},
	}
}

type httpDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

type Checker struct {
	HTTPClient       httpDoer
	LatestReleaseURL string
	Cache            *Cache
}

type Result struct {
	CurrentVersion  string
	LatestVersion   string
	ReleaseURL      string
	Checkable       bool
	UpdateAvailable bool
}

type latestReleaseResponse struct {
	Draft      bool   `json:"draft"`
	HTMLURL    string `json:"html_url"`
	Prerelease bool   `json:"prerelease"`
	TagName    string `json:"tag_name"`
}

type stableVersion struct {
	major int
	minor int
	patch int
}

func NewChecker(client httpDoer) *Checker {
	if client == nil {
		client = newSecureClient()
	}

	return &Checker{
		HTTPClient:       client,
		LatestReleaseURL: DefaultLatestReleaseURL,
		Cache:            NewCache(),
	}
}

func (c *Checker) Check(ctx context.Context, currentVersion string) (*Result, error) {
	return c.CheckWithForce(ctx, currentVersion, false)
}

func (c *Checker) CheckWithForce(ctx context.Context, currentVersion string, force bool) (*Result, error) {
	current, ok := parseStableVersion(currentVersion)
	if !ok {
		return &Result{CurrentVersion: strings.TrimSpace(currentVersion)}, nil
	}

	if !force && c.Cache != nil {
		if entry, err := c.Cache.Load(); err == nil && entry != nil {
			latest, cacheOk := parseStableVersion(entry.LatestVersion)
			if cacheOk {
				result := &Result{
					CurrentVersion:  current.String(),
					LatestVersion:   latest.String(),
					ReleaseURL:      entry.ReleaseURL,
					Checkable:       true,
					UpdateAvailable: compareStableVersions(current, latest) < 0,
				}
				if result.UpdateAvailable {
					metrics.RecordUpdateCheck("update_available")
				} else {
					metrics.RecordUpdateCheck("up_to_date")
				}
				metrics.RecordUpdateCheck("cache_hit")
				return result, nil
			}
		}
	}

	release, err := c.fetchLatestRelease(ctx, currentVersion)
	if err != nil {
		metrics.RecordUpdateCheck("error")
		return nil, err
	}

	latest, ok := parseStableVersion(release.TagName)
	if !ok {
		metrics.RecordUpdateCheck("error")
		return nil, fmt.Errorf("latest release tag %q is not a stable semantic version", release.TagName)
	}

	result := &Result{
		CurrentVersion:  current.String(),
		LatestVersion:   latest.String(),
		ReleaseURL:      strings.TrimSpace(release.HTMLURL),
		Checkable:       true,
		UpdateAvailable: compareStableVersions(current, latest) < 0,
	}

	if c.Cache != nil {
		_ = c.Cache.Save(&CacheEntry{
			Timestamp:     time.Now(),
			LatestVersion: result.LatestVersion,
			ReleaseURL:    result.ReleaseURL,
		})
	}

	if result.UpdateAvailable {
		metrics.RecordUpdateCheck("update_available")
	} else {
		metrics.RecordUpdateCheck("up_to_date")
	}

	return result, nil
}

func (c *Checker) fetchLatestRelease(ctx context.Context, currentVersion string) (*latestReleaseResponse, error) {
	url := strings.TrimSpace(c.LatestReleaseURL)
	if url == "" {
		url = DefaultLatestReleaseURL
	}

	client := c.HTTPClient
	if client == nil {
		client = newSecureClient()
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("create latest release request: %w", err)
	}

	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", fmt.Sprintf("symaira/%s", strings.TrimSpace(currentVersion)))

	resp, err := client.Do(req) // #nosec G107 — URL is validated and points to GitHub API
	if err != nil {
		if isTLSCertificateError(err) {
			return nil, fmt.Errorf("update check failed: TLS certificate verification error - %w", err)
		}
		return nil, fmt.Errorf("request latest release: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode == http.StatusForbidden && resp.Header.Get("X-RateLimit-Remaining") == "0" {
			return nil, fmt.Errorf("GitHub API rate limit exceeded")
		}
		return nil, fmt.Errorf("GitHub API returned HTTP %d", resp.StatusCode)
	}

	var release latestReleaseResponse
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return nil, fmt.Errorf("decode latest release response: %w", err)
	}

	if release.Draft {
		return nil, fmt.Errorf("latest release response returned a draft release")
	}
	if release.Prerelease {
		return nil, fmt.Errorf("latest release response returned a prerelease")
	}
	if strings.TrimSpace(release.TagName) == "" {
		return nil, fmt.Errorf("latest release response did not include a tag name")
	}

	return &release, nil
}

// isTLSCertificateError reports whether an error is caused by a TLS
// certificate verification failure.
func isTLSCertificateError(err error) bool {
	var certErr *x509.CertificateInvalidError
	if errors.As(err, &certErr) {
		return true
	}
	var hostnameErr x509.HostnameError
	if errors.As(err, &hostnameErr) {
		return true
	}
	var unknownAuthorityErr x509.UnknownAuthorityError
	return errors.As(err, &unknownAuthorityErr)
}

func parseStableVersion(raw string) (stableVersion, bool) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return stableVersion{}, false
	}

	trimmed = strings.TrimPrefix(trimmed, "v")
	if strings.ContainsAny(trimmed, "-+") {
		return stableVersion{}, false
	}

	parts := strings.Split(trimmed, ".")
	if len(parts) != 3 {
		return stableVersion{}, false
	}

	values := make([]int, 0, len(parts))
	for _, part := range parts {
		if part == "" {
			return stableVersion{}, false
		}
		value, err := strconv.Atoi(part)
		if err != nil || value < 0 {
			return stableVersion{}, false
		}
		values = append(values, value)
	}

	return stableVersion{major: values[0], minor: values[1], patch: values[2]}, true
}

func compareStableVersions(left, right stableVersion) int {
	switch {
	case left.major != right.major:
		if left.major < right.major {
			return -1
		}
	case left.minor != right.minor:
		if left.minor < right.minor {
			return -1
		}
	case left.patch != right.patch:
		if left.patch < right.patch {
			return -1
		}
	default:
		return 0
	}

	return 1
}

func (v stableVersion) String() string {
	return fmt.Sprintf("%d.%d.%d", v.major, v.minor, v.patch)
}
