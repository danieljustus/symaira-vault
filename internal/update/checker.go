package update

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/danieljustus/symaira-corekit/updatecheck"

	"github.com/danieljustus/symaira-vault/internal/metrics"
)

// DefaultLatestReleaseURL targets GitHub's "latest stable release" endpoint for
// the symaira-vault repository. The returned release is whatever GitHub
// currently advertises as latest.
//
// Release-line context (2026-06): the repository carries two lineages. The
// historical pre-rename releases v1.0.0–v4.0.0 remain in the tag list, and the
// current Symaira Vault series begins at v0.1.0. The semver comparison below
// is correct within any single series (e.g. v0.4.0 → v0.4.1) but is NOT
// designed to span the rename boundary — a user on v0.x will be told a v4.x
// release is "newer" because 4.0.0 > 0.4.0 numerically, even though the v4.x
// releases belong to the discontinued pre-rename line. See CHANGELOG.md (the
// release-series note added in #384) and docs/commercial-boundary.md for the
// current policy.
const DefaultLatestReleaseURL = "https://api.github.com/repos/danieljustus/symaira-vault/releases/latest"

// DefaultCacheTTL is the shared update-check cache lifetime.
const DefaultCacheTTL = updatecheck.DefaultCacheTTL

// httpDoer keeps the checker testable while production uses corekit's hardened
// HTTP client implementation.
type httpDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

// Checker adapts corekit's release checker to Vault's release-line filtering
// and metrics/output contract.
type Checker struct {
	HTTPClient       httpDoer
	LatestReleaseURL string
	CacheTTL         time.Duration
	CachePath        string

	corekit *updatecheck.Checker
}

type Result struct {
	CurrentVersion  string
	LatestVersion   string
	ReleaseURL      string
	Checkable       bool
	UpdateAvailable bool

	release *updatecheck.Release
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
		CacheTTL:         DefaultCacheTTL,
		CachePath:        updatecheck.DefaultCachePath("danieljustus", "symaira-vault"),
	}
}

// newSecureClient returns corekit's hardened HTTP client for release metadata.
func newSecureClient() *http.Client {
	return updatecheck.NewSecureClient()
}

// syncCorekit ensures the inner corekit checker reflects the Vault adapter's
// endpoint and cache settings before every check.
func (c *Checker) syncCorekit() {
	if c.corekit == nil {
		c.corekit = updatecheck.NewChecker("danieljustus", "symaira-vault")
	}
	if c.HTTPClient != nil {
		c.corekit.HTTPClient = c.HTTPClient
	}
	url := strings.TrimSpace(c.LatestReleaseURL)
	if url == "" {
		url = DefaultLatestReleaseURL
	}
	c.corekit.LatestReleaseURL = url
	c.corekit.CacheTTL = c.CacheTTL
	c.corekit.CachePath = c.CachePath
}

func (c *Checker) Check(ctx context.Context, currentVersion string) (*Result, error) {
	return c.CheckWithForce(ctx, currentVersion, false)
}

func (c *Checker) CheckWithForce(ctx context.Context, currentVersion string, force bool) (*Result, error) {
	current, ok := parseStableVersion(currentVersion)
	if !ok {
		return &Result{CurrentVersion: strings.TrimSpace(currentVersion)}, nil
	}

	c.syncCorekit()
	release, err := c.corekit.CheckWithForce(ctx, currentVersion, force)
	if err != nil {
		metrics.RecordUpdateCheck("error")
		return nil, err
	}

	result := &Result{
		CurrentVersion:  current.String(),
		LatestVersion:   current.String(),
		Checkable:       true,
		UpdateAvailable: release != nil,
		release:         release,
	}
	if release != nil {
		result.LatestVersion = strings.TrimPrefix(release.TagName, "v")
		result.ReleaseURL = release.HTMLURL
	}

	if result.UpdateAvailable {
		metrics.RecordUpdateCheck("update_available")
	} else {
		metrics.RecordUpdateCheck("up_to_date")
	}

	return result, nil
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
