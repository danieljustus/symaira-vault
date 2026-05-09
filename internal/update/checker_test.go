package update

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type stubHTTPDoer struct {
	do func(req *http.Request) (*http.Response, error)
}

func (s stubHTTPDoer) Do(req *http.Request) (*http.Response, error) {
	return s.do(req)
}

func TestCheckerSkipsNonReleaseVersions(t *testing.T) {
	checker := NewChecker(stubHTTPDoer{
		do: func(req *http.Request) (*http.Response, error) {
			t.Fatalf("unexpected HTTP request to %s", req.URL.String())
			return nil, nil
		},
	})

	result, err := checker.Check(context.Background(), "dev")
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if result.Checkable {
		t.Fatalf("Checkable = %v, want false", result.Checkable)
	}
	if result.CurrentVersion != "dev" {
		t.Fatalf("CurrentVersion = %q, want %q", result.CurrentVersion, "dev")
	}
}

func TestCheckerReportsAvailableUpdate(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"tag_name":"v1.2.0","html_url":"https://example.com/v1.2.0"}`))
	}))
	defer server.Close()

	checker := NewChecker(server.Client())
	checker.LatestReleaseURL = server.URL
	checker.Cache = nil

	result, err := checker.Check(context.Background(), "1.0.0")
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if !result.Checkable {
		t.Fatal("expected release build to be checkable")
	}
	if !result.UpdateAvailable {
		t.Fatal("expected update to be available")
	}
	if result.LatestVersion != "1.2.0" {
		t.Fatalf("LatestVersion = %q, want %q", result.LatestVersion, "1.2.0")
	}
	if result.ReleaseURL != "https://example.com/v1.2.0" {
		t.Fatalf("ReleaseURL = %q", result.ReleaseURL)
	}
}

func TestCheckerReportsUpToDate(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"tag_name":"v1.10.0","html_url":"https://example.com/v1.10.0"}`))
	}))
	defer server.Close()

	checker := NewChecker(server.Client())
	checker.LatestReleaseURL = server.URL
	checker.Cache = nil

	result, err := checker.Check(context.Background(), "v1.10.0")
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if result.UpdateAvailable {
		t.Fatal("expected no update to be available")
	}
	if result.CurrentVersion != "1.10.0" {
		t.Fatalf("CurrentVersion = %q, want %q", result.CurrentVersion, "1.10.0")
	}
}

func TestCheckerRejectsInvalidLatestTag(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"tag_name":"latest","html_url":"https://example.com/latest"}`))
	}))
	defer server.Close()

	checker := NewChecker(server.Client())
	checker.LatestReleaseURL = server.URL
	checker.Cache = nil

	_, err := checker.Check(context.Background(), "1.0.0")
	if err == nil {
		t.Fatal("expected invalid tag name to fail")
	}
	if !strings.Contains(err.Error(), "stable semantic version") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestCheckerReturnsHTTPError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusInternalServerError)
	}))
	defer server.Close()

	checker := NewChecker(server.Client())
	checker.LatestReleaseURL = server.URL
	checker.Cache = nil

	_, err := checker.Check(context.Background(), "1.0.0")
	if err == nil {
		t.Fatal("expected HTTP error")
	}
	if !strings.Contains(err.Error(), "HTTP 500") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestCheckerReturnsDecodeError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"tag_name":`))
	}))
	defer server.Close()

	checker := NewChecker(server.Client())
	checker.LatestReleaseURL = server.URL
	checker.Cache = nil

	_, err := checker.Check(context.Background(), "1.0.0")
	if err == nil {
		t.Fatal("expected decode error")
	}
	if !strings.Contains(err.Error(), "decode latest release response") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestCheckerReturnsTimeoutError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(50 * time.Millisecond)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"tag_name":"v1.0.1","html_url":"https://example.com/v1.0.1"}`))
	}))
	defer server.Close()

	client := server.Client()
	client.Timeout = 10 * time.Millisecond

	checker := NewChecker(client)
	checker.LatestReleaseURL = server.URL
	checker.Cache = nil

	_, err := checker.Check(context.Background(), "1.0.0")
	if err == nil {
		t.Fatal("expected timeout error")
	}
	if !strings.Contains(err.Error(), "request latest release") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestCompareStableVersions(t *testing.T) {
	left, ok := parseStableVersion("1.10.0")
	if !ok {
		t.Fatal("expected left version to parse")
	}
	right, ok := parseStableVersion("1.2.0")
	if !ok {
		t.Fatal("expected right version to parse")
	}

	if compareStableVersions(left, right) <= 0 {
		t.Fatalf("expected %s to be newer than %s", left.String(), right.String())
	}
}

func TestCheckerUsesCache(t *testing.T) {
	tmpDir := t.TempDir()
	cache := NewCacheWithTTL(tmpDir+"/update-cache.json", 24*time.Hour)

	_ = cache.Save(&CacheEntry{
		Timestamp:     time.Now(),
		LatestVersion: "1.5.0",
		ReleaseURL:    "https://example.com/v1.5.0",
	})

	requestCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"tag_name":"v1.5.0","html_url":"https://example.com/v1.5.0"}`))
	}))
	defer server.Close()

	checker := NewChecker(server.Client())
	checker.LatestReleaseURL = server.URL
	checker.Cache = cache

	result, err := checker.Check(context.Background(), "1.0.0")
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if requestCount != 0 {
		t.Fatalf("expected cache hit, but got %d HTTP requests", requestCount)
	}
	if result.LatestVersion != "1.5.0" {
		t.Fatalf("LatestVersion = %q, want %q", result.LatestVersion, "1.5.0")
	}
	if result.ReleaseURL != "https://example.com/v1.5.0" {
		t.Fatalf("ReleaseURL = %q, want %q", result.ReleaseURL, "https://example.com/v1.5.0")
	}
}

func TestCheckerForceBypassesCache(t *testing.T) {
	tmpDir := t.TempDir()
	cache := NewCacheWithTTL(tmpDir+"/update-cache.json", 24*time.Hour)

	_ = cache.Save(&CacheEntry{
		Timestamp:     time.Now(),
		LatestVersion: "1.5.0",
		ReleaseURL:    "https://example.com/v1.5.0",
	})

	requestCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"tag_name":"v1.6.0","html_url":"https://example.com/v1.6.0"}`))
	}))
	defer server.Close()

	checker := NewChecker(server.Client())
	checker.LatestReleaseURL = server.URL
	checker.Cache = cache

	result, err := checker.CheckWithForce(context.Background(), "1.0.0", true)
	if err != nil {
		t.Fatalf("CheckWithForce() error = %v", err)
	}
	if requestCount != 1 {
		t.Fatalf("expected 1 HTTP request with --force, got %d", requestCount)
	}
	if result.LatestVersion != "1.6.0" {
		t.Fatalf("LatestVersion = %q, want %q", result.LatestVersion, "1.6.0")
	}
}

func TestCheckerSavesToCache(t *testing.T) {
	tmpDir := t.TempDir()
	cachePath := tmpDir + "/update-cache.json"
	cache := NewCacheWithTTL(cachePath, 24*time.Hour)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"tag_name":"v1.2.0","html_url":"https://example.com/v1.2.0"}`))
	}))
	defer server.Close()

	checker := NewChecker(server.Client())
	checker.LatestReleaseURL = server.URL
	checker.Cache = cache

	_, err := checker.Check(context.Background(), "1.0.0")
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}

	loaded, err := cache.Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if loaded == nil {
		t.Fatal("expected cache to be saved")
	}
	if loaded.LatestVersion != "1.2.0" {
		t.Fatalf("cached LatestVersion = %q, want %q", loaded.LatestVersion, "1.2.0")
	}
	if loaded.ReleaseURL != "https://example.com/v1.2.0" {
		t.Fatalf("cached ReleaseURL = %q, want %q", loaded.ReleaseURL, "https://example.com/v1.2.0")
	}
}

func TestCheckerNilCache(t *testing.T) {
	requestCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"tag_name":"v1.2.0","html_url":"https://example.com/v1.2.0"}`))
	}))
	defer server.Close()

	checker := NewChecker(server.Client())
	checker.LatestReleaseURL = server.URL
	checker.Cache = nil

	result, err := checker.Check(context.Background(), "1.0.0")
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if requestCount != 1 {
		t.Fatalf("expected 1 HTTP request with nil cache, got %d", requestCount)
	}
	if result.LatestVersion != "1.2.0" {
		t.Fatalf("LatestVersion = %q, want %q", result.LatestVersion, "1.2.0")
	}
}

func TestCheckerRejectsDraftRelease(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"draft":true,"tag_name":"v1.0.0","html_url":"https://example.com/v1.0.0"}`))
	}))
	defer server.Close()

	checker := NewChecker(server.Client())
	checker.LatestReleaseURL = server.URL
	checker.Cache = nil

	_, err := checker.Check(context.Background(), "0.9.0")
	if err == nil {
		t.Fatal("expected error for draft release")
	}
	if !strings.Contains(err.Error(), "draft") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestCheckerRejectsPrerelease(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"prerelease":true,"tag_name":"v1.0.0","html_url":"https://example.com/v1.0.0"}`))
	}))
	defer server.Close()

	checker := NewChecker(server.Client())
	checker.LatestReleaseURL = server.URL
	checker.Cache = nil

	_, err := checker.Check(context.Background(), "0.9.0")
	if err == nil {
		t.Fatal("expected error for prerelease")
	}
	if !strings.Contains(err.Error(), "prerelease") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestCheckerRejectsEmptyTagName(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"tag_name":"   ","html_url":"https://example.com/"}`))
	}))
	defer server.Close()

	checker := NewChecker(server.Client())
	checker.LatestReleaseURL = server.URL
	checker.Cache = nil

	_, err := checker.Check(context.Background(), "1.0.0")
	if err == nil {
		t.Fatal("expected error for empty tag name")
	}
	if !strings.Contains(err.Error(), "did not include a tag name") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestCheckerRateLimitExceeded(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-RateLimit-Remaining", "0")
		w.WriteHeader(http.StatusForbidden)
	}))
	defer server.Close()

	checker := NewChecker(server.Client())
	checker.LatestReleaseURL = server.URL
	checker.Cache = nil

	_, err := checker.Check(context.Background(), "1.0.0")
	if err == nil {
		t.Fatal("expected error for rate limit exceeded")
	}
	if !strings.Contains(err.Error(), "rate limit exceeded") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestCheckerCacheUnparseableVersion(t *testing.T) {
	tmpDir := t.TempDir()
	cache := NewCacheWithTTL(tmpDir+"/update-cache.json", 24*time.Hour)

	_ = cache.Save(&CacheEntry{
		Timestamp:     time.Now(),
		LatestVersion: "not-a-version",
		ReleaseURL:    "https://example.com/v1.0.0",
	})

	requestCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"tag_name":"v1.5.0","html_url":"https://example.com/v1.5.0"}`))
	}))
	defer server.Close()

	checker := NewChecker(server.Client())
	checker.LatestReleaseURL = server.URL
	checker.Cache = cache

	result, err := checker.Check(context.Background(), "1.0.0")
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if requestCount != 1 {
		t.Fatalf("expected 1 HTTP request due to unparseable cache version, got %d", requestCount)
	}
	if result.LatestVersion != "1.5.0" {
		t.Fatalf("LatestVersion = %q, want %q", result.LatestVersion, "1.5.0")
	}
}

func TestNewCheckerWithNilClient(t *testing.T) {
	checker := NewChecker(nil)
	if checker == nil {
		t.Fatal("NewChecker(nil) returned nil")
	}
	if checker.HTTPClient == nil {
		t.Fatal("NewChecker(nil) should have non-nil HTTPClient")
	}
	if checker.Cache == nil {
		t.Fatal("NewChecker(nil) should have non-nil Cache")
	}
	if checker.LatestReleaseURL == "" {
		t.Fatal("NewChecker(nil) should have non-empty LatestReleaseURL")
	}
}

func TestCheckerURLTrimming(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"tag_name":"v1.2.0","html_url":"https://example.com/v1.2.0"}`))
	}))
	defer server.Close()

	checker := NewChecker(server.Client())
	checker.LatestReleaseURL = "  " + server.URL + "  "
	checker.Cache = nil

	result, err := checker.Check(context.Background(), "1.0.0")
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if result.LatestVersion != "1.2.0" {
		t.Fatalf("LatestVersion = %q, want %q", result.LatestVersion, "1.2.0")
	}
}

func TestCheckerReturnsHTTP404(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "not found", http.StatusNotFound)
	}))
	defer server.Close()

	checker := NewChecker(server.Client())
	checker.LatestReleaseURL = server.URL
	checker.Cache = nil

	_, err := checker.Check(context.Background(), "1.0.0")
	if err == nil {
		t.Fatal("expected HTTP 404 error")
	}
	if !strings.Contains(err.Error(), "HTTP 404") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestCheckerReturnsNetworkError(t *testing.T) {
	checker := NewChecker(stubHTTPDoer{
		do: func(req *http.Request) (*http.Response, error) {
			return nil, fmt.Errorf("connection refused")
		},
	})
	checker.LatestReleaseURL = "http://localhost:1"
	checker.Cache = nil

	_, err := checker.Check(context.Background(), "1.0.0")
	if err == nil {
		t.Fatal("expected network error")
	}
	if !strings.Contains(err.Error(), "request latest release") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestCheckerEmptyLatestReleaseURLFallback(t *testing.T) {
	checker := NewChecker(stubHTTPDoer{
		do: func(req *http.Request) (*http.Response, error) {
			if req.URL.String() != DefaultLatestReleaseURL {
				t.Fatalf("expected URL %q, got %q", DefaultLatestReleaseURL, req.URL.String())
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader(`{"tag_name":"v1.0.0","html_url":"https://example.com"}`)),
				Header:     http.Header{"Content-Type": []string{"application/json"}},
			}, nil
		},
	})
	checker.LatestReleaseURL = ""
	checker.Cache = nil

	_, err := checker.Check(context.Background(), "1.0.0")
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
}

func TestParseStableVersionEmpty(t *testing.T) {
	_, ok := parseStableVersion("")
	if ok {
		t.Fatal("parseStableVersion(\"\") should return ok=false")
	}
}

func TestParseStableVersionWhitespaceOnly(t *testing.T) {
	_, ok := parseStableVersion("   ")
	if ok {
		t.Fatal("parseStableVersion(\"   \") should return ok=false")
	}
}

func TestParseStableVersionNegative(t *testing.T) {
	_, ok := parseStableVersion("-1.0.0")
	if ok {
		t.Fatal("parseStableVersion(\"-1.0.0\") should return ok=false")
	}
}

func TestParseStableVersionPrerelease(t *testing.T) {
	_, ok := parseStableVersion("1.0.0-alpha")
	if ok {
		t.Fatal("parseStableVersion(\"1.0.0-alpha\") should return ok=false")
	}
}

func TestParseStableVersionBuildMetadata(t *testing.T) {
	_, ok := parseStableVersion("1.0.0+build")
	if ok {
		t.Fatal("parseStableVersion(\"1.0.0+build\") should return ok=false")
	}
}

func TestParseStableVersionPrereleaseAndBuildMetadata(t *testing.T) {
	_, ok := parseStableVersion("1.0.0-alpha+build")
	if ok {
		t.Fatal("parseStableVersion(\"1.0.0-alpha+build\") should return ok=false")
	}
}

func TestParseStableVersionTooFewParts(t *testing.T) {
	_, ok := parseStableVersion("1.0")
	if ok {
		t.Fatal("parseStableVersion(\"1.0\") should return ok=false")
	}
}

func TestParseStableVersionTooManyParts(t *testing.T) {
	_, ok := parseStableVersion("1.0.0.0")
	if ok {
		t.Fatal("parseStableVersion(\"1.0.0.0\") should return ok=false")
	}
}

func TestParseStableVersionEmptyPart(t *testing.T) {
	_, ok := parseStableVersion("1..0")
	if ok {
		t.Fatal("parseStableVersion(\"1..0\") should return ok=false")
	}
}

func TestParseStableVersionNonNumeric(t *testing.T) {
	_, ok := parseStableVersion("a.b.c")
	if ok {
		t.Fatal("parseStableVersion(\"a.b.c\") should return ok=false")
	}
}

func TestCompareStableVersionsLeftGreater(t *testing.T) {
	left, _ := parseStableVersion("2.0.0")
	right, _ := parseStableVersion("1.9.9")
	if compareStableVersions(left, right) != 1 {
		t.Fatalf("expected 2.0.0 > 1.9.9")
	}
}

func TestCompareStableVersionsRightGreaterMajor(t *testing.T) {
	left, _ := parseStableVersion("1.0.0")
	right, _ := parseStableVersion("2.0.0")
	if compareStableVersions(left, right) != -1 {
		t.Fatalf("expected 1.0.0 < 2.0.0")
	}
}

func TestCompareStableVersionsRightGreaterMinor(t *testing.T) {
	left, _ := parseStableVersion("1.1.0")
	right, _ := parseStableVersion("1.2.0")
	if compareStableVersions(left, right) != -1 {
		t.Fatalf("expected 1.1.0 < 1.2.0")
	}
}

func TestCompareStableVersionsRightGreaterPatch(t *testing.T) {
	left, _ := parseStableVersion("1.0.1")
	right, _ := parseStableVersion("1.0.2")
	if compareStableVersions(left, right) != -1 {
		t.Fatalf("expected 1.0.1 < 1.0.2")
	}
}

func TestCompareStableVersionsLeftGreaterMinor(t *testing.T) {
	left, _ := parseStableVersion("1.2.0")
	right, _ := parseStableVersion("1.1.0")
	if compareStableVersions(left, right) != 1 {
		t.Fatalf("expected 1.2.0 > 1.1.0")
	}
}

func TestCompareStableVersionsLeftGreaterPatch(t *testing.T) {
	left, _ := parseStableVersion("1.0.2")
	right, _ := parseStableVersion("1.0.1")
	if compareStableVersions(left, right) != 1 {
		t.Fatalf("expected 1.0.2 > 1.0.1")
	}
}
