package update

import (
	"context"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
)

func TestFetchCosignSignature_Success(t *testing.T) {
	expectedBody := []byte("fake-cosign-signature")
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

	data, err := FetchCosignSignature(context.Background(), "0.5.0")
	if err != nil {
		t.Fatalf("FetchCosignSignature() error = %v", err)
	}
	if string(data) != string(expectedBody) {
		t.Fatalf("got body %q, want %q", string(data), string(expectedBody))
	}
}

func TestFetchCosignSignature_HTTPError(t *testing.T) {
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

	_, err := FetchCosignSignature(context.Background(), "0.5.0")
	if err == nil {
		t.Fatal("expected HTTP error")
	}
	if !strings.Contains(err.Error(), "HTTP 404") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestFetchCosignSignature_EmptyVersion(t *testing.T) {
	_, err := FetchCosignSignature(context.Background(), "")
	if err == nil {
		t.Fatal("expected empty version error")
	}
	if !strings.Contains(err.Error(), "version must not be empty") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestFetchCosignSignature_URLScheme(t *testing.T) {
	origURL := DefaultDownloadBaseURL
	DefaultDownloadBaseURL = "http://example.com/fake"
	t.Cleanup(func() { DefaultDownloadBaseURL = origURL })

	_, err := FetchCosignSignature(context.Background(), "0.5.0")
	if err == nil {
		t.Fatal("expected HTTPS enforcement error")
	}
	if !strings.Contains(err.Error(), "must use HTTPS") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestFetchCosignCertificate_Success(t *testing.T) {
	expectedBody := []byte("fake-cosign-certificate")
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

	data, err := FetchCosignCertificate(context.Background(), "0.5.0")
	if err != nil {
		t.Fatalf("FetchCosignCertificate() error = %v", err)
	}
	if string(data) != string(expectedBody) {
		t.Fatalf("got body %q, want %q", string(data), string(expectedBody))
	}
}

func TestFetchCosignCertificate_HTTPError(t *testing.T) {
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

	_, err := FetchCosignCertificate(context.Background(), "0.5.0")
	if err == nil {
		t.Fatal("expected HTTP error")
	}
	if !strings.Contains(err.Error(), "HTTP 403") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestFetchCosignCertificate_EmptyVersion(t *testing.T) {
	_, err := FetchCosignCertificate(context.Background(), "")
	if err == nil {
		t.Fatal("expected empty version error")
	}
	if !strings.Contains(err.Error(), "version must not be empty") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestFetchCosignCertificate_URLScheme(t *testing.T) {
	origURL := DefaultDownloadBaseURL
	DefaultDownloadBaseURL = "http://example.com/fake"
	t.Cleanup(func() { DefaultDownloadBaseURL = origURL })

	_, err := FetchCosignCertificate(context.Background(), "0.5.0")
	if err == nil {
		t.Fatal("expected HTTPS enforcement error")
	}
	if !strings.Contains(err.Error(), "must use HTTPS") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestVerifyCosignSignature_CosignNotFound(t *testing.T) {
	origPath := os.Getenv("PATH")
	t.Cleanup(func() { os.Setenv("PATH", origPath) })
	os.Setenv("PATH", "")

	err := VerifyCosignSignature(
		[]byte("test-content"),
		[]byte("fake-signature"),
		[]byte("fake-certificate"),
	)
	if err == nil {
		t.Fatal("expected error when cosign is not on PATH")
	}
	if !strings.Contains(err.Error(), "cosign CLI not found") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestCosignIdentityRegexp_MatchesSymairaVault(t *testing.T) {
	// The regexp must use the correct lowercase-hyphenated repo slug.
	// Regression test for the OpenPass→Symaira rename where "Symaira Vault"
	// (with space) was left in the regexp, causing every verification to fail.
	if strings.Contains(CosignIdentityRegexp, "Symaira Vault") {
		t.Fatal("CosignIdentityRegexp contains 'Symaira Vault' — must use 'symaira-vault' (lowercase, hyphenated)")
	}
	if !strings.Contains(CosignIdentityRegexp, `danieljustus/symaira-vault`) {
		t.Fatal("CosignIdentityRegexp must contain 'danieljustus/symaira-vault'")
	}
}
