package update

import (
	"context"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestCosignSignatureFileName(t *testing.T) {
	tests := []struct {
		version  string
		expected string
	}{
		{"0.5.0", "OpenPass_0.5.0_checksums.txt.sig"},
		{"v1.2.0", "OpenPass_1.2.0_checksums.txt.sig"},
		{"v", "OpenPass__checksums.txt.sig"},
	}
	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			got := cosignSignatureFileName(tt.version)
			if got != tt.expected {
				t.Fatalf("cosignSignatureFileName(%q) = %q, want %q",
					tt.version, got, tt.expected)
			}
		})
	}
}

func TestCosignCertificateFileName(t *testing.T) {
	tests := []struct {
		version  string
		expected string
	}{
		{"0.5.0", "OpenPass_0.5.0_checksums.txt.pem"},
		{"v1.2.0", "OpenPass_1.2.0_checksums.txt.pem"},
	}
	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			got := cosignCertificateFileName(tt.version)
			if got != tt.expected {
				t.Fatalf("cosignCertificateFileName(%q) = %q, want %q",
					tt.version, got, tt.expected)
			}
		})
	}
}

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

func TestVerifyCosignSignature_InvalidArgs(t *testing.T) {
	if _, err := exec.LookPath("cosign"); err == nil {
		t.Skip("cosign is installed — this test is for the binary-not-found path")
	}

	origPath := os.Getenv("PATH")
	t.Cleanup(func() { os.Setenv("PATH", origPath) })
	os.Setenv("PATH", "")

	err := VerifyCosignSignature(
		[]byte("random-content"),
		[]byte("random-sig"),
		[]byte("random-cert"),
	)
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "install cosign") {
		t.Fatalf("error should instruct user to install cosign: %v", err)
	}
}

func TestVerifyCosignSignature_ExecFailure(t *testing.T) {
	if _, err := exec.LookPath("cosign"); err != nil {
		t.Skip("cosign not on PATH — exec failure test requires cosign to pass LookPath")
	}

	origExec := execCommand
	t.Cleanup(func() { execCommand = origExec })

	execCommand = func(name string, arg ...string) *exec.Cmd {
		if name == "cosign" {
			return exec.Command("false")
		}
		return exec.Command(name, arg...)
	}

	err := VerifyCosignSignature(
		[]byte("content"),
		[]byte("sig"),
		[]byte("cert"),
	)
	if err == nil {
		t.Fatal("expected error from cosign exec failure")
	}
	if !strings.Contains(err.Error(), "cosign verify-blob failed") {
		t.Fatalf("unexpected error: %v", err)
	}
}
