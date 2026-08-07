package ssrf

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// roundTripperFunc adapts a plain function to http.RoundTripper so tests can
// serve responses without any network I/O.
type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestValidateURL_RejectsResolvedPrivateAddress(t *testing.T) {
	resolver := func(context.Context, string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("127.0.0.1")}}, nil
	}

	err := ValidateURL(context.Background(), "http://public.example/secret", false, resolver)
	if err == nil {
		t.Fatal("ValidateURL() expected a private-address error")
	}
	if !strings.Contains(err.Error(), "resolves to private") {
		t.Fatalf("error = %v, want resolved-private explanation", err)
	}
}

func TestValidateURL_RejectsUnparseableURL(t *testing.T) {
	resolver := func(context.Context, string) ([]net.IPAddr, error) {
		return nil, fmt.Errorf("resolver should not be called for an unparseable URL")
	}

	err := ValidateURL(context.Background(), "http://[::1", false, resolver)
	if err == nil {
		t.Fatal("ValidateURL() expected an invalid-URL error")
	}
	if !strings.Contains(err.Error(), "invalid URL") {
		t.Fatalf("error = %v, want invalid-URL explanation", err)
	}
}

func TestValidateURL_RejectsEmptyHost(t *testing.T) {
	resolver := func(context.Context, string) ([]net.IPAddr, error) {
		return nil, fmt.Errorf("resolver should not be called when the host is empty")
	}

	err := ValidateURL(context.Background(), "http:///secret", false, resolver)
	if err == nil {
		t.Fatal("ValidateURL() expected a missing-host error")
	}
	if !strings.Contains(err.Error(), "URL host is required") {
		t.Fatalf("error = %v, want missing-host explanation", err)
	}
}

func TestValidateURL_RejectsPrivateHostLiteral(t *testing.T) {
	resolver := func(context.Context, string) ([]net.IPAddr, error) {
		return nil, fmt.Errorf("resolver should not be called for a literal private host")
	}

	err := ValidateURL(context.Background(), "http://127.0.0.1:8080/secret", false, resolver)
	if err == nil {
		t.Fatal("ValidateURL() expected a private-host error")
	}
	if !strings.Contains(err.Error(), "private or local network address") {
		t.Fatalf("error = %v, want private-host explanation", err)
	}
}

func TestValidateURL_RejectsUnresolvableHost(t *testing.T) {
	resolver := func(context.Context, string) ([]net.IPAddr, error) {
		return nil, fmt.Errorf("no such host")
	}

	err := ValidateURL(context.Background(), "http://unresolvable.example/secret", false, resolver)
	if err == nil {
		t.Fatal("ValidateURL() expected a resolution error")
	}
	if !strings.Contains(err.Error(), "cannot resolve request target") {
		t.Fatalf("error = %v, want resolution-error explanation", err)
	}
}

func TestAPIHTTPClient_RejectsPrivateRedirect(t *testing.T) {
	resolver := func(context.Context, string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("192.168.1.10")}}, nil
	}
	client := NewHTTPClientWithResolver(time.Second, false, resolver)
	req := httptest.NewRequest(http.MethodGet, "http://private.example/secret", nil)

	err := client.CheckRedirect(req, nil)
	if err == nil {
		t.Fatal("CheckRedirect() expected a private-address error")
	}
	if !strings.Contains(err.Error(), "redirect rejected") {
		t.Fatalf("error = %v, want redirect rejection", err)
	}
}

func TestAPIHTTPClient_AllowsPrivateOverride(t *testing.T) {
	resolver := func(context.Context, string) ([]net.IPAddr, error) {
		return nil, fmt.Errorf("resolver should not be called when private access is allowed")
	}
	client := NewHTTPClientWithResolver(time.Second, true, resolver)
	req := httptest.NewRequest(http.MethodGet, "http://localhost/secret", nil)

	if err := client.CheckRedirect(req, nil); err != nil {
		t.Fatalf("CheckRedirect() error with allow_private: %v", err)
	}
}

// TestAPIHTTPClient_RejectsRedirectViaRealClient exercises the redirect
// rejection through http.Client's own redirect-following machinery rather
// than calling CheckRedirect directly. The RoundTripper serves the redirect
// response without any network I/O, and the private redirect target is
// rejected before it could be dialed.
func TestAPIHTTPClient_RejectsRedirectViaRealClient(t *testing.T) {
	resolver := func(context.Context, string) ([]net.IPAddr, error) {
		return nil, fmt.Errorf("resolver should not be called for a literal private redirect target")
	}
	client := NewHTTPClientWithResolver(time.Second, false, resolver)
	client.Transport = roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusFound,
			Status:     "302 Found",
			Header:     http.Header{"Location": []string{"http://127.0.0.1:1/private"}},
			Body:       io.NopCloser(strings.NewReader("")),
			Request:    req,
		}, nil
	})

	resp, err := client.Get("http://public.example/start")
	if resp != nil && resp.Body != nil {
		_ = resp.Body.Close()
	}
	if err == nil {
		t.Fatal("client.Get() expected the redirect to be rejected")
	}
	if !strings.Contains(err.Error(), "redirect rejected") {
		t.Fatalf("error = %v, want redirect rejection", err)
	}
}

func TestDialAddress_RejectsPrivateIP(t *testing.T) {
	resolver := func(context.Context, string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("10.0.0.5")}}, nil
	}
	_, err := DialAddress(context.Background(), &net.Dialer{}, "tcp", "evil.example:443", false, resolver)
	if err == nil {
		t.Fatal("DialAddress() expected private-address error")
	}
	if !strings.Contains(err.Error(), "resolves to private") {
		t.Fatalf("error = %v, want resolved-private explanation", err)
	}
}

func TestDialAddress_RejectsInvalidAddress(t *testing.T) {
	resolver := func(context.Context, string) ([]net.IPAddr, error) {
		return nil, fmt.Errorf("resolver should not be called for an invalid address")
	}

	_, err := DialAddress(context.Background(), &net.Dialer{}, "tcp", "no-port", false, resolver)
	if err == nil {
		t.Fatal("DialAddress() expected an invalid-address error")
	}
	if !strings.Contains(err.Error(), "invalid request address") {
		t.Fatalf("error = %v, want invalid-address explanation", err)
	}
}

func TestDialAddress_RejectsPrivateHostLiteral(t *testing.T) {
	resolver := func(context.Context, string) ([]net.IPAddr, error) {
		return nil, fmt.Errorf("resolver should not be called for a literal private host")
	}

	_, err := DialAddress(context.Background(), &net.Dialer{}, "tcp", "127.0.0.1:443", false, resolver)
	if err == nil {
		t.Fatal("DialAddress() expected a private-host error")
	}
	if !strings.Contains(err.Error(), "private or local network address") {
		t.Fatalf("error = %v, want private-host explanation", err)
	}
}

func TestDialAddress_RejectsEmptyResolution(t *testing.T) {
	resolver := func(context.Context, string) ([]net.IPAddr, error) {
		return []net.IPAddr{}, nil
	}

	_, err := DialAddress(context.Background(), &net.Dialer{}, "tcp", "empty.example:443", false, resolver)
	if err == nil {
		t.Fatal("DialAddress() expected a no-usable-addresses error")
	}
	if !strings.Contains(err.Error(), "no usable addresses") {
		t.Fatalf("error = %v, want no-usable-addresses explanation", err)
	}
}

func TestDialAddress_FiltersIPv6ForTCP4(t *testing.T) {
	resolver := func(context.Context, string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("2606:4700:4700::1111")}}, nil
	}

	_, err := DialAddress(context.Background(), &net.Dialer{}, "tcp4", "v6-only.example:443", false, resolver)
	if err == nil {
		t.Fatal("DialAddress() expected a no-usable-addresses error for tcp4 with only IPv6 addresses")
	}
	if !strings.Contains(err.Error(), "no usable addresses") {
		t.Fatalf("error = %v, want no-usable-addresses explanation", err)
	}
}

func TestDialAddress_FiltersIPv4ForTCP6(t *testing.T) {
	resolver := func(context.Context, string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("1.2.3.4")}}, nil
	}

	_, err := DialAddress(context.Background(), &net.Dialer{}, "tcp6", "v4-only.example:443", false, resolver)
	if err == nil {
		t.Fatal("DialAddress() expected a no-usable-addresses error for tcp6 with only IPv4 addresses")
	}
	if !strings.Contains(err.Error(), "no usable addresses") {
		t.Fatalf("error = %v, want no-usable-addresses explanation", err)
	}
}

// TestDialAddress_ReturnsLastDialError covers the all-dials-failed branch.
// The port 99999 is above the uint16 range, so DialContext fails at address
// parsing without any network I/O.
func TestDialAddress_ReturnsLastDialError(t *testing.T) {
	resolver := func(context.Context, string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("1.2.3.4")}}, nil
	}

	_, err := DialAddress(context.Background(), &net.Dialer{}, "tcp4", "public.example:99999", false, resolver)
	if err == nil {
		t.Fatal("DialAddress() expected the dial error")
	}
	if !strings.Contains(err.Error(), "99999") {
		t.Fatalf("error = %v, want the dial error mentioning the rejected port", err)
	}
	if strings.Contains(err.Error(), "no usable addresses") {
		t.Fatalf("error = %v, want the dial error, not the no-usable-addresses message", err)
	}
}

func TestHTTPClientWithTLSConfig_AppliesTLSConfig(t *testing.T) {
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	client := NewHTTPClientWithTLSConfig(time.Second, false, tlsConfig)

	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("Transport = %T, want *http.Transport", client.Transport)
	}
	if transport.TLSClientConfig != tlsConfig {
		t.Fatalf("TLSClientConfig = %v, want the injected config", transport.TLSClientConfig)
	}
}

func TestHTTPClientWithTLSConfig_NilConfigDoesNotPanic(t *testing.T) {
	client := NewHTTPClientWithTLSConfig(time.Second, false, nil)

	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("Transport = %T, want *http.Transport", client.Transport)
	}
	if transport.TLSClientConfig != nil {
		t.Fatalf("TLSClientConfig = %v, want nil for a nil config", transport.TLSClientConfig)
	}
}
