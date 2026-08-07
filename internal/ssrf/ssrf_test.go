package ssrf

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

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
