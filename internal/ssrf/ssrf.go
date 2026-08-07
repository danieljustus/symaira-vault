// Package ssrf provides SSRF-hardened HTTP client plumbing shared by the
// execute_api_request tool and the egress broker: dial-time DNS
// re-resolution with private-address blocking, request-target validation and
// redirect validation. DNS is resolved at dial time so a rebinding attack
// cannot redirect injected credentials to a private network address.
package ssrf

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/danieljustus/symaira-vault/internal/mcp/apitemplates"
)

// Resolver resolves a host to IP addresses. Production code uses
// net.DefaultResolver.LookupIPAddr; tests inject a stub.
type Resolver func(context.Context, string) ([]net.IPAddr, error)

// ValidateURL blocks request targets that are private, local or resolve to
// private addresses, unless allowPrivate is set.
func ValidateURL(ctx context.Context, rawURL string, allowPrivate bool, resolve Resolver) error {
	if allowPrivate {
		return nil
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("blocked request target: invalid URL: %w", err)
	}
	if u.Hostname() == "" {
		return fmt.Errorf("blocked request target: URL host is required")
	}
	if apitemplates.IsPrivateHost(u.Host) {
		return fmt.Errorf("blocked request target %q: private or local network address", u.Host)
	}
	addresses, err := resolve(ctx, u.Hostname())
	if err != nil {
		return fmt.Errorf("cannot resolve request target %q: %w", u.Hostname(), err)
	}
	for _, address := range addresses {
		if apitemplates.IsPrivateIP(address.IP) {
			return fmt.Errorf("blocked request target %q: resolves to private or local network address", u.Hostname())
		}
	}
	return nil
}

// DialAddress dials the given network address with dial-time re-resolution
// of the hostname, rejecting private targets unless allowPrivate is set.
func DialAddress(ctx context.Context, dialer *net.Dialer, network, address string, allowPrivate bool, resolve Resolver) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, fmt.Errorf("invalid request address %q: %w", address, err)
	}
	if allowPrivate {
		return dialer.DialContext(ctx, network, address)
	}
	if apitemplates.IsPrivateHost(host) {
		return nil, fmt.Errorf("blocked request target %q: private or local network address", host)
	}
	addresses, err := resolve(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("cannot resolve request target %q: %w", host, err)
	}
	var lastErr error
	for _, resolved := range addresses {
		if apitemplates.IsPrivateIP(resolved.IP) {
			return nil, fmt.Errorf("blocked request target %q: resolves to private or local network address", host)
		}
		if network == "tcp4" && resolved.IP.To4() == nil {
			continue
		}
		if network == "tcp6" && resolved.IP.To4() != nil {
			continue
		}
		conn, dialErr := dialer.DialContext(ctx, network, net.JoinHostPort(resolved.IP.String(), port))
		if dialErr == nil {
			return conn, nil
		}
		lastErr = dialErr
	}
	if lastErr != nil {
		return nil, lastErr
	}
	return nil, fmt.Errorf("no usable addresses for request target %q", host)
}

// NewHTTPClient builds an SSRF-hardened HTTP client with the given timeout.
func NewHTTPClient(timeout time.Duration, allowPrivate bool) *http.Client {
	return NewHTTPClientWithResolver(timeout, allowPrivate, net.DefaultResolver.LookupIPAddr)
}

// NewHTTPClientWithTLSConfig builds an SSRF-hardened HTTP client with a custom
// upstream TLS configuration (test hooks, corporate MITM setups).
func NewHTTPClientWithTLSConfig(timeout time.Duration, allowPrivate bool, tlsConfig *tls.Config) *http.Client {
	client := NewHTTPClientWithResolver(timeout, allowPrivate, net.DefaultResolver.LookupIPAddr)
	if tlsConfig != nil {
		transport, ok := client.Transport.(*http.Transport)
		if ok {
			transport.TLSClientConfig = tlsConfig
		}
	}
	return client
}

// NewHTTPClientWithResolver builds an SSRF-hardened HTTP client with an
// injectable resolver.
func NewHTTPClientWithResolver(timeout time.Duration, allowPrivate bool, resolve Resolver) *http.Client {
	dialer := &net.Dialer{}
	transport := &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			return DialAddress(ctx, dialer, network, address, allowPrivate, resolve)
		},
	}
	return &http.Client{
		Timeout:   timeout,
		Transport: transport,
		CheckRedirect: func(req *http.Request, _ []*http.Request) error {
			if err := ValidateURL(req.Context(), req.URL.String(), allowPrivate, resolve); err != nil {
				return fmt.Errorf("redirect rejected: %w", err)
			}
			return nil
		},
	}
}
