package mcp

import (
	"net"
	"net/netip"
	"strings"
)

// StripPort strips the port from a host:port string.
func StripPort(hostport string) string {
	hostport = strings.TrimSpace(hostport)
	if hostport == "" {
		return ""
	}
	if host, _, err := net.SplitHostPort(hostport); err == nil {
		return host
	}
	if strings.Count(hostport, ":") == 1 {
		if host, _, ok := strings.Cut(hostport, ":"); ok {
			return host
		}
	}
	return strings.Trim(hostport, "[]")
}

// IsLoopbackHost reports whether host is a loopback host.
func IsLoopbackHost(host string) bool {
	host = strings.Trim(strings.ToLower(host), "[]")
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// IsTrustedProxy checks if the given remote address belongs to a trusted proxy.
func IsTrustedProxy(remoteAddr string, trustedProxies []string) bool {
	if len(trustedProxies) == 0 {
		return false
	}
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	if host == "" {
		return false
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	for _, p := range trustedProxies {
		if strings.Contains(p, "/") {
			prefix, err := netip.ParsePrefix(p)
			if err == nil && prefix.Contains(addr) {
				return true
			}
		} else {
			trustedAddr, err := netip.ParseAddr(p)
			if err == nil && trustedAddr == addr {
				return true
			}
		}
	}
	return false
}
