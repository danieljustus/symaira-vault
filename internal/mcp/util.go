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

// DetectLANIPv4 returns the machine's non-loopback IPv4 addresses, suitable
// for advertising to a device pairing over the local network (e.g. a QR
// pairing payload). Loopback, down, and link-local interfaces are excluded.
// Returns an empty slice (not an error) when no LAN-reachable address is
// found; callers should treat that as "ask the user for --host explicitly"
// rather than a hard failure.
func DetectLANIPv4() ([]net.IP, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var out []net.IP
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			ip4 := ip.To4()
			if ip4 == nil || ip4.IsLoopback() || ip4.IsLinkLocalUnicast() {
				continue
			}
			out = append(out, ip4)
		}
	}
	return out, nil
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
