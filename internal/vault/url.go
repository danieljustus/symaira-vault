package vault

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"unicode"
)

// URLKey is the well-known key in Entry.Data for associated service URLs.
const URLKey = "url"

// ErrInvalidURL indicates that a URL or host string could not be parsed or validated.
var ErrInvalidURL = errors.New("invalid url")

// ValidateURL validates that a raw URL or host string is non-empty, contains no invalid
// whitespace or control characters, and normalizes to a valid host.
func ValidateURL(raw string) error {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return fmt.Errorf("%w: url cannot be empty", ErrInvalidURL)
	}
	if strings.ContainsAny(trimmed, " \t\r\n") {
		return fmt.Errorf("%w: url contains whitespace", ErrInvalidURL)
	}
	for _, r := range trimmed {
		if unicode.IsControl(r) {
			return fmt.Errorf("%w: url contains control character", ErrInvalidURL)
		}
	}
	_, err := NormalizeHost(trimmed)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidURL, err)
	}
	_, err = NormalizeURL(trimmed)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidURL, err)
	}
	return nil
}

// NormalizeURL normalizes a URL by defaulting the scheme to https:// if missing,
// lowercasing the scheme and host, and stripping default protocol ports (e.g. 443 for https, 80 for http).
func NormalizeURL(raw string) (string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", fmt.Errorf("%w: url cannot be empty", ErrInvalidURL)
	}
	if strings.ContainsAny(trimmed, " \t\r\n") {
		return "", fmt.Errorf("%w: url contains whitespace", ErrInvalidURL)
	}
	for _, r := range trimmed {
		if unicode.IsControl(r) {
			return "", fmt.Errorf("%w: url contains control character", ErrInvalidURL)
		}
	}

	rawWithScheme := trimmed
	if !strings.Contains(rawWithScheme, "://") {
		if strings.HasPrefix(rawWithScheme, "//") {
			rawWithScheme = "https:" + rawWithScheme
		} else {
			rawWithScheme = "https://" + rawWithScheme
		}
	}

	u, err := url.Parse(rawWithScheme)
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrInvalidURL, err)
	}

	if u.Host == "" {
		return "", fmt.Errorf("%w: missing host", ErrInvalidURL)
	}

	scheme := strings.ToLower(u.Scheme)
	normHost, err := normalizeHostPort(u.Host, scheme)
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrInvalidURL, err)
	}

	u.Scheme = scheme
	u.Host = normHost
	return u.String(), nil
}

// NormalizeHost extracts and normalizes the host (and non-default port) from a URL or host string.
// Schemes are ignored, hosts are lowercased, and default protocol ports are stripped.
func NormalizeHost(raw string) (string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", fmt.Errorf("%w: host cannot be empty", ErrInvalidURL)
	}
	if strings.ContainsAny(trimmed, " \t\r\n") {
		return "", fmt.Errorf("%w: host contains whitespace", ErrInvalidURL)
	}
	for _, r := range trimmed {
		if unicode.IsControl(r) {
			return "", fmt.Errorf("%w: host contains control character", ErrInvalidURL)
		}
	}

	rawWithScheme := trimmed
	scheme := ""
	if strings.Contains(rawWithScheme, "://") {
		u, err := url.Parse(rawWithScheme)
		if err != nil {
			return "", fmt.Errorf("%w: %w", ErrInvalidURL, err)
		}
		if u.Host == "" {
			return "", fmt.Errorf("%w: missing host", ErrInvalidURL)
		}
		return normalizeHostPort(u.Host, strings.ToLower(u.Scheme))
	}

	if strings.HasPrefix(rawWithScheme, "//") {
		rawWithScheme = "https:" + rawWithScheme
		scheme = "https"
	} else {
		rawWithScheme = "//" + rawWithScheme
	}

	u, err := url.Parse(rawWithScheme)
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrInvalidURL, err)
	}
	if u.Host == "" {
		return "", fmt.Errorf("%w: missing host", ErrInvalidURL)
	}
	return normalizeHostPort(u.Host, scheme)
}

// normalizeHostPort splits hostname and port, validates and lowercases the hostname,
// strips default ports for the given scheme, and returns "hostname" or "hostname:port".
func normalizeHostPort(hostWithPort, scheme string) (string, error) {
	hostname, port, err := net.SplitHostPort(hostWithPort)
	if err != nil {
		hostname = hostWithPort
		port = ""
		if strings.HasPrefix(hostname, "[") && strings.HasSuffix(hostname, "]") {
			hostname = strings.Trim(hostname, "[]")
		}
	} else {
		p, portErr := strconv.Atoi(port)
		if portErr != nil || p <= 0 || p > 65535 {
			return "", fmt.Errorf("invalid port %q", port)
		}
		if isDefaultPort(scheme, p) {
			port = ""
		}
	}

	hostname = strings.ToLower(hostname)
	hostname = strings.TrimSuffix(hostname, ".")

	if hostname == "" {
		return "", errors.New("empty hostname")
	}

	// Validate IP or domain name
	ip := net.ParseIP(hostname)
	if ip != nil {
		if ip.To4() == nil {
			// IPv6
			if port != "" {
				return fmt.Sprintf("[%s]:%s", hostname, port), nil
			}
			return fmt.Sprintf("[%s]", hostname), nil
		}
		if port != "" {
			return fmt.Sprintf("%s:%s", hostname, port), nil
		}
		return hostname, nil
	}

	// Hostname validation
	for _, r := range hostname {
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '.' && r != '-' && r != '_' {
			return "", fmt.Errorf("invalid character %q in hostname", r)
		}
	}

	if port != "" {
		return fmt.Sprintf("%s:%s", hostname, port), nil
	}
	return hostname, nil
}

// isDefaultPort returns true if port matches the default port for the scheme.
func isDefaultPort(scheme string, port int) bool {
	switch strings.ToLower(scheme) {
	case "http", "ws":
		return port == 80
	case "https", "wss":
		return port == 443
	case "ssh", "sftp":
		return port == 22
	case "ftp":
		return port == 21
	case "":
		return port == 80 || port == 443
	default:
		return false
	}
}

// SameHost reports whether two URL or host strings normalize to the same host.
func SameHost(a, b string) bool {
	h1, err1 := NormalizeHost(a)
	if err1 != nil {
		return false
	}
	h2, err2 := NormalizeHost(b)
	if err2 != nil {
		return false
	}
	return h1 == h2
}

// ExtractHostsFromData extracts all normalized hosts from the "url" field(s) of an entry's data map.
func ExtractHostsFromData(data map[string]any) []string {
	if len(data) == 0 {
		return nil
	}
	val, ok := data[URLKey]
	if !ok || val == nil {
		return nil
	}

	seen := make(map[string]struct{})
	var hosts []string

	addHost := func(s string) {
		s = strings.TrimSpace(s)
		if s == "" {
			return
		}
		h, err := NormalizeHost(s)
		if err != nil || h == "" {
			return
		}
		if _, exists := seen[h]; !exists {
			seen[h] = struct{}{}
			hosts = append(hosts, h)
		}
	}

	switch v := val.(type) {
	case string:
		addHost(v)
	case []string:
		for _, s := range v {
			addHost(s)
		}
	case []any:
		for _, item := range v {
			if s, ok := item.(string); ok {
				addHost(s)
			}
		}
	}

	sort.Strings(hosts)
	return hosts
}
