// Package apitemplates provides API request templates with credential isolation.
// Templates define how to authenticate and communicate with external APIs
// without agents ever seeing the raw credential values.
package apitemplates

import (
	"embed"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

//go:embed builtin/*.yaml
var builtinFS embed.FS

// AuthType defines the authentication mechanism for an API template.
type AuthType string

const (
	// AuthBearer sends credentials via Authorization: Bearer *** header.
	AuthBearer AuthType = "bearer"
	// AuthBasic sends credentials via HTTP Basic Auth (base64(username:password)).
	AuthBasic AuthType = "basic"
	// AuthHeader sends credentials via a custom header defined in the vault entry.
	AuthHeader AuthType = "header"
	// AuthQueryParam sends credentials as a URL query parameter.
	AuthQueryParam AuthType = "query_param"
	// AuthNone declares that no auth header is injected; credentials are
	// delivered exclusively through substitutions (path/query/header/body).
	// Templates using it must declare at least one substitution.
	AuthNone AuthType = "none"
)

// SubstitutionSurface names a request location where a substitution
// placeholder is replaced with a credential value.
type SubstitutionSurface string

const (
	// SurfacePath replaces placeholders in the request URL path.
	SurfacePath SubstitutionSurface = "path"
	// SurfaceQuery replaces placeholders in the request URL query string.
	SurfaceQuery SubstitutionSurface = "query"
	// SurfaceHeader replaces placeholders in request header values.
	SurfaceHeader SubstitutionSurface = "header"
	// SurfaceBody replaces placeholders in the request body.
	SurfaceBody SubstitutionSurface = "body"
)

// DefaultSubstitutionSurfaces is applied when a substitution omits "in".
// It mirrors the upstream agent-vault default of path + query.
func DefaultSubstitutionSurfaces() []SubstitutionSurface {
	return []SubstitutionSurface{SurfacePath, SurfaceQuery}
}

// Substitution declares a placeholder that is replaced with a credential
// value from the vault entry before the request leaves symvault. The value
// is resolved from the vault entry field named by Field.
type Substitution struct {
	// Placeholder is the literal text replaced in the request. Rules (ported
	// from the agent-vault broker): at least 4 characters, only RFC 3986
	// unreserved characters [A-Za-z0-9_.~-], at least one alphanumeric, and a
	// mandatory delimiter ("__" or a non-word character) so a short
	// placeholder cannot accidentally rewrite a legitimate URL word.
	Placeholder string `yaml:"placeholder" json:"placeholder"`
	// Field is the vault entry field the credential value is read from.
	Field string `yaml:"field" json:"field"`
	// In lists the surfaces where the placeholder is replaced. When empty,
	// defaults to path + query.
	In []SubstitutionSurface `yaml:"in,omitempty" json:"in,omitempty"`
}

// APITemplate defines how to authenticate and communicate with an external API.
type APITemplate struct {
	// Name is the template identifier (e.g., "github", "openai").
	Name string `yaml:"-" json:"name"`
	// BaseURL is the base URL for the API (e.g., "https://api.github.com").
	BaseURL string `yaml:"base_url" json:"base_url"`
	// AuthType specifies the authentication mechanism.
	AuthType AuthType `yaml:"auth_type" json:"auth_type"`
	// EntryRef is the 1Password op:// vault reference for credential storage.
	EntryRef string `yaml:"entry_ref" json:"entry_ref"`
	// AllowedEndpoints is a list of glob patterns for allowed endpoint paths.
	AllowedEndpoints []string `yaml:"allowed_endpoints" json:"allowed_endpoints"`
	// AllowedMethods is a list of allowed HTTP methods.
	AllowedMethods []string `yaml:"allowed_methods" json:"allowed_methods"`
	// DefaultHeaders are headers to include in every request.
	DefaultHeaders map[string]string `yaml:"default_headers" json:"default_headers,omitempty"`
	// Substitutions replace placeholders in the request path, query, header
	// values or body with credential values from the vault entry.
	Substitutions []Substitution `yaml:"substitutions,omitempty" json:"substitutions,omitempty"`
	// AllowPrivate permits requests to private or local network destinations.
	// It is intentionally opt-in because templates can inject vault credentials.
	AllowPrivate bool `yaml:"allow_private" json:"allow_private,omitempty"`
}

// Validate checks the template's required fields and substitution rules.
// Templates loaded from YAML are validated at parse time; this method lets
// callers and tests validate constructed or modified templates.
func (t *APITemplate) Validate() error {
	if t.Name == "" {
		return fmt.Errorf("template name is required")
	}
	if t.BaseURL == "" {
		return fmt.Errorf("template %q: base_url is required", t.Name)
	}
	parsedURL, err := url.Parse(t.BaseURL)
	if err != nil {
		return fmt.Errorf("template %q: invalid base_url: %w", t.Name, err)
	}
	if IsPrivateHost(parsedURL.Host) && !t.AllowPrivate {
		return fmt.Errorf("template %q: base_url host %q resolves to a private/internal address; set allow_private: true to override", t.Name, parsedURL.Host)
	}
	if t.AuthType == "" {
		return fmt.Errorf("template %q: auth_type is required", t.Name)
	}
	if t.AuthType == AuthNone && len(t.Substitutions) == 0 {
		return fmt.Errorf("template %q: auth_type \"none\" requires at least one substitution", t.Name)
	}
	if t.EntryRef == "" {
		return fmt.Errorf("template %q: entry_ref is required", t.Name)
	}
	return validateSubstitutions(t.Name, t.Substitutions)
}

// templateFile is the on-disk representation of an APITemplate.
type templateFile struct {
	BaseURL          string            `yaml:"base_url"`
	AuthType         AuthType          `yaml:"auth_type"`
	EntryRef         string            `yaml:"entry_ref"`
	AllowedEndpoints []string          `yaml:"allowed_endpoints"`
	AllowedMethods   []string          `yaml:"allowed_methods"`
	DefaultHeaders   map[string]string `yaml:"default_headers"`
	Substitutions    []Substitution    `yaml:"substitutions,omitempty"`
	AllowPrivate     bool              `yaml:"allow_private"`
}

// Load loads a template by name. It checks the user's template directory
// (<vault>/templates/) first, then falls back to embedded built-ins.
func Load(name string, vaultDir string) (*APITemplate, error) {
	if name == "" {
		return nil, fmt.Errorf("template name is required")
	}
	if strings.ContainsAny(name, `/\`) || strings.Contains(name, "..") {
		return nil, fmt.Errorf("invalid template name: %q", name)
	}

	// Check user override directory first
	if vaultDir != "" {
		userPath := filepath.Join(vaultDir, "templates", name+".yaml")
		if _, err := os.Stat(userPath); err == nil {
			return loadFromFile(name, userPath)
		}
	}

	// Fall back to built-in templates
	return loadBuiltin(name)
}

// LoadAll loads all embedded built-in templates.
func LoadAll() ([]*APITemplate, error) {
	var templates []*APITemplate

	// Load built-in templates
	entries, err := builtinFS.ReadDir("builtin")
	if err != nil {
		return nil, fmt.Errorf("read builtin templates: %w", err)
	}

	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".yaml" {
			continue
		}
		name := entry.Name()[:len(entry.Name())-len(".yaml")]
		tmpl, err := loadBuiltin(name)
		if err != nil {
			return nil, fmt.Errorf("load builtin %q: %w", name, err)
		}
		templates = append(templates, tmpl)
	}

	if len(templates) == 0 {
		return nil, fmt.Errorf("no templates found")
	}

	return templates, nil
}

// loadBuiltin loads a built-in template by name.
func loadBuiltin(name string) (*APITemplate, error) {
	data, err := builtinFS.ReadFile(filepath.Join("builtin", name+".yaml"))
	if err != nil {
		return nil, fmt.Errorf("template %q not found", name)
	}
	return parseTemplate(name, data)
}

// loadFromFile loads a template from a file path.
func loadFromFile(name, path string) (*APITemplate, error) {
	data, err := os.ReadFile(path) // #nosec G304 — path constructed from validated name within vault templates dir
	if err != nil {
		return nil, fmt.Errorf("read template file %q: %w", path, err)
	}
	return parseTemplate(name, data)
}

var blockedPrivateRanges = func() []*net.IPNet {
	ranges := []string{
		"127.0.0.0/8",    // Loopback IPv4
		"::1/128",        // Loopback IPv6
		"169.254.0.0/16", // Link-local IPv4
		"fe80::/10",      // Link-local IPv6
		"10.0.0.0/8",     // RFC 1918 private
		"172.16.0.0/12",  // RFC 1918 private
		"192.168.0.0/16", // RFC 1918 private
	}
	var nets []*net.IPNet
	for _, cidr := range ranges {
		_, ipnet, err := net.ParseCIDR(cidr)
		if err != nil {
			panic(fmt.Sprintf("invalid CIDR %q: %v", cidr, err))
		}
		nets = append(nets, ipnet)
	}
	return nets
}()

// IsPrivateIP reports whether ip is a local, private, multicast, or
// otherwise non-routable address that must not receive injected credentials.
func IsPrivateIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsPrivate() || ip.IsMulticast() || ip.IsUnspecified() {
		return true
	}
	for _, blocked := range blockedPrivateRanges {
		if blocked.Contains(ip) {
			return true
		}
	}
	return false
}

// IsPrivateHost reports whether the given host is a loopback, link-local,
// private, multicast, or unspecified address. Hostnames are checked against
// known local names; DNS names are resolved by the request transport at dial
// time so DNS rebinding cannot bypass this check.
func IsPrivateHost(host string) bool {
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}

	if host == "localhost" || host == "localhost.localdomain" {
		return true
	}

	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	return IsPrivateIP(ip)
}

// parseTemplate parses YAML data into an APITemplate.
func parseTemplate(name string, data []byte) (*APITemplate, error) {
	var tf templateFile
	if err := yaml.Unmarshal(data, &tf); err != nil {
		return nil, fmt.Errorf("parse template %q: %w", name, err)
	}

	if tf.BaseURL == "" {
		return nil, fmt.Errorf("template %q: base_url is required", name)
	}
	parsedURL, err := url.Parse(tf.BaseURL)
	if err != nil {
		return nil, fmt.Errorf("template %q: invalid base_url: %w", name, err)
	}
	if IsPrivateHost(parsedURL.Host) && !tf.AllowPrivate {
		return nil, fmt.Errorf("template %q: base_url host %q resolves to a private/internal address; set allow_private: true to override", name, parsedURL.Host)
	}
	if tf.AuthType == "" {
		return nil, fmt.Errorf("template %q: auth_type is required", name)
	}
	if tf.AuthType == AuthNone && len(tf.Substitutions) == 0 {
		return nil, fmt.Errorf("template %q: auth_type \"none\" requires at least one substitution", name)
	}
	if tf.EntryRef == "" {
		return nil, fmt.Errorf("template %q: entry_ref is required", name)
	}
	if err := validateSubstitutions(name, tf.Substitutions); err != nil {
		return nil, err
	}
	for i := range tf.Substitutions {
		if len(tf.Substitutions[i].In) == 0 {
			tf.Substitutions[i].In = DefaultSubstitutionSurfaces()
		}
	}

	return &APITemplate{
		Name:             name,
		BaseURL:          tf.BaseURL,
		AuthType:         tf.AuthType,
		EntryRef:         tf.EntryRef,
		AllowedEndpoints: tf.AllowedEndpoints,
		AllowedMethods:   tf.AllowedMethods,
		DefaultHeaders:   tf.DefaultHeaders,
		Substitutions:    tf.Substitutions,
		AllowPrivate:     tf.AllowPrivate,
	}, nil
}

// validateSubstitutions enforces the placeholder rules ported from the
// agent-vault broker (internal/broker/broker.go): minimum 4 characters, only
// RFC 3986 unreserved characters, at least one alphanumeric, a mandatory
// delimiter ("__" or a non-word character) so a placeholder cannot
// accidentally match a legitimate URL word, and no duplicate placeholders.
func validateSubstitutions(name string, subs []Substitution) error {
	seen := make(map[string]struct{}, len(subs))
	for i, sub := range subs {
		label := fmt.Sprintf("template %q: substitutions[%d]", name, i)
		ph := sub.Placeholder
		if ph == "" {
			return fmt.Errorf("%s: placeholder is required", label)
		}
		if len(ph) < 4 {
			return fmt.Errorf("%s: placeholder %q must be at least 4 characters long", label, ph)
		}
		hasAlnum := false
		hasDelimiter := strings.Contains(ph, "__")
		for _, r := range ph {
			if !isUnreservedRune(r) {
				return fmt.Errorf("%s: placeholder %q contains disallowed character %q (only RFC 3986 unreserved characters [A-Za-z0-9_.~-] are allowed)", label, ph, r)
			}
			if isAlnumRune(r) {
				hasAlnum = true
			} else if !isWordRune(r) {
				hasDelimiter = true
			}
		}
		if !hasAlnum {
			return fmt.Errorf("%s: placeholder %q must contain at least one alphanumeric character", label, ph)
		}
		if !hasDelimiter {
			return fmt.Errorf("%s: placeholder %q must contain a delimiter (\"__\" or a non-word character) so it cannot accidentally match a legitimate URL word", label, ph)
		}
		if _, dup := seen[ph]; dup {
			return fmt.Errorf("%s: duplicate placeholder %q across substitutions", label, ph)
		}
		seen[ph] = struct{}{}
		if sub.Field == "" {
			return fmt.Errorf("%s: field is required for placeholder %q", label, ph)
		}
		for _, surface := range sub.In {
			switch surface {
			case SurfacePath, SurfaceQuery, SurfaceHeader, SurfaceBody:
			default:
				return fmt.Errorf("%s: unsupported substitution surface %q (supported: path, query, header, body)", label, surface)
			}
		}
	}
	return nil
}

func isUnreservedRune(r rune) bool {
	return isAlnumRune(r) || r == '-' || r == '.' || r == '_' || r == '~'
}

func isAlnumRune(r rune) bool {
	return (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')
}

// isWordRune mirrors the regexp \w class ([A-Za-z0-9_]) for the delimiter rule.
func isWordRune(r rune) bool {
	return isAlnumRune(r) || r == '_'
}
