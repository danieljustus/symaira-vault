package apitemplates

import (
	"net"
	"slices"
	"strings"
	"testing"
)

func TestIsPrivateHost_LoopbackIPv4(t *testing.T) {
	if !IsPrivateHost("127.0.0.1") {
		t.Error("expected 127.0.0.1 to be private")
	}
}

func TestIsPrivateHost_LoopbackIPv6(t *testing.T) {
	if !IsPrivateHost("::1") {
		t.Error("expected ::1 to be private")
	}
}

func TestIsPrivateHost_LinkLocalIPv4(t *testing.T) {
	if !IsPrivateHost("169.254.169.254") {
		t.Error("expected 169.254.169.254 to be private")
	}
}

func TestIsPrivateHost_RFC1918_10(t *testing.T) {
	if !IsPrivateHost("10.0.0.1") {
		t.Error("expected 10.0.0.1 to be private")
	}
}

func TestIsPrivateHost_RFC1918_172(t *testing.T) {
	if !IsPrivateHost("172.16.0.1") {
		t.Error("expected 172.16.0.1 to be private")
	}
}

func TestIsPrivateHost_RFC1918_192(t *testing.T) {
	if !IsPrivateHost("192.168.1.1") {
		t.Error("expected 192.168.1.1 to be private")
	}
}

func TestIsPrivateHost_Localhost(t *testing.T) {
	if !IsPrivateHost("localhost") {
		t.Error("expected localhost to be private")
	}
}

func TestIsPrivateHost_LocalhostWithPort(t *testing.T) {
	if !IsPrivateHost("localhost:8080") {
		t.Error("expected localhost:8080 to be private")
	}
}

func TestIsPrivateHost_PublicHost(t *testing.T) {
	if IsPrivateHost("api.github.com") {
		t.Error("expected api.github.com to not be private")
	}
}

func TestIsPrivateHost_PublicIP(t *testing.T) {
	if IsPrivateHost("8.8.8.8") {
		t.Error("expected 8.8.8.8 to not be private")
	}
}

func TestIsPrivateIP_NonRoutableAddresses(t *testing.T) {
	for _, address := range []string{"0.0.0.0", "::", "224.0.0.1", "ff02::1", "fc00::1"} {
		t.Run(address, func(t *testing.T) {
			if !IsPrivateIP(net.ParseIP(address)) {
				t.Errorf("expected %s to be private or non-routable", address)
			}
		})
	}
}

func TestParseTemplate_BlocksPrivateBaseURL(t *testing.T) {
	yaml := []byte(`
base_url: http://169.254.169.254
auth_type: bearer
entry_ref: op://vault/item
`)
	_, err := parseTemplate("test", yaml)
	if err == nil {
		t.Fatal("expected error for private base_url")
	}
}

func TestParseTemplate_BlocksLocalhost(t *testing.T) {
	yaml := []byte(`
base_url: http://localhost:8080
auth_type: bearer
entry_ref: op://vault/item
`)
	_, err := parseTemplate("test", yaml)
	if err == nil {
		t.Fatal("expected error for localhost base_url")
	}
}

func TestParseTemplate_AllowsPublicBaseURL(t *testing.T) {
	yaml := []byte(`
base_url: https://api.github.com
auth_type: bearer
entry_ref: op://vault/item
`)
	_, err := parseTemplate("test", yaml)
	if err != nil {
		t.Fatalf("unexpected error for public base_url: %v", err)
	}
}

func TestParseTemplate_AllowsPrivateWithOverride(t *testing.T) {
	yaml := []byte(`
base_url: http://localhost:8080
auth_type: bearer
entry_ref: op://vault/item
allow_private: true
`)
	tmpl, err := parseTemplate("test", yaml)
	if err != nil {
		t.Fatalf("unexpected error with allow_private: %v", err)
	}
	if !tmpl.AllowPrivate {
		t.Fatal("expected allow_private to be preserved on the loaded template")
	}
}

// --- Substitution validation tests ---

func TestParseTemplate_ValidSubstitutions(t *testing.T) {
	yaml := []byte(`
base_url: https://api.telegram.org/bot__BOT_TOKEN__
auth_type: none
entry_ref: op://vault/item
substitutions:
  - placeholder: __BOT_TOKEN__
    field: credential
    in: [path]
`)
	tmpl, err := parseTemplate("telegram", yaml)
	if err != nil {
		t.Fatalf("parseTemplate() error = %v", err)
	}
	if len(tmpl.Substitutions) != 1 {
		t.Fatalf("Substitutions len = %d, want 1", len(tmpl.Substitutions))
	}
	if tmpl.Substitutions[0].Placeholder != "__BOT_TOKEN__" {
		t.Errorf("Placeholder = %q, want __BOT_TOKEN__", tmpl.Substitutions[0].Placeholder)
	}
	if tmpl.Substitutions[0].Field != "credential" {
		t.Errorf("Field = %q, want credential", tmpl.Substitutions[0].Field)
	}
	if len(tmpl.Substitutions[0].In) != 1 || tmpl.Substitutions[0].In[0] != SurfacePath {
		t.Errorf("In = %v, want [path]", tmpl.Substitutions[0].In)
	}
}

func TestParseTemplate_SubstitutionDefaultsToPathQuery(t *testing.T) {
	yaml := []byte(`
base_url: https://example.com
auth_type: none
entry_ref: op://vault/item
substitutions:
  - placeholder: __API_KEY__
    field: credential
`)
	tmpl, err := parseTemplate("test", yaml)
	if err != nil {
		t.Fatalf("parseTemplate() error = %v", err)
	}
	got := tmpl.Substitutions[0].In
	if len(got) != 2 || got[0] != SurfacePath || got[1] != SurfaceQuery {
		t.Errorf("default In = %v, want [path query]", got)
	}
}

func TestParseTemplate_SubstitutionTooShort(t *testing.T) {
	yaml := []byte(`
base_url: https://example.com
auth_type: none
entry_ref: op://vault/item
substitutions:
  - placeholder: __T
    field: credential
`)
	_, err := parseTemplate("test", yaml)
	if err == nil || !strings.Contains(err.Error(), "at least 4 characters") {
		t.Fatalf("expected minimum-length error, got %v", err)
	}
}

func TestParseTemplate_SubstitutionDisallowedCharacter(t *testing.T) {
	yaml := []byte(`
base_url: https://example.com
auth_type: none
entry_ref: op://vault/item
substitutions:
  - placeholder: __TO{KEN__
    field: credential
`)
	_, err := parseTemplate("test", yaml)
	if err == nil || !strings.Contains(err.Error(), "disallowed character") {
		t.Fatalf("expected disallowed-character error, got %v", err)
	}
}

func TestParseTemplate_SubstitutionNoAlphanumeric(t *testing.T) {
	yaml := []byte(`
base_url: https://example.com
auth_type: none
entry_ref: op://vault/item
substitutions:
  - placeholder: "____"
    field: credential
`)
	_, err := parseTemplate("test", yaml)
	if err == nil || !strings.Contains(err.Error(), "at least one alphanumeric") {
		t.Fatalf("expected alphanumeric error, got %v", err)
	}
}

func TestParseTemplate_SubstitutionNoDelimiter(t *testing.T) {
	// All word characters and no "__" — must be rejected so a short
	// placeholder cannot accidentally match a legitimate URL word.
	yaml := []byte(`
base_url: https://example.com
auth_type: none
entry_ref: op://vault/item
substitutions:
  - placeholder: TOKEN
    field: credential
`)
	_, err := parseTemplate("test", yaml)
	if err == nil || !strings.Contains(err.Error(), "delimiter") {
		t.Fatalf("expected delimiter error, got %v", err)
	}
}

func TestParseTemplate_SubstitutionDuplicatePlaceholder(t *testing.T) {
	yaml := []byte(`
base_url: https://example.com
auth_type: none
entry_ref: op://vault/item
substitutions:
  - placeholder: __API_KEY__
    field: credential
  - placeholder: __API_KEY__
    field: token
`)
	_, err := parseTemplate("test", yaml)
	if err == nil || !strings.Contains(err.Error(), "duplicate placeholder") {
		t.Fatalf("expected duplicate-placeholder error, got %v", err)
	}
}

func TestParseTemplate_SubstitutionUnsupportedSurface(t *testing.T) {
	yaml := []byte(`
base_url: https://example.com
auth_type: none
entry_ref: op://vault/item
substitutions:
  - placeholder: __API_KEY__
    field: credential
    in: [websocket]
`)
	_, err := parseTemplate("test", yaml)
	if err == nil || !strings.Contains(err.Error(), "unsupported substitution surface") {
		t.Fatalf("expected unsupported-surface error, got %v", err)
	}
}

func TestParseTemplate_AuthNoneRequiresSubstitution(t *testing.T) {
	yaml := []byte(`
base_url: https://example.com
auth_type: none
entry_ref: op://vault/item
`)
	_, err := parseTemplate("test", yaml)
	if err == nil || !strings.Contains(err.Error(), "requires at least one substitution") {
		t.Fatalf("expected auth-none substitution error, got %v", err)
	}
}

// --- Built-in catalog tests ---

func TestBuiltinTemplates_AllParseAndValidate(t *testing.T) {
	templates, err := LoadAll()
	if err != nil {
		t.Fatalf("LoadAll() error = %v", err)
	}
	if len(templates) < 5 {
		t.Fatalf("LoadAll() returned %d templates, want at least 5", len(templates))
	}
	for _, tmpl := range templates {
		t.Run(tmpl.Name, func(t *testing.T) {
			if err := tmpl.Validate(); err != nil {
				t.Fatalf("Validate(%q) error = %v", tmpl.Name, err)
			}
		})
	}
}

func TestBuiltinTemplates_NoBlanketMutatingGrant(t *testing.T) {
	// The five original built-ins predate this rule and are intentionally
	// left unchanged; the rule applies to newly added templates.
	newBuiltins := []string{
		"gitlab", "linear", "notion", "stripe", "sentry", "cloudflare",
		"vercel", "resend", "gemini", "openrouter", "npm", "telegram",
	}
	templates, err := LoadAll()
	if err != nil {
		t.Fatalf("LoadAll() error = %v", err)
	}
	for _, tmpl := range templates {
		if !slices.Contains(newBuiltins, tmpl.Name) {
			continue
		}
		t.Run(tmpl.Name, func(t *testing.T) {
			hasRootWildcard := false
			for _, ep := range tmpl.AllowedEndpoints {
				if ep == "/*" || ep == "*" {
					hasRootWildcard = true
					break
				}
			}
			if !hasRootWildcard {
				return
			}
			for _, m := range tmpl.AllowedMethods {
				switch strings.ToUpper(m) {
				case "POST", "PUT", "PATCH", "DELETE":
					t.Errorf("template %q grants root-wildcard endpoint with mutating method %s", tmpl.Name, m)
				}
			}
		})
	}
}
