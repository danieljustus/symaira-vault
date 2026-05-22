package apitemplates

import (
	"testing"
)

func TestIsPrivateHost_LoopbackIPv4(t *testing.T) {
	if !isPrivateHost("127.0.0.1") {
		t.Error("expected 127.0.0.1 to be private")
	}
}

func TestIsPrivateHost_LoopbackIPv6(t *testing.T) {
	if !isPrivateHost("::1") {
		t.Error("expected ::1 to be private")
	}
}

func TestIsPrivateHost_LinkLocalIPv4(t *testing.T) {
	if !isPrivateHost("169.254.169.254") {
		t.Error("expected 169.254.169.254 to be private")
	}
}

func TestIsPrivateHost_RFC1918_10(t *testing.T) {
	if !isPrivateHost("10.0.0.1") {
		t.Error("expected 10.0.0.1 to be private")
	}
}

func TestIsPrivateHost_RFC1918_172(t *testing.T) {
	if !isPrivateHost("172.16.0.1") {
		t.Error("expected 172.16.0.1 to be private")
	}
}

func TestIsPrivateHost_RFC1918_192(t *testing.T) {
	if !isPrivateHost("192.168.1.1") {
		t.Error("expected 192.168.1.1 to be private")
	}
}

func TestIsPrivateHost_Localhost(t *testing.T) {
	if !isPrivateHost("localhost") {
		t.Error("expected localhost to be private")
	}
}

func TestIsPrivateHost_LocalhostWithPort(t *testing.T) {
	if !isPrivateHost("localhost:8080") {
		t.Error("expected localhost:8080 to be private")
	}
}

func TestIsPrivateHost_PublicHost(t *testing.T) {
	if isPrivateHost("api.github.com") {
		t.Error("expected api.github.com to not be private")
	}
}

func TestIsPrivateHost_PublicIP(t *testing.T) {
	if isPrivateHost("8.8.8.8") {
		t.Error("expected 8.8.8.8 to not be private")
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
	_, err := parseTemplate("test", yaml)
	if err != nil {
		t.Fatalf("unexpected error with allow_private: %v", err)
	}
}
