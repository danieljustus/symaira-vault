package cmd

import (
	"os"
	"path/filepath"
	"testing"
)

func TestApprovalTLSCertFileUsesConfiguredCertificate(t *testing.T) {
	dir := t.TempDir()
	customCert := filepath.Join(dir, "custom-server.crt")
	customKey := filepath.Join(dir, "custom-server.key")
	config := "mcp:\n  tls_cert_file: " + customCert + "\n  tls_key_file: " + customKey + "\n"
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := approvalTLSCertFile(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got != customCert {
		t.Fatalf("approvalTLSCertFile() = %q, want configured certificate %q", got, customCert)
	}
	if _, err := os.Stat(filepath.Join(dir, "mcp-server.crt")); !os.IsNotExist(err) {
		t.Fatalf("generated certificate exists despite configured certificate: %v", err)
	}
}

func TestApprovalTLSCertFileRejectsMTLSWithoutLocalClientIdentity(t *testing.T) {
	dir := t.TempDir()
	config := "mcp:\n  mtls_enabled: true\n"
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := approvalTLSCertFile(dir)
	if err == nil {
		t.Fatal("approvalTLSCertFile() error = nil, want mTLS configuration error")
	}
	const want = "approval CLI cannot connect while MCP.mtls_enabled=true because no local approval client certificate is configured; use an enrolled approval device instead"
	if got := err.Error(); got != want {
		t.Fatalf("approvalTLSCertFile() error = %q, want %q", got, want)
	}
}
