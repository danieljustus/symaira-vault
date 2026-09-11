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
