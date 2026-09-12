package cmd

import (
	"os"
	"path/filepath"
	"testing"

	cli "github.com/danieljustus/symaira-vault/internal/cli"
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

	got, err := approvalTLSCertFile(dir)
	if err != nil {
		t.Fatalf("approvalTLSCertFile() error = %v, want generated server certificate", err)
	}
	if got == "" {
		t.Fatal("approvalTLSCertFile() returned an empty certificate path")
	}
}

func TestApprovalTLSCertFilePrefersRunningMTLSState(t *testing.T) {
	dir := t.TempDir()
	customCert := filepath.Join(t.TempDir(), "running-server.crt")
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte("mcp:\n  mtls_enabled: true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := cli.SaveRuntimeTLSCert(dir, customCert, false); err != nil {
		t.Fatal(err)
	}
	got, err := approvalTLSCertFile(dir)
	if err != nil {
		t.Fatalf("approvalTLSCertFile() error = %v, want runtime state to win", err)
	}
	if got != customCert {
		t.Fatalf("approvalTLSCertFile() = %q, want runtime certificate %q", got, customCert)
	}
}

func TestApprovalTLSCertFileUsesRunningServerOverride(t *testing.T) {
	dir := t.TempDir()
	customCert := filepath.Join(t.TempDir(), "flag-server.crt")
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte("mcp:\n  tls_cert_file: config.crt\n  tls_key_file: config.key\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := cli.SaveRuntimeTLSCert(dir, customCert); err != nil {
		t.Fatal(err)
	}
	got, err := approvalTLSCertFile(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got != customCert {
		t.Fatalf("approvalTLSCertFile() = %q, want runtime override %q", got, customCert)
	}
}
