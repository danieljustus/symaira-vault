package cli

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRuntimeTLSConfigPreservesEffectiveApprovalIdentityWithoutKeyMaterial(t *testing.T) {
	dir := t.TempDir()
	if err := SaveRuntimeTLSConfig(dir, "/tmp/server.crt", "/tmp/client-ca.crt", "/tmp/approval.crt", "/tmp/approval.key", true); err != nil {
		t.Fatal(err)
	}
	got, ok := LoadRuntimeTLSConfig(dir)
	if !ok || !got.ClientAuthRequired || got.ClientCertificate != "/tmp/approval.crt" || got.ClientKey != "/tmp/approval.key" || got.ClientCAFile != "/tmp/client-ca.crt" {
		t.Fatalf("runtime TLS config = %#v, ok=%v", got, ok)
	}
	data, err := os.ReadFile(filepath.Join(dir, RuntimeTLSFileName))
	if err != nil {
		t.Fatal(err)
	}
	if string(data) == "" || string(data) == "private" {
		t.Fatal("runtime TLS metadata unexpectedly contains key material")
	}
}
