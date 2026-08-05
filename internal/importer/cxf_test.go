package importer

import (
	"archive/zip"
	"bytes"
	"strings"
	"testing"

	vaultpkg "github.com/danieljustus/symaira-vault/internal/vault"
)

// cxfTestPayload is a CXF document exercising the supported credential
// types: a basic-auth + totp item inside a collection, a passkey item, a
// note item, an ssh-key item and a bare (collection-less) totp item.
const cxfTestPayload = `{
  "version": {"major": 1, "minor": 0},
  "exporterRpId": "test.exporter.example",
  "exporterDisplayName": "Test Exporter",
  "timestamp": 1705228800,
  "accounts": [
    {
      "id": "YWNjb3VudDE",
      "username": "jane_smith",
      "email": "jane.smith@example.com",
      "collections": [
        {
          "id": "Y29sbGVjdGlvbjE",
          "title": "Work",
          "items": [{"item": "aXRlbTEx"}]
        }
      ],
      "items": [
        {
          "id": "aXRlbTEx",
          "title": "GitHub",
          "scope": {"urls": ["https://github.com/login", "https://github.com/"], "androidApps": []},
          "tags": ["development", "git"],
          "credentials": [
            {
              "type": "basic-auth",
              "username": {"fieldType": "string", "value": "user@example.com", "label": "Username"},
              "password": {"fieldType": "concealed-string", "value": "mysecretpassword", "label": "Password"}
            },
            {
              "type": "totp",
              "secret": "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP",
              "period": 30,
              "digits": 6,
              "issuer": "GitHub",
              "algorithm": "sha256",
              "username": "user@example.com"
            }
          ]
        },
        {
          "id": "aXRlbTIy",
          "title": "WebAuthn.io",
          "credentials": [
            {
              "type": "passkey",
              "credentialId": "Y3JlZGVudGlhbElkRXhhbXBsZQ",
              "rpId": "webauthn.io",
              "username": "johndoe",
              "userDisplayName": "John Doe",
              "userHandle": "cnEzaNHWcYK3coWZjvoaV1Hj9gnI12mKe2dL2HZVFlY",
              "key": "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgARu_0sCt20EpgVxb4Puq3Ga5VVLpuTY75ngvZlyq3X6hRANCAASmdk1xLsK0oOlhxIPp0d1ZuS0sT9nf6BZtSelhqvLBW0fOL33l_bXgsr_STUHjCLn8l6gcRJwe7OQvbQubZ1dY"
            }
          ]
        },
        {
          "id": "aXRlbTMz",
          "title": "Home alarm",
          "credentials": [
            {"type": "note", "content": {"fieldType": "string", "value": "some instructions to enable/disable the alarm", "label": "alarm"}}
          ]
        },
        {
          "id": "aXRlbTQ0",
          "title": "SSH Key",
          "credentials": [
            {
              "type": "ssh-key",
              "keyType": "ssh-rsa",
              "privateKey": "dGVzdC1rZXktbWF0ZXJpYWw",
              "keyComment": "Work SSH Key"
            }
          ]
        },
        {
          "id": "aXRlbTU1",
          "title": "AWS",
          "credentials": [
            {
              "type": "totp",
              "secret": "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP",
              "period": 30,
              "digits": 6,
              "issuer": "Amazon",
              "algorithm": "sha1"
            }
          ]
        }
      ]
    }
  ]
}`

func TestCXFImporterParse(t *testing.T) {
	data := cxfZip(t, map[string]string{"cxf.json": cxfTestPayload})
	entries, err := (&cxfImporter{}).Parse(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if len(entries) != 5 {
		t.Fatalf("Parse() returned %d entries, want 5", len(entries))
	}

	github := findEntry(t, entries, "Work/GitHub")
	assertStringField(t, github.Data, "username", "user@example.com")
	assertStringField(t, github.Data, "password", "mysecretpassword")
	assertStringField(t, github.Data, "url", "https://github.com/login")
	assertStringSliceField(t, github.Data, "urls", []string{"https://github.com/login", "https://github.com/"})
	assertStringSliceField(t, github.Data, "tags", []string{"development", "git"})
	assertCXFTOTP(t, github.Data, "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP", "SHA256", float64(6), float64(30))

	webauthn := findEntry(t, entries, "WebAuthn.io")
	assertCXFPasskey(t, webauthn.Data, "webauthn.io")

	alarm := findEntry(t, entries, "Home-alarm")
	assertStringField(t, alarm.Data, "notes", "some instructions to enable/disable the alarm")

	ssh := findEntry(t, entries, "SSH-Key")
	gotKey, ok := ssh.Data["private_key"].(string)
	if !ok {
		t.Fatalf("data[private_key] = %#v, want string", ssh.Data["private_key"])
	}
	if !strings.Contains(gotKey, "-----BEGIN PRIVATE KEY-----") {
		t.Errorf("private_key = %q, want PKCS#8 PEM frame", gotKey)
	}
	if ssh.SecretMetadata == nil || ssh.SecretMetadata.Type != vaultpkg.SecretTypeSSHKey {
		t.Errorf("SecretMetadata = %#v, want SSH key type", ssh.SecretMetadata)
	}

	aws := findEntry(t, entries, "AWS")
	assertCXFTOTP(t, aws.Data, "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP", "SHA1", float64(6), float64(30))
}

func TestCXFImporterPicksPayloadJSON(t *testing.T) {
	junk := `{"version": {"major": 1, "minor": 0}}`
	payload := cxfTestPayload

	tests := []struct {
		name  string
		files map[string]string
	}{
		{
			name:  "cxf.json wins over other json entries",
			files: map[string]string{"manifest.json": junk, "nested/cxf.json": payload},
		},
		{
			name:  "largest json entry when no preferred name",
			files: map[string]string{"a.json": junk, "export.json": payload},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entries, err := (&cxfImporter{}).Parse(bytes.NewReader(cxfZip(t, tt.files)))
			if err != nil {
				t.Fatalf("Parse() error = %v", err)
			}
			if len(entries) != 5 {
				t.Fatalf("Parse() returned %d entries, want 5 (payload not found)", len(entries))
			}
		})
	}
}

func TestCXFImporterErrors(t *testing.T) {
	t.Run("not a zip", func(t *testing.T) {
		_, err := (&cxfImporter{}).Parse(strings.NewReader("this is not a zip archive"))
		if err == nil {
			t.Fatal("expected error for non-zip input, got nil")
		}
	})

	t.Run("zip without json document", func(t *testing.T) {
		data := cxfZip(t, map[string]string{"readme.txt": "hello"})
		_, err := (&cxfImporter{}).Parse(bytes.NewReader(data))
		if err == nil {
			t.Fatal("expected error for zip without JSON, got nil")
		}
		if !strings.Contains(err.Error(), "no CXF JSON document") {
			t.Errorf("error = %v, want missing JSON document error", err)
		}
	})

	t.Run("invalid json document", func(t *testing.T) {
		data := cxfZip(t, map[string]string{"cxf.json": "{not json"})
		_, err := (&cxfImporter{}).Parse(bytes.NewReader(data))
		if err == nil {
			t.Fatal("expected error for invalid JSON, got nil")
		}
	})
}

func TestCXFImporterSkipsUnsupportedCredentials(t *testing.T) {
	payload := `{
	  "version": {"major": 1, "minor": 0},
	  "accounts": [{
	    "id": "YWNjb3VudDI",
	    "items": [
	      {
	        "id": "aXRlbTY2",
	        "title": "Mixed",
	        "credentials": [
	          {"type": "address", "streetAddress": {"fieldType": "string", "value": "123 Main Street"}},
	          {"type": "file", "id": "VGVzdEZpbGVJRA", "name": "example.pdf", "decryptedSize": 10, "integrityHash": "aGFzaA"},
	          {"type": "basic-auth", "username": {"value": "u"}, "password": {"value": "p"}}
	        ]
	      },
	      {
	        "id": "aXRlbTc3",
	        "title": "Only Address",
	        "credentials": [{"type": "address", "city": {"fieldType": "string", "value": "Springfield"}}]
	      }
	    ]
	  }]
	}`

	entries, err := (&cxfImporter{}).Parse(bytes.NewReader(cxfZip(t, map[string]string{"cxf.json": payload})))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("Parse() returned %d entries, want 1 (address-only item must be skipped)", len(entries))
	}

	entry := entries[0]
	if entry.Path != "Mixed" {
		t.Errorf("path = %q, want Mixed", entry.Path)
	}
	assertStringField(t, entry.Data, "username", "u")
	assertStringField(t, entry.Data, "password", "p")
	joined := strings.Join(entry.Warnings, "|")
	if !strings.Contains(joined, "address") || !strings.Contains(joined, "file") {
		t.Errorf("warnings = %v, want skipped notes for address and file credentials", entry.Warnings)
	}
}

func TestCXFImporterDraftStyleCredentials(t *testing.T) {
	// Draft-era exports used CamelCase type names and bare string field
	// values instead of EditableField objects.
	payload := `{
	  "version": {"major": 1, "minor": 0},
	  "accounts": [{
	    "id": "YWNjb3VudDM",
	    "items": [{
	      "id": "aXRlbTg4",
	      "title": "Draft",
	      "credentials": [
	        {"type": "BasicAuth", "username": "legacy-user", "password": "legacy-pass", "urls": ["https://example.com"]},
	        {"type": "Cryptographic-key", "privateKeyPem": "-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n-----END OPENSSH PRIVATE KEY-----\n"}
	      ]
	    }]
	  }]
	}`

	entries, err := (&cxfImporter{}).Parse(bytes.NewReader(cxfZip(t, map[string]string{"cxf.json": payload})))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("Parse() returned %d entries, want 1", len(entries))
	}

	entry := entries[0]
	assertStringField(t, entry.Data, "username", "legacy-user")
	assertStringField(t, entry.Data, "password", "legacy-pass")
	assertStringField(t, entry.Data, "url", "https://example.com")
	gotKey, ok := entry.Data["private_key"].(string)
	if !ok {
		t.Fatalf("data[private_key] = %#v, want string", entry.Data["private_key"])
	}
	if !strings.Contains(gotKey, "-----BEGIN OPENSSH PRIVATE KEY-----") {
		t.Errorf("private_key = %q, want PEM passthrough", gotKey)
	}
	if entry.SecretMetadata == nil || entry.SecretMetadata.Type != vaultpkg.SecretTypeSSHKey {
		t.Errorf("SecretMetadata = %#v, want SSH key type", entry.SecretMetadata)
	}
}

func TestCXFImporterTOTPUTIPassthrough(t *testing.T) {
	payload := `{
	  "version": {"major": 1, "minor": 0},
	  "accounts": [{
	    "id": "YWNjb3VudDQ",
	    "items": [{
	      "id": "aXRlbTk5",
	      "title": "URI TOTP",
	      "credentials": [
	        {"type": "totp", "secret": "otpauth://totp/Example?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP&algorithm=SHA512&digits=8&period=45"}
	      ]
	    }]
	  }]
	}`

	entries, err := (&cxfImporter{}).Parse(bytes.NewReader(cxfZip(t, map[string]string{"cxf.json": payload})))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("Parse() returned %d entries, want 1", len(entries))
	}
	assertCXFTOTP(t, entries[0].Data, "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP", "SHA512", float64(8), float64(45))
}

func TestCXFImporterInvalidTOTPWarning(t *testing.T) {
	// The 16-character secret decodes to 10 bytes, below the 16-byte minimum
	// enforced by crypto.ValidateTOTPSecret, so it must be skipped with a
	// per-entry warning instead of writing an unusable secret. The item's
	// basic-auth credential still imports.
	payload := `{
	  "version": {"major": 1, "minor": 0},
	  "accounts": [{
	    "id": "YWNjb3VudDU",
	    "items": [{
	      "id": "aXRlbTEwMA",
	      "title": "Broken TOTP",
	      "credentials": [
	        {"type": "basic-auth", "username": {"value": "user"}, "password": {"value": "pass"}},
	        {"type": "totp", "secret": "JBSWY3DPEHPK3PXP", "period": 30, "digits": 6, "algorithm": "sha1"}
	      ]
	    }]
	  }]
	}`

	entries, err := (&cxfImporter{}).Parse(bytes.NewReader(cxfZip(t, map[string]string{"cxf.json": payload})))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("Parse() returned %d entries, want 1", len(entries))
	}
	if _, ok := entries[0].Data["totp"]; ok {
		t.Fatal("entry unexpectedly contains TOTP data for an invalid secret")
	}
	if len(entries[0].Warnings) == 0 {
		t.Fatal("entry should carry a TOTP warning for the invalid secret")
	}
}

func cxfZip(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, content := range files {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatalf("create %s in zip: %v", name, err)
		}
		if _, err := w.Write([]byte(content)); err != nil {
			t.Fatalf("write %s in zip: %v", name, err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("close zip: %v", err)
	}
	return buf.Bytes()
}

func assertCXFTOTP(t *testing.T, data map[string]any, secret, algorithm string, digits, period float64) {
	t.Helper()
	totp, ok := data["totp"].(map[string]any)
	if !ok {
		t.Fatalf("data[totp] = %#v, want map", data["totp"])
	}
	if got := totp["secret"]; got != secret {
		t.Errorf("totp[secret] = %v, want %s", got, secret)
	}
	if got := totp["algorithm"]; got != algorithm {
		t.Errorf("totp[algorithm] = %v, want %s", got, algorithm)
	}
	if got := totp["digits"]; got != digits {
		t.Errorf("totp[digits] = %v, want %v", got, digits)
	}
	if got := totp["period"]; got != period {
		t.Errorf("totp[period] = %v, want %v", got, period)
	}
}

func assertCXFPasskey(t *testing.T, data map[string]any, rpID string) {
	t.Helper()
	pk, ok := data["passkey"].(map[string]any)
	if !ok {
		t.Fatalf("data[passkey] = %#v, want map", data["passkey"])
	}
	if got := pk["rpId"]; got != rpID {
		t.Errorf("passkey[rpId] = %v, want %s", got, rpID)
	}
	if got := pk["credentialId"]; got != "Y3JlZGVudGlhbElkRXhhbXBsZQ" {
		t.Errorf("passkey[credentialId] = %v, want fixture credential id", got)
	}
	if got, _ := pk["key"].(string); got == "" {
		t.Error("passkey[key] is empty, want private key material")
	}
}
