package importer

import (
	"archive/zip"
	"bytes"
	"os"
	"reflect"
	"testing"
)

// FuzzCSVImporterParse verifies the CSV parser handles arbitrary input without panic.
func FuzzCSVImporterParse(f *testing.F) {
	csvFixture, err := os.ReadFile("../../testdata/importer/csv/sample.csv")
	if err != nil {
		f.Fatalf("read csv fixture: %v", err)
	}
	f.Add(csvFixture)
	f.Add([]byte("title,username,password\nExample,user,secret\n"))
	f.Add([]byte(""))
	f.Add([]byte("header only,no data\n"))
	f.Add([]byte("a,b\n1,2\n,\n\n"))

	f.Fuzz(func(t *testing.T, data []byte) {
		entries, err := NewCSV("").Parse(bytes.NewReader(data))

		entries2, err2 := NewCSV("").Parse(bytes.NewReader(data))
		if (err == nil) != (err2 == nil) {
			t.Errorf("deterministic error mismatch")
		}
		if len(entries) != len(entries2) {
			t.Errorf("deterministic length mismatch: %d vs %d", len(entries), len(entries2))
		}

		if err == nil {
			for i, entry := range entries {
				if entry.Data == nil {
					t.Errorf("entry[%d].Data is nil", i)
				}
			}
		}
	})
}

// FuzzBitwardenImporterParse verifies the Bitwarden JSON parser handles arbitrary input without panic.
func FuzzBitwardenImporterParse(f *testing.F) {
	bwFixture, err := os.ReadFile("../../testdata/importer/bitwarden/sample.json")
	if err != nil {
		f.Fatalf("read bitwarden fixture: %v", err)
	}
	f.Add(bwFixture)
	f.Add([]byte(`{"folders":[],"items":[]}`))
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"items":[{"type":1,"name":"Test","login":{"username":"u","password":"p"}}]}`))
	f.Add([]byte(""))
	f.Add([]byte("not json"))

	f.Fuzz(func(t *testing.T, data []byte) {
		entries, err := (&bitwardenImporter{}).Parse(bytes.NewReader(data))

		entries2, err2 := (&bitwardenImporter{}).Parse(bytes.NewReader(data))
		if (err == nil) != (err2 == nil) {
			t.Errorf("deterministic error mismatch")
		}
		if len(entries) != len(entries2) {
			t.Errorf("deterministic length mismatch: %d vs %d", len(entries), len(entries2))
		}

		if err == nil {
			for i, entry := range entries {
				if entry.Data == nil {
					t.Errorf("entry[%d].Data is nil", i)
				}
			}
		}
	})
}

// FuzzOnePUXImporterParse verifies the 1Password UX parser handles arbitrary input without panic.
func FuzzOnePUXImporterParse(f *testing.F) {
	opFixture, err := os.ReadFile("../../testdata/importer/onepux/sample.1pux")
	if err != nil {
		f.Fatalf("read 1pux fixture: %v", err)
	}
	f.Add(opFixture)

	min1PUX := fuzzOnePUXZip(nil, `{"accounts":[{"vaults":[{"items":[{"categoryUuid":"001","title":"Test","details":{"loginFields":[{"designation":"username","value":"u"},{"designation":"password","value":"p"}]}}]}]}]}`)
	f.Add(min1PUX)

	f.Add([]byte("not a zip"))
	f.Add([]byte(""))
	f.Add([]byte("PK\x03\x04"))

	f.Fuzz(func(t *testing.T, data []byte) {
		entries, err := (&onePUXImporter{}).Parse(bytes.NewReader(data))

		entries2, err2 := (&onePUXImporter{}).Parse(bytes.NewReader(data))
		if (err == nil) != (err2 == nil) {
			t.Errorf("deterministic error mismatch")
		}
		if len(entries) != len(entries2) {
			t.Errorf("deterministic length mismatch: %d vs %d", len(entries), len(entries2))
		}

		if err == nil {
			for i, entry := range entries {
				if entry.Data == nil {
					t.Errorf("entry[%d].Data is nil", i)
				}
			}
		}
	})
}

// FuzzParsePassEntry verifies the pass entry parser handles arbitrary input without panic.
func FuzzParsePassEntry(f *testing.F) {
	f.Add("secret\n")
	f.Add("work-aws-secret\nurl: https://aws.amazon.com\nusername: admin@company.com\notpauth://totp/Amazon?secret=JBSWY3DPEHPK3PXP\n")
	f.Add("secret\r\nfirst note line\r\nsecond note line\r\n")
	f.Add("")
	f.Add("only password no newline")
	f.Add("password\nurl: \nusername: \n")
	f.Add("p\nurl:http://example.com\n")
	f.Add("p\n..\n../secrets\n")

	f.Fuzz(func(t *testing.T, content string) {
		data, _ := parsePassEntry(content)

		if _, ok := data["password"]; !ok {
			t.Errorf("password key missing in result")
		}
		if data == nil {
			t.Errorf("parsePassEntry returned nil map")
		}
	})
}

// FuzzParseTOTP verifies the TOTP normalizer handles arbitrary input without
// panic, including malformed otpauth URIs.
func FuzzParseTOTP(f *testing.F) {
	f.Add("JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP")
	f.Add("otpauth://totp/Example:user@example.com?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP&issuer=Example")
	f.Add("otpauth://totp/Example?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP&algorithm=SHA256&digits=8&period=60")
	f.Add("otpauth://hotp/Example?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP")
	f.Add("otpauth://totp/Example")
	f.Add("otpauth://totp/Exa mple?secret=X")
	f.Add("otpauth://totp/Example?secret=not-base32!!")
	f.Add("otpauth://totp/Example?digits=abc")
	f.Add("")
	f.Add("not base32 at all")

	f.Fuzz(func(t *testing.T, value string) {
		result, err := ParseTOTP(value)

		result2, err2 := ParseTOTP(value)
		if (err == nil) != (err2 == nil) {
			t.Errorf("deterministic error mismatch")
		}
		if err == nil && !reflect.DeepEqual(result, result2) {
			t.Errorf("deterministic result mismatch")
		}
		if err == nil {
			if result["secret"] == "" {
				t.Errorf("secret empty for %q", value)
			}
		}
	})
}

// FuzzNormalizePath verifies path normalization handles arbitrary input without panic.
func FuzzNormalizePath(f *testing.F) {
	f.Add("github.com/user")
	f.Add("  /work/aws/  ")
	f.Add("Bank Checking")
	f.Add("../secrets/..")
	f.Add(`Bank "Checking"`)
	f.Add("")
	f.Add("/")
	f.Add("a/../b")
	f.Add("file:name")
	f.Add("spaces and .. dots")

	f.Fuzz(func(t *testing.T, path string) {
		_ = NormalizePath(path)
	})
}

// FuzzParseMapping verifies the mapping parser handles arbitrary input without panic.
func FuzzParseMapping(f *testing.F) {
	f.Add("title=Name, username=Login, password=Secret, otp=Authenticator")
	f.Add("")
	f.Add("title=Name,password")
	f.Add("=Name")
	f.Add("title=")
	f.Add("a=b")
	f.Add("a=b,c=d,e=f")
	f.Add(" spaces = values , more = data ")

	f.Fuzz(func(t *testing.T, mapping string) {
		result, err := ParseMapping(mapping)

		result2, err2 := ParseMapping(mapping)
		if (err == nil) != (err2 == nil) {
			t.Errorf("deterministic error mismatch")
		}
		if err == nil && !reflect.DeepEqual(result, result2) {
			t.Errorf("deterministic result mismatch")
		}

		if mapping == "" && (result != nil || err != nil) {
			t.Errorf("empty mapping should return nil, nil")
		}
	})
}

func fuzzOnePUXZip(t testing.TB, exportJSON string) []byte {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.Create("export.json")
	if err != nil {
		if t != nil {
			t.Fatalf("create export.json in zip: %v", err)
		}
		panic(err)
	}
	if _, err := w.Write([]byte(exportJSON)); err != nil {
		if t != nil {
			t.Fatalf("write export.json in zip: %v", err)
		}
		panic(err)
	}
	if err := zw.Close(); err != nil {
		if t != nil {
			t.Fatalf("close zip: %v", err)
		}
		panic(err)
	}
	return buf.Bytes()
}
