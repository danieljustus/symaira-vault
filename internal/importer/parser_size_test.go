package importer

import (
	"strings"
	"testing"
)

func TestCSVAndBitwardenParsersAcceptInputOver100MiB(t *testing.T) {
	const limit = 100 * 1024 * 1024
	largeField := strings.Repeat("x", limit+1)
	csv := "title,username,password,url,notes,otp,name,note,OTPAuth,ignored\nentry,user,pw,https://example.test,n,,entry,n,," + largeField + "\n"
	for _, format := range []Format{FormatCSV, FormatApple, FormatChrome, FormatFirefox} {
		t.Run(string(format), func(t *testing.T) {
			imp, err := New(format)
			if err != nil {
				t.Fatal(err)
			}
			entries, err := imp.Parse(strings.NewReader(csv))
			if err != nil {
				t.Fatalf("parser rejected %d-byte input: %v", len(csv), err)
			}
			if len(entries) != 1 {
				t.Fatalf("got %d entries, want 1", len(entries))
			}
		})
	}

	var input strings.Builder
	input.Grow(limit + 128)
	input.WriteString(`{"items":[{"type":1,"name":"entry","notes":"`)
	input.WriteString(largeField)
	input.WriteString(`"}]}`)
	entries, err := (&bitwardenImporter{}).Parse(strings.NewReader(input.String()))
	if err != nil {
		t.Fatalf("Bitwarden parser rejected %d-byte input: %v", input.Len(), err)
	}
	if len(entries) != 1 || len(entries[0].Data[bitwardenFieldNotes].(string)) != limit+1 {
		t.Fatalf("Bitwarden parser did not retain the large notes field")
	}
}
