package importer

import (
	"bytes"
	"testing"
)

func TestChromeCSVInvalidUTF8TitlePathsRemainDistinct(t *testing.T) {
	input := []byte("name,url,username,password,note\n\xff,https://one.example,u1,p1,\n\xfe,https://two.example,u2,p2,\n")
	profile, err := NewCSVProfile(FormatChrome, "")
	if err != nil {
		t.Fatalf("NewCSVProfile() error = %v", err)
	}
	entries, err := profile.Parse(bytes.NewReader(input))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("Parse() returned %d entries, want 2", len(entries))
	}
	if !bytes.Equal([]byte(entries[0].Path), []byte{0xff}) || !bytes.Equal([]byte(entries[1].Path), []byte{0xfe}) {
		t.Fatalf("paths = % x and % x, want distinct raw bytes ff and fe", []byte(entries[0].Path), []byte(entries[1].Path))
	}
}
