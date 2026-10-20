package oracletest

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestEvidenceConfinement(t *testing.T) {
	for _, tc := range []struct {
		generator string
		cases     int
		valid     bool
	}{
		{"tools-call", 4, true}, {"http-initialize", 27, true},
		{"tools-call", 27, false}, {"http-initialize", 4, false},
		{"../tools-call", 4, false}, {"--output", 4, false},
		{"execute-with-secret", 13, false}, {"", 0, false},
	} {
		if _, err := fixtureName(tc.generator, tc.cases); (err == nil) != tc.valid {
			t.Fatalf("generator %q/%d: %v", tc.generator, tc.cases, err)
		}
	}
	owned := t.TempDir()
	root, err := os.OpenRoot(owned)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if err := root.WriteFile("receipt.json", []byte("checked"), 0o600); err != nil {
		t.Fatal(err)
	}
	if data, err := readEvidence(root, "receipt.json"); err != nil || string(data) != "checked" {
		t.Fatalf("owned read: %q, %v", data, err)
	}
	for _, name := range []string{"../receipt.json", filepath.Join(owned, "receipt.json"), ".", "missing"} {
		if _, err := readEvidence(root, name); err == nil {
			t.Fatalf("accepted invalid evidence path %q", name)
		}
	}
	large, err := root.Create("large.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := large.Truncate((16 << 20) + 1); err != nil {
		t.Fatal(err)
	}
	if err := large.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := readEvidence(root, "large.json"); err == nil {
		t.Fatal("accepted oversized evidence")
	}
	// Symlink creation needs privileges on Windows; path/size controls above
	// execute everywhere, and the native Root implementation enforces escape.
	if runtime.GOOS != "windows" {
		outside := t.TempDir()
		if err := os.WriteFile(filepath.Join(outside, "outside.json"), []byte("outside"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := root.Symlink(filepath.Join(outside, "outside.json"), "escape.json"); err != nil {
			t.Fatal(err)
		}
		if _, err := readEvidence(root, "escape.json"); err == nil {
			t.Fatal("accepted symlink escape")
		}
	}
}

func TestProductReceipt(t *testing.T) {
	valid := productReceipt{SourceCommit: "1a815b23c42a6236101c50c22167c639a3018a8e", Passed: true, Cases: 4, Fixtures: 1}
	if err := validateProductReceipt(valid, 4); err != nil {
		t.Fatal(err)
	}
	for _, fault := range []string{"missing", "short-pin", "wrong-pin", "failed", "cases", "fixtures"} {
		product := valid
		switch fault {
		case "missing":
			product = productReceipt{}
		case "short-pin":
			product.SourceCommit = product.SourceCommit[:8]
		case "wrong-pin":
			product.SourceCommit = "24acdb08fcc7021262717aa803d72eb8d151c66a"
		case "failed":
			product.Passed = false
		case "cases":
			product.Cases++
		case "fixtures":
			product.Fixtures++
		}
		if err := validateProductReceipt(product, 4); err == nil {
			t.Fatalf("accepted product receipt fault: %s", fault)
		}
	}
}
