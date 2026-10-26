// Package oracletest runs ordinary generator tests through the same immutable
// two-reference acceptance path as the native MCP fixture gate.
package oracletest

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

// Check returns the freshly checked historical fixture, never a capture from
// the current product compiled under a historical revision label.
func Check(t *testing.T, generator string, cases int) []byte {
	t.Helper()
	fixture, err := fixtureName(generator, cases)
	if err != nil {
		t.Fatal(err)
	}
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate oracle acceptance helper")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(filename), "../../../.."))
	owned := t.TempDir()
	output := filepath.Join(owned, "evidence")
	files, err := os.OpenRoot(owned)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if closeErr := files.Close(); closeErr != nil {
			t.Errorf("close evidence root: %v", closeErr)
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	// Fixed interpreter/script, no shell. The only variable arguments are an
	// allowlisted generator and a private testing-owned output directory.
	cmd := exec.CommandContext(ctx, "python3", "-B", "scripts/rust-port/mcp_fixture_contract.py")
	if cmd.Err != nil || !filepath.IsAbs(cmd.Path) {
		t.Fatalf("python3 must resolve to an absolute PATH executable: %v", cmd.Err)
	}
	cmd.Args = append(cmd.Args, "--generator", generator, "--output", output)
	cmd.Dir = root
	cmd.Env = append(os.Environ(), "GOTOOLCHAIN=go1.26.6", "GOWORK=off", "GOENV=off")
	log, err := cmd.CombinedOutput()
	t.Log(string(log))
	if err != nil {
		t.Fatalf("two-reference generator acceptance: %v", err)
	}
	data, err := readEvidence(files, "evidence/receipt.json")
	if err != nil {
		t.Fatal(err)
	}
	var receipt struct {
		Passed              bool
		Compiler            struct{ Version string }
		ProductSourceReplay productReceipt `json:"product_source_replay"`
		Lanes               []struct {
			Lane         string
			SourceCommit string `json:"source_commit"`
			Passed       bool
			Cases        int
			Fixtures     int
		}
	}
	if err = json.Unmarshal(data, &receipt); err != nil {
		t.Fatal(err)
	}
	if !receipt.Passed || receipt.Compiler.Version != "go1.26.6" || len(receipt.Lanes) != 2 {
		t.Fatal("missing passing two-reference receipt with actual historical compiler")
	}
	for i, expected := range []struct{ lane, commit string }{
		{"historical", "d1cd0f97ac550bc3020bc86b0514989f8d28d95c"},
		{"corrected", "24acdb08fcc7021262717aa803d72eb8d151c66a"},
	} {
		lane := receipt.Lanes[i]
		if lane.Lane != expected.lane || lane.SourceCommit != expected.commit || !lane.Passed || lane.Cases != cases || lane.Fixtures != 1 {
			t.Fatalf("incomplete %s generator acceptance", expected.lane)
		}
	}
	if err = validateProductReceipt(receipt.ProductSourceReplay, cases); err != nil {
		t.Fatal(err)
	}
	data, err = readEvidence(files, "evidence/historical/"+fixture)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

type productReceipt struct {
	SourceCommit string `json:"source_commit"`
	Passed       bool
	Cases        int
	Fixtures     int
}

func validateProductReceipt(product productReceipt, cases int) error {
	if product.SourceCommit != "58d978bb53a1dc6257b3a0e3154f7bd29fdd3fd9" || !product.Passed || product.Cases != cases || product.Fixtures != 1 {
		return fmt.Errorf("missing passing pinned product-source generator acceptance")
	}
	return nil
}

func fixtureName(generator string, cases int) (string, error) {
	switch {
	case generator == "tools-call" && cases == 4:
		return "tools-call.json", nil
	case generator == "http-initialize" && cases == 27:
		return "http-initialize.json", nil
	default:
		return "", fmt.Errorf("unsupported generator/count: %q/%d", generator, cases)
	}
}

// Root.Open confines reads even if a generated path is replaced by a symlink.
// The size limit bounds both the receipt and the returned fixture allocation.
func readEvidence(root *os.Root, name string) (data []byte, err error) {
	if !fs.ValidPath(name) {
		return nil, fmt.Errorf("invalid evidence path: %q", name)
	}
	file, err := root.Open(name)
	if err != nil {
		return nil, err
	}
	defer func() {
		if closeErr := file.Close(); err == nil && closeErr != nil {
			err = closeErr
		}
	}()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	const limit = 16 << 20
	if !info.Mode().IsRegular() || info.Size() > limit {
		return nil, fmt.Errorf("evidence must be a regular file of at most %d bytes", limit)
	}
	data, err = io.ReadAll(io.LimitReader(file, limit+1))
	if len(data) > limit {
		return nil, fmt.Errorf("evidence exceeds %d bytes", limit)
	}
	return data, err
}
