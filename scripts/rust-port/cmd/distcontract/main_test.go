package main

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestStagedArchiveMatchesGoReleaseContract(t *testing.T) {
	root := testRepoRoot(t)
	data, err := os.ReadFile(filepath.Join(root, ".goreleaser.yml"))
	if err != nil {
		t.Fatal(err)
	}
	var cfg config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		t.Fatal(err)
	}
	plans, err := makePlans(root, cfg, "v9.8.7")
	if err != nil {
		t.Fatal(err)
	}
	var plan *archivePlan
	for i := range plans {
		if plans[i].format == "tar.gz" && plans[i].name == "symaira-vault_9.8.7_linux_amd64.tar.gz" {
			plan = &plans[i]
			break
		}
	}
	if plan == nil {
		t.Fatalf("source config did not produce expected Linux archive name; plans=%v", plans)
	}
	stage := t.TempDir()
	writeTarGz(t, filepath.Join(stage, plan.name), root, *plan, false)
	if err := compare(root, stage, "9.8.7", "linux/amd64"); err != nil {
		t.Fatalf("valid staged artifact rejected: %v", err)
	}
	if err := compare(root, stage, "9.8.7", "unknown/arch"); err == nil {
		t.Fatal("unknown target passed")
	}
}

func TestStagedArchiveRejectsUnexpectedMember(t *testing.T) {
	root := testRepoRoot(t)
	data, err := os.ReadFile(filepath.Join(root, ".goreleaser.yml"))
	if err != nil {
		t.Fatal(err)
	}
	var cfg config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		t.Fatal(err)
	}
	plans, err := makePlans(root, cfg, "9.8.7")
	if err != nil {
		t.Fatal(err)
	}
	plan := plans[0]
	stage := t.TempDir()
	writeTarGz(t, filepath.Join(stage, plan.name), root, plan, true)
	path := filepath.Join(stage, plan.name)
	if err := compareOne(path, plan); err == nil {
		t.Fatal("archive with extra member passed")
	}
}

func TestWindowsStagedArchiveUsesZipAndExeMember(t *testing.T) {
	root := testRepoRoot(t)
	data, err := os.ReadFile(filepath.Join(root, ".goreleaser.yml"))
	if err != nil {
		t.Fatal(err)
	}
	var cfg config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		t.Fatal(err)
	}
	plans, err := makePlans(root, cfg, "9.8.7")
	if err != nil {
		t.Fatal(err)
	}
	var plan *archivePlan
	for i := range plans {
		if plans[i].format == "zip" && strings.Contains(plans[i].name, "_windows_") {
			plan = &plans[i]
			break
		}
	}
	if plan == nil || plan.binary != "symvault.exe" {
		t.Fatalf("Windows zip plan = %#v", plan)
	}
	path := filepath.Join(t.TempDir(), plan.name)
	writeZip(t, path, root, *plan)
	if err := compareOne(path, *plan); err != nil {
		t.Fatalf("valid staged Windows archive rejected: %v", err)
	}
}

func testRepoRoot(t *testing.T) string {
	t.Helper()
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Clean(filepath.Join(cwd, "..", "..", "..", ".."))
}

func writeTarGz(t *testing.T, path, root string, plan archivePlan, extra bool) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	gz := gzip.NewWriter(f)
	tr := tar.NewWriter(gz)
	files := map[string]string{plan.binary: "test-rust-binary"}
	for name := range plan.files {
		files[name] = filepath.Join(root, filepath.FromSlash(name))
	}
	for name, value := range files {
		var body []byte
		if name == plan.binary {
			body = []byte(value)
		} else {
			body, err = os.ReadFile(value)
			if err != nil {
				t.Fatal(err)
			}
		}
		header := &tar.Header{Name: filepath.ToSlash(filepath.Join(plan.root, filepath.FromSlash(name))), Mode: 0o644, Size: int64(len(body)), Typeflag: tar.TypeReg}
		if err := tr.WriteHeader(header); err != nil {
			t.Fatal(err)
		}
		if _, err := tr.Write(body); err != nil {
			t.Fatal(err)
		}
	}
	if extra {
		body := []byte("unexpected")
		if err := tr.WriteHeader(&tar.Header{Name: filepath.ToSlash(filepath.Join(plan.root, "unexpected.txt")), Mode: 0o644, Size: int64(len(body)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := tr.Write(body); err != nil {
			t.Fatal(err)
		}
	}
	if err := errors.Join(tr.Close(), gz.Close(), f.Close()); err != nil {
		t.Fatal(err)
	}
}

func writeZip(t *testing.T, path, root string, plan archivePlan) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(f)
	files := map[string]string{plan.binary: "test-rust-binary"}
	for name := range plan.files {
		files[name] = filepath.Join(root, filepath.FromSlash(name))
	}
	for name, value := range files {
		var body []byte
		if name == plan.binary {
			body = []byte(value)
		} else {
			body, err = os.ReadFile(value)
			if err != nil {
				t.Fatal(err)
			}
		}
		w, err := zw.Create(filepath.ToSlash(filepath.Join(plan.root, filepath.FromSlash(name))))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(body); err != nil {
			t.Fatal(err)
		}
	}
	if err := errors.Join(zw.Close(), f.Close()); err != nil {
		t.Fatal(err)
	}
}
