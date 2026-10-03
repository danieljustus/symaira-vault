package main

import (
	"archive/tar"
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

const (
	archiveTestLimit        int64 = maxArchiveBytes
	archiveTestPreserveMode       = true
)

type archiveTestEntry struct {
	name     string
	typeflag byte
	data     string
	linkname string
}

func archiveTestReader(t *testing.T, entries ...archiveTestEntry) *bytes.Reader {
	t.Helper()
	var data bytes.Buffer
	writer := tar.NewWriter(&data)
	for _, entry := range entries {
		header := &tar.Header{Name: entry.name, Mode: 0640, Typeflag: entry.typeflag, Linkname: entry.linkname, Size: int64(len(entry.data))}
		if err := writer.WriteHeader(header); err != nil {
			t.Fatalf("write archive header %q: %v", entry.name, err)
		}
		if entry.data != "" {
			if _, err := io.WriteString(writer, entry.data); err != nil {
				t.Fatalf("write archive data %q: %v", entry.name, err)
			}
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close test archive: %v", err)
	}
	return bytes.NewReader(data.Bytes())
}

func extractArchiveForTest(reader io.Reader, destination string) error {
	return extractArchive(reader, destination, archiveTestLimit, archiveTestPreserveMode)
}

func TestExtractArchiveContainment(t *testing.T) {
	root := t.TempDir()
	destination := filepath.Join(root, "destination")
	if err := os.Mkdir(destination, 0700); err != nil {
		t.Fatal(err)
	}
	reader := archiveTestReader(t,
		archiveTestEntry{name: "valid..name/nested.txt", typeflag: tar.TypeReg, data: "inside"},
	)
	if err := extractArchiveForTest(reader, destination); err != nil {
		t.Fatalf("valid archive extraction: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(destination, "valid..name", "nested.txt"))
	if err != nil || string(got) != "inside" {
		t.Fatalf("valid extracted file = %q, %v", got, err)
	}
	if archiveTestPreserveMode && runtime.GOOS != "windows" {
		info, err := os.Stat(filepath.Join(destination, "valid..name", "nested.txt"))
		if err != nil || info.Mode().Perm() != 0640 {
			t.Fatalf("preserved file mode = %v, %v", info, err)
		}
	}

	parent := t.TempDir()
	outside := filepath.Join(parent, "outside.txt")
	outsideDir := filepath.Join(parent, "outside")
	if err := os.Mkdir(outsideDir, 0700); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name    string
		entries []archiveTestEntry
		target  string
	}{
		{name: "parent traversal", entries: []archiveTestEntry{{name: "../outside.txt", typeflag: tar.TypeReg, data: "escape"}}, target: outside},
		{name: "nested traversal", entries: []archiveTestEntry{{name: "nested/../outside.txt", typeflag: tar.TypeReg, data: "escape"}}, target: outside},
		{name: "absolute path", entries: []archiveTestEntry{{name: filepath.Join(parent, "absolute.txt"), typeflag: tar.TypeReg, data: "escape"}}, target: filepath.Join(parent, "absolute.txt")},
		{name: "symbolic link", entries: []archiveTestEntry{{name: "link", typeflag: tar.TypeSymlink, linkname: "../outside"}, {name: "link/escaped.txt", typeflag: tar.TypeReg, data: "escape"}}, target: filepath.Join(outsideDir, "escaped.txt")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dest := filepath.Join(parent, "destination-"+tc.name)
			if err := os.Mkdir(dest, 0700); err != nil {
				t.Fatal(err)
			}
			if err := extractArchiveForTest(archiveTestReader(t, tc.entries...), dest); err == nil {
				t.Fatal("unsafe archive was accepted")
			}
			if _, err := os.Lstat(tc.target); !os.IsNotExist(err) {
				t.Fatalf("outside target exists after rejection: %v", err)
			}
		})
	}
}

func TestExtractArchiveRejectsSymlinkedParent(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation may require elevated privileges on Windows")
	}
	parent := t.TempDir()
	destination := filepath.Join(parent, "destination")
	outside := filepath.Join(parent, "outside")
	if err := os.Mkdir(destination, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(outside, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(destination, "link")); err != nil {
		t.Skipf("create symlink: %v", err)
	}
	if err := extractArchiveForTest(archiveTestReader(t, archiveTestEntry{name: "link/escaped.txt", typeflag: tar.TypeReg, data: "escape"}), destination); err == nil {
		t.Fatal("extraction through an outside symlink was accepted")
	}
	if _, err := os.Lstat(filepath.Join(outside, "escaped.txt")); !os.IsNotExist(err) {
		t.Fatalf("outside file exists after symlinked-parent rejection: %v", err)
	}
}

func TestRefreshProvenanceOnlyPreservesFixturePayload(t *testing.T) {
	root := rootDir()
	fixturePath := filepath.Join(root, "testdata", "port", "store", "store.json")
	data, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatal(err)
	}
	var before fixture
	if err := json.Unmarshal(data, &before); err != nil {
		t.Fatal(err)
	}
	before.Oracle.GeneratorDigest = "stale-provenance"
	stale, err := json.MarshalIndent(before, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	stale = append(stale, '\n')
	path := filepath.Join(t.TempDir(), "store.json")
	if err := os.WriteFile(path, stale, 0600); err != nil {
		t.Fatal(err)
	}
	if err := refreshProvenanceOnly(root, path); err != nil {
		t.Fatal(err)
	}
	updated, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var after fixture
	if err := json.Unmarshal(updated, &after); err != nil {
		t.Fatal(err)
	}
	before.Oracle.GeneratorDigest = after.Oracle.GeneratorDigest
	before.Oracle.GeneratorFiles = after.Oracle.GeneratorFiles
	want, err := json.MarshalIndent(before, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	want = append(want, '\n')
	if !bytes.Equal(want, updated) {
		t.Fatal("provenance-only refresh changed fixture observations or bytes")
	}
	if after.Oracle.GeneratorDigest == "stale-provenance" {
		t.Fatal("provenance-only refresh retained stale generator digest")
	}
}
