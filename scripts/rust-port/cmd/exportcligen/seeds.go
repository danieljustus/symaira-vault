package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"
)

// seedStep is one oracle command run to create a frozen vault seed.
type seedStep struct {
	argv []string
}

var seedCertBytes = []byte("\x30\x82\x01\x0a\x02\x82\x01\x01\x00synthetic-pkcs12-bytes\x00\xff\xfe\x01")

// seedCommands are the oracle commands that build each frozen seed. They run
// only with --new-seeds; later generations and --check read the result back
// from the fixture.
func seedCommands() map[string][]seedStep {
	add := func(args ...string) seedStep { return seedStep{append([]string{"add"}, args...)} }
	return map[string][]seedStep{
		// A fresh vault's first open rewrites config.yaml and creates .lock and
		// manifest.age in Go. That is vault-open behaviour shared by every
		// command, not export/backup/restore behaviour, so each seed ends with a
		// settling `list` and the scenarios start from a settled vault.
		"empty": {{[]string{"init"}}, {[]string{"list"}}},
		"entries": {
			{[]string{"init"}},
			add("a/first", "--value", "Val-Alpha-000"),
			add("work/example", "--value", "Val-Alpha-001", "--username", "alice", "--url", "https://example.test", "--notes", "a,b"),
			add("work/two", "--value", "Val-Alpha-002"),
			add("personal/quote", "--value", `Val-"q"-0003`, "--username", `bob "b"`, "--notes", "line1\nline2"),
			add("unicode/ünï", "--value", "Wert-äöü-0004"),
			{[]string{"file", "add", "files/cert", "--field", "cert", "--from", "cert.bin"}},
			{[]string{"list"}},
		},
	}
}

// buildSeeds creates every seed with the oracle and returns the vault trees.
func buildSeeds(goBinary string) (map[string][]FileSpec, error) {
	seeds := map[string][]FileSpec{}
	for name, steps := range seedCommands() {
		box, err := newSandbox()
		if err != nil {
			return nil, err
		}
		spec, err := func() ([]FileSpec, error) {
			defer box.remove()
			if err := os.WriteFile(filepath.Join(box.root, "work", "cert.bin"), seedCertBytes, 0o600); err != nil {
				return nil, err
			}
			for _, step := range steps {
				result, err := box.runStep(goBinary, Case{ID: "seed-" + name}, Step{Argv: step.argv})
				if err != nil {
					return nil, err
				}
				if result.Exit != 0 {
					return nil, fmt.Errorf("seed %s: %v exited %d: %s", name, step.argv, result.Exit, result.Stderr)
				}
			}
			return collectVault(box.root)
		}()
		if err != nil {
			return nil, fmt.Errorf("seed %s: %w", name, err)
		}
		seeds[name] = spec
	}
	return seeds, nil
}

// collectVault records <root>/vault as FileSpecs in a parent-first order.
func collectVault(root string) ([]FileSpec, error) {
	base := filepath.Join(root, "vault")
	var specs []FileSpec
	err := filepath.WalkDir(base, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		spec := FileSpec{Path: filepath.ToSlash(rel), Mode: uint32(info.Mode().Perm())}
		switch {
		case info.IsDir():
			spec.Kind = "dir"
		case info.Mode().IsRegular():
			spec.Kind = "file"
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			setData(&spec, data)
		default:
			return fmt.Errorf("seed contains unsupported file %s (%v)", path, info.Mode())
		}
		specs = append(specs, spec)
		return nil
	})
	return specs, err
}

// setData stores content as text when it is plain UTF-8 text and as base64
// otherwise, so the fixture stays reviewable where it can.
func setData(spec *FileSpec, data []byte) {
	if utf8.Valid(data) && !bytes.ContainsAny(data, "\x00") {
		spec.Data = string(data)
		return
	}
	spec.B64 = base64.StdEncoding.EncodeToString(data)
}

// member is one tar member of a synthetic archive.
type member struct {
	name string
	typ  byte
	mode int64
	data string
	link string
}

func dirMember(name string, mode int64) member {
	return member{name: name, typ: tar.TypeDir, mode: mode}
}
func fileMember(name string, mode int64, data string) member {
	return member{name: name, typ: tar.TypeReg, mode: mode, data: data}
}

// buildGz writes members with fixed headers and a fixed gzip header so the
// bytes are reproducible for the pinned toolchain.
func buildGz(members []member) ([]byte, error) {
	var out bytes.Buffer
	gw := gzip.NewWriter(&out)
	tw := tar.NewWriter(gw)
	fixed := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	for _, m := range members {
		header := &tar.Header{Name: m.name, Typeflag: m.typ, Mode: m.mode, ModTime: fixed, Linkname: m.link}
		if m.typ == tar.TypeReg {
			header.Size = int64(len(m.data))
		}
		if err := tw.WriteHeader(header); err != nil {
			return nil, err
		}
		if m.typ == tar.TypeReg {
			if _, err := tw.Write([]byte(m.data)); err != nil {
				return nil, err
			}
		}
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	if err := gw.Close(); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

// archiveFile is a pre-existing archive file of a scenario.
func archiveFile(path string, mode uint32, members []member) (FileSpec, error) {
	data, err := buildGz(members)
	if err != nil {
		return FileSpec{}, err
	}
	return FileSpec{Path: path, Kind: "file", Mode: mode, B64: base64.StdEncoding.EncodeToString(data)}, nil
}

// seedMembers turns a vault seed into archive members named relative to the
// vault directory, in the seed's parent-first order. Files stay byte-identical
// to the seed, so a restored vault keeps decrypting with the test passphrase.
func seedMembers(seed []FileSpec, skip func(rel string) bool) []member {
	var members []member
	for _, spec := range seed {
		rel := strings.TrimPrefix(spec.Path, "vault")
		rel = strings.TrimPrefix(rel, "/")
		if rel == "" || (skip != nil && skip(rel)) {
			continue
		}
		switch spec.Kind {
		case "dir":
			members = append(members, dirMember(rel, int64(spec.Mode)))
		case "file":
			data, err := decodeSpecData(spec)
			if err != nil {
				panic(err)
			}
			members = append(members, fileMember(rel, int64(spec.Mode), string(data)))
		}
	}
	return members
}
