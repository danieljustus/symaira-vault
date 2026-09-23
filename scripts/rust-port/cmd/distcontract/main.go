// Command distcontract checks locally staged Rust release archives against
// the archive naming and file contract in the pinned GoReleaser config.
package main

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"crypto/sha256"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

type config struct {
	Release struct {
		GitHub struct {
			Name string `yaml:"name"`
		} `yaml:"github"`
	} `yaml:"release"`
	Builds []struct {
		Binary string   `yaml:"binary"`
		GOOS   []string `yaml:"goos"`
		GOARCH []string `yaml:"goarch"`
	} `yaml:"builds"`
	Archives []struct {
		NameTemplate    string   `yaml:"name_template"`
		Formats         []string `yaml:"formats"`
		FormatOverrides []struct {
			GOOS    string   `yaml:"goos"`
			Formats []string `yaml:"formats"`
		} `yaml:"format_overrides"`
		Files           []string `yaml:"files"`
		WrapInDirectory bool     `yaml:"wrap_in_directory"`
	} `yaml:"archives"`
}

type archivePlan struct {
	name   string
	format string
	root   string
	files  map[string]string // archive path -> SHA-256 of source file
	binary string
}

const maxArchiveMemberBytes = 256 << 20

func main() {
	var repo, stage, version string
	flag.StringVar(&repo, "repo", ".", "repository root containing .goreleaser.yml and packaged source files")
	flag.StringVar(&stage, "rust-dir", "dist/rust", "directory containing locally staged Rust archives")
	flag.StringVar(&version, "version", "", "release version, with or without a leading v")
	flag.Parse()
	if version == "" {
		fatal(errors.New("--version is required"))
	}
	if err := compare(repo, stage, version); err != nil {
		fatal(err)
	}
	fmt.Println("Rust archive metadata matches GoReleaser contract")
}

func compare(repo, stage, version string) error {
	root, err := filepath.Abs(repo)
	if err != nil {
		return err
	}
	stage, err = filepath.Abs(stage)
	if err != nil {
		return err
	}
	data, err := os.ReadFile(filepath.Join(root, ".goreleaser.yml"))
	if err != nil {
		return fmt.Errorf("read GoReleaser config: %w", err)
	}
	var cfg config
	err = yaml.Unmarshal(data, &cfg)
	if err != nil {
		return fmt.Errorf("parse GoReleaser config: %w", err)
	}
	plans, err := makePlans(root, cfg, version)
	if err != nil {
		return err
	}
	if len(plans) == 0 {
		return errors.New("GoReleaser config produced no archive plans")
	}
	for _, plan := range plans {
		path := filepath.Join(stage, plan.name)
		if err := compareOne(path, plan); err != nil {
			return fmt.Errorf("%s: %w", plan.name, err)
		}
	}
	return nil
}

func makePlans(root string, cfg config, version string) ([]archivePlan, error) {
	project := cfg.Release.GitHub.Name
	version = strings.TrimPrefix(version, "v")
	if project == "" || version == "" {
		return nil, errors.New("GoReleaser release.github.name and a non-empty version are required")
	}
	if len(cfg.Archives) != 1 || len(cfg.Builds) == 0 {
		return nil, errors.New("expected one archive definition and at least one build definition")
	}
	archive := cfg.Archives[0]
	if archive.NameTemplate == "" || len(archive.Formats) != 1 || !archive.WrapInDirectory {
		return nil, errors.New("unsupported GoReleaser archive configuration")
	}
	files, err := sourceFiles(root, archive.Files)
	if err != nil {
		return nil, err
	}
	plans := make([]archivePlan, 0)
	for _, build := range cfg.Builds {
		if build.Binary == "" {
			return nil, errors.New("GoReleaser build binary is empty")
		}
		for _, goos := range build.GOOS {
			for _, goarch := range build.GOARCH {
				format := archive.Formats[0]
				for _, override := range archive.FormatOverrides {
					if override.GOOS == goos {
						if len(override.Formats) != 1 {
							return nil, fmt.Errorf("unsupported format override for %s", goos)
						}
						format = override.Formats[0]
					}
				}
				extension, err := extension(format)
				if err != nil {
					return nil, err
				}
				stem, err := renderName(archive.NameTemplate, project, version, goos, goarch)
				if err != nil {
					return nil, err
				}
				binary := build.Binary
				if goos == "windows" && !strings.HasSuffix(binary, ".exe") {
					binary += ".exe"
				}
				memberFiles := make(map[string]string, len(files))
				for name, hash := range files {
					memberFiles[name] = hash
				}
				plans = append(plans, archivePlan{
					name: stem + extension, format: format, root: stem,
					files: memberFiles, binary: binary,
				})
			}
		}
	}
	return plans, nil
}

func sourceFiles(root string, patterns []string) (map[string]string, error) {
	files := make(map[string]string)
	for _, pattern := range patterns {
		matches, err := filepath.Glob(filepath.Join(root, filepath.FromSlash(pattern)))
		if err != nil {
			return nil, fmt.Errorf("expand GoReleaser file pattern %q: %w", pattern, err)
		}
		if len(matches) == 0 {
			return nil, fmt.Errorf("GoReleaser file pattern %q matched no files", pattern)
		}
		for _, path := range matches {
			info, err := os.Stat(path)
			if err != nil {
				return nil, err
			}
			if !info.Mode().IsRegular() {
				continue
			}
			data, err := os.ReadFile(path)
			if err != nil {
				return nil, err
			}
			relative, err := filepath.Rel(root, path)
			if err != nil {
				return nil, err
			}
			files[filepath.ToSlash(relative)] = fmt.Sprintf("%x", sha256.Sum256(data))
		}
	}
	return files, nil
}

func renderName(template, project, version, goos, goarch string) (string, error) {
	name := strings.NewReplacer(
		"{{ .ProjectName }}", project,
		"{{ .Version }}", version,
		"{{ .Os }}", goos,
		"{{ .Arch }}", goarch,
	).Replace(template)
	if strings.Contains(name, "{{") || strings.Contains(name, "}}") || filepath.Base(name) != name {
		return "", fmt.Errorf("unsupported archive name template %q", template)
	}
	return name, nil
}

func extension(format string) (string, error) {
	switch format {
	case "tar.gz":
		return ".tar.gz", nil
	case "zip":
		return ".zip", nil
	default:
		return "", fmt.Errorf("unsupported archive format %q", format)
	}
}

func compareOne(path string, plan archivePlan) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open staged archive: %w", err)
	}
	defer func() { _ = f.Close() }()
	var names map[string]string
	switch plan.format {
	case "tar.gz":
		gz, gzipErr := gzip.NewReader(f)
		if gzipErr != nil {
			return fmt.Errorf("open gzip stream: %w", gzipErr)
		}
		defer func() { _ = gz.Close() }()
		names, err = readTar(gz, plan)
	case "zip":
		info, statErr := f.Stat()
		if statErr != nil {
			return statErr
		}
		zr, zipErr := zip.NewReader(f, info.Size())
		if zipErr != nil {
			return fmt.Errorf("open zip archive: %w", zipErr)
		}
		names, err = readZip(zr, plan)
	default:
		return fmt.Errorf("unsupported format %q", plan.format)
	}
	if err != nil {
		return err
	}
	expected := make(map[string]string, len(plan.files)+1)
	for name, hash := range plan.files {
		expected[filepath.ToSlash(filepath.Join(plan.root, filepath.FromSlash(name)))] = hash
	}
	binaryName := filepath.ToSlash(filepath.Join(plan.root, plan.binary))
	expected[binaryName] = "" // binary bytes differ by implementation; presence and path are the contract here.
	if len(names) != len(expected) {
		return fmt.Errorf("member count = %d, want %d (actual: %s)", len(names), len(expected), strings.Join(sortedKeys(names), ", "))
	}
	for name, expectedHash := range expected {
		actualHash, ok := names[name]
		if !ok {
			return fmt.Errorf("required archive member %q is missing", name)
		}
		if expectedHash != "" && actualHash != expectedHash {
			return fmt.Errorf("source member %q hash differs from Go release input", name)
		}
	}
	return nil
}

func readTar(r io.Reader, plan archivePlan) (map[string]string, error) {
	tr := tar.NewReader(r)
	result := make(map[string]string)
	for {
		header, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return result, nil
		}
		if err != nil {
			return nil, fmt.Errorf("read tar member: %w", err)
		}
		if header.Typeflag == tar.TypeDir {
			continue
		}
		if !header.FileInfo().Mode().IsRegular() {
			return nil, fmt.Errorf("unsupported tar member type %d", header.Typeflag)
		}
		name, err := normalizeMember(header.Name, plan.root)
		if err != nil {
			return nil, err
		}
		if _, duplicate := result[name]; duplicate {
			return nil, fmt.Errorf("duplicate archive member %q", name)
		}
		data, err := io.ReadAll(io.LimitReader(tr, maxArchiveMemberBytes+1))
		if err != nil {
			return nil, err
		}
		if len(data) > maxArchiveMemberBytes {
			return nil, fmt.Errorf("archive member %q exceeds %d bytes", name, maxArchiveMemberBytes)
		}
		result[name] = fmt.Sprintf("%x", sha256.Sum256(data))
	}
}

func readZip(zr *zip.Reader, plan archivePlan) (map[string]string, error) {
	result := make(map[string]string)
	for _, file := range zr.File {
		if file.FileInfo().IsDir() {
			continue
		}
		name, err := normalizeMember(file.Name, plan.root)
		if err != nil {
			return nil, err
		}
		if _, duplicate := result[name]; duplicate {
			return nil, fmt.Errorf("duplicate archive member %q", name)
		}
		r, err := file.Open()
		if err != nil {
			return nil, err
		}
		data, readErr := io.ReadAll(io.LimitReader(r, maxArchiveMemberBytes+1))
		closeErr := r.Close()
		if err := errors.Join(readErr, closeErr); err != nil {
			return nil, err
		}
		if len(data) > maxArchiveMemberBytes {
			return nil, fmt.Errorf("archive member %q exceeds %d bytes", name, maxArchiveMemberBytes)
		}
		result[name] = fmt.Sprintf("%x", sha256.Sum256(data))
	}
	return result, nil
}

func normalizeMember(name, root string) (string, error) {
	name = filepath.ToSlash(filepath.Clean(filepath.FromSlash(name)))
	if name == "." || strings.HasPrefix(name, "../") || strings.HasPrefix(name, "/") {
		return "", fmt.Errorf("unsafe archive member path %q", name)
	}
	if name != root && !strings.HasPrefix(name, root+"/") {
		return "", fmt.Errorf("archive member %q is outside wrapper %q", name, root)
	}
	return name, nil
}

func sortedKeys[V any](values map[string]V) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "distcontract:", err)
	os.Exit(1)
}
