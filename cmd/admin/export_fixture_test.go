package admin

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"testing"

	"github.com/danieljustus/symaira-vault/internal/exporter"
	"github.com/danieljustus/symaira-vault/internal/importer"
)

const exportFixturePath = "testdata/port/cli/export.json"
const exportOracleCommit = "fca3f894"

var exportOracleSources = []string{
	"cmd/admin/export.go",
	"internal/exporter/csv.go",
	"internal/exporter/json.go",
	"internal/importer/importer.go",
}

type exportFixture struct {
	SchemaVersion int               `json:"schema_version"`
	Oracle        exportOracle      `json:"oracle"`
	Cases         []exportCase      `json:"cases"`
	Invalid       exportInvalidCase `json:"invalid"`
	Cancel        exportCancelCase  `json:"cancel"`
}

type exportOracle struct {
	Commit          string   `json:"commit"`
	SourceFiles     []string `json:"source_files"`
	SourceDigest    string   `json:"source_digest"`
	GeneratorFiles  []string `json:"generator_files"`
	GeneratorDigest string   `json:"generator_digest"`
}

type exportCase struct {
	Name    string `json:"name"`
	Format  string `json:"format"`
	Mapping string `json:"mapping"`
	Output  string `json:"output"`
}

type exportInvalidCase struct {
	MappingError string `json:"mapping_error"`
	FormatError  string `json:"format_error"`
}

type exportCancelCase struct {
	Stderr            string `json:"stderr"`
	OutputStillAbsent bool   `json:"output_still_absent"`
}

func exportFixtureRoot() string {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		panic("locate export fixture generator")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
}

func exportDigestFiles(root string, revision string, names []string) (string, error) {
	ordered := append([]string(nil), names...)
	sort.Strings(ordered)
	h := sha256.New()
	for _, name := range ordered {
		var data []byte
		var err error
		if revision == "" {
			data, err = os.ReadFile(filepath.Join(root, name))
		} else {
			data, err = exec.Command("git", "-C", root, "show", revision+":"+name).Output() // #nosec G204 -- fixed fixture inputs
		}
		if err != nil {
			return "", err
		}
		h.Write([]byte(name))
		h.Write([]byte{0})
		h.Write(data)
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func exportFixtureOracle(root string) (exportOracle, error) {
	sourceDigest, err := exportDigestFiles(root, exportOracleCommit, exportOracleSources)
	if err != nil {
		return exportOracle{}, err
	}
	generatorDigest, err := exportDigestFiles(root, "", []string{"cmd/admin/export_fixture_test.go"})
	if err != nil {
		return exportOracle{}, err
	}
	return exportOracle{
		Commit:          exportOracleCommit,
		SourceFiles:     append([]string(nil), exportOracleSources...),
		SourceDigest:    sourceDigest,
		GeneratorFiles:  []string{"cmd/admin/export_fixture_test.go"},
		GeneratorDigest: generatorDigest,
	}, nil
}

func buildExportFixture(root string) (exportFixture, error) {
	oracle, err := exportFixtureOracle(root)
	if err != nil {
		return exportFixture{}, err
	}
	entries := []exporter.ExportEntry{
		{Path: "work/example", Data: map[string]any{"password": "fixture-pass", "username": "alice", "note": "a,b"}},
		{Path: "empty/otp", Data: map[string]any{"username": "bob", "otp": nil}},
	}
	write := func(format exporter.Format, input []exporter.ExportEntry, mapping map[string]string) (string, error) {
		var output bytes.Buffer
		selected, selectErr := newExporter(format)
		if selectErr != nil {
			return "", selectErr
		}
		if err := selected.Export(&output, input, mapping); err != nil {
			return "", err
		}
		return output.String(), nil
	}
	mapping, err := importer.ParseMapping("username=user,password=secret")
	if err != nil {
		return exportFixture{}, err
	}
	jsonOutput, err := write(exporter.FormatJSON, entries, mapping)
	if err != nil {
		return exportFixture{}, err
	}
	csvOutput, err := write(exporter.FormatCSV, entries, mapping)
	if err != nil {
		return exportFixture{}, err
	}
	jsonEmpty, err := write(exporter.FormatJSON, nil, nil)
	if err != nil {
		return exportFixture{}, err
	}
	csvEmpty, err := write(exporter.FormatCSV, nil, nil)
	if err != nil {
		return exportFixture{}, err
	}
	_, mappingErr := importer.ParseMapping("username")
	_, formatErr := newExporter(exporter.Format("yaml"))
	return exportFixture{
		SchemaVersion: 1,
		Oracle:        oracle,
		Cases: []exportCase{
			{Name: "json_mapping", Format: "json", Mapping: "username=user,password=secret", Output: jsonOutput},
			{Name: "csv_mapping", Format: "csv", Mapping: "username=user,password=secret", Output: csvOutput},
			{Name: "json_empty", Format: "json", Output: jsonEmpty},
			{Name: "csv_empty", Format: "csv", Output: csvEmpty},
		},
		Invalid: exportInvalidCase{
			MappingError: errorText(mappingErr),
			FormatError:  errorText(formatErr),
		},
	}, nil
}

func errorText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func TestExportFixture(t *testing.T) {
	root := exportFixtureRoot()
	fixture, err := buildExportFixture(root)
	if err != nil {
		t.Fatal(err)
	}
	fixture.Cancel = runExportCancellationFixture(t)
	path := filepath.Join(root, exportFixturePath)
	if os.Getenv("UPDATE_EXPORT_FIXTURE") == "1" {
		data, marshalErr := json.MarshalIndent(fixture, "", "  ")
		if marshalErr != nil {
			t.Fatal(marshalErr)
		}
		data = append(data, '\n')
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		return
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	want, err := json.MarshalIndent(fixture, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	want = append(want, '\n')
	if !bytes.Equal(got, want) {
		t.Fatalf("export fixture drift; run UPDATE_EXPORT_FIXTURE=1 go test ./cmd/admin -run '^TestExportFixture$'")
	}
	var parsed exportFixture
	if err := json.Unmarshal(got, &parsed); err != nil {
		t.Fatal(err)
	}
	if parsed.Oracle.Commit != exportOracleCommit || len(parsed.Cases) != 4 || parsed.Invalid.MappingError == "" || parsed.Invalid.FormatError == "" || !parsed.Cancel.OutputStillAbsent || parsed.Cancel.Stderr == "" {
		t.Fatal("export fixture provenance or cardinality drift")
	}
}

func runExportCancellationFixture(t *testing.T) exportCancelCase {
	t.Helper()
	outputPath := filepath.Join(t.TempDir(), "cancel.csv")
	original := confirmExport
	confirmExport = func(_ string, _ bool) (bool, error) { return false, nil }
	t.Cleanup(func() { confirmExport = original })
	stderr := captureStderr(t, func() {
		cmd := newTestRootCmd()
		cmd.SetArgs([]string{"export", "--format", "csv", "--output", outputPath})
		if err := cmd.Execute(); err != nil {
			t.Fatalf("export cancellation: %v", err)
		}
	})
	_, statErr := os.Stat(outputPath)
	return exportCancelCase{Stderr: stderr, OutputStillAbsent: os.IsNotExist(statErr)}
}
