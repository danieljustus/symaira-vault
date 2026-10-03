package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func cloneCapture(t *testing.T, value fixture) fixture {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	var copy fixture
	if err = json.Unmarshal(encoded, &copy); err != nil {
		t.Fatal(err)
	}
	return copy
}

func TestRepeatedPinnedStoreObservationsHaveStableProjection(t *testing.T) {
	first, err := build(rootDir())
	if err != nil {
		t.Fatal(err)
	}
	second, err := build(rootDir())
	if err != nil {
		t.Fatal(err)
	}
	rawFirst, _ := json.Marshal(first)
	rawSecond, _ := json.Marshal(second)
	if bytes.Equal(rawFirst, rawSecond) {
		t.Fatal("negative control did not observe randomized captures")
	}
	a, err := comparisonProjection(first)
	if err != nil {
		t.Fatal(err)
	}
	b, err := comparisonProjection(second)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, b) {
		t.Fatal("repeated real Go observations drift after explicit normalization")
	}
	unchanged, _ := json.Marshal(first)
	if !bytes.Equal(rawFirst, unchanged) {
		t.Fatal("projection modified the raw capture")
	}
	cases := []struct {
		name   string
		mutate func(*fixture)
	}{
		{"entry value", func(v *fixture) {
			e := &v.Vaults[0].Entries[0]
			e.ExpectedJSON = strings.Replace(e.ExpectedJSON, "fake-password-v1", "fake-password-v2", 1)
			e.BeforeJSON = e.ExpectedJSON
			e.Expected = json.RawMessage(e.ExpectedJSON)
			e.BeforeExpected = e.Expected
		}},
		{"type result", func(v *fixture) { v.Vaults[0].TypeVectors[0].Expected = "changed" }},
		{"file mode", func(v *fixture) { v.Vaults[0].Files[0].Mode = 0644; v.Vaults[0].Migration.After.Files[0].Mode = 0644 }},
		{"entry path", func(v *fixture) { v.Vaults[0].Entries[0].Path = "changed" }},
		{"malformed bytes", func(v *fixture) { v.Malformed[1].Input = "changed" }},
		{"presence", func(v *fixture) { v.Vaults[0].Presence.Identity = false }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			modified := cloneCapture(t, first)
			tc.mutate(&modified)
			projection, err := comparisonProjection(modified)
			if err == nil && bytes.Equal(a, projection) {
				t.Fatal("semantic drift was normalized away")
			}
		})
	}
	t.Run("live check rejects semantic drift", func(t *testing.T) {
		modified := cloneCapture(t, first)
		modified.Vaults[0].TypeVectors[0].Expected = "changed"
		if err := verify(rootDir(), writeFixture(t, modified)); err == nil {
			t.Fatal("live freshness check accepted changed type semantics")
		}
	})

	t.Run("unknown observation fields", func(t *testing.T) {
		var capture map[string]any
		if err := json.Unmarshal(rawFirst, &capture); err != nil {
			t.Fatal(err)
		}
		capture["unrecognized_observation"] = "must not disappear in the projection"
		data, err := json.Marshal(capture)
		if err != nil {
			t.Fatal(err)
		}
		output := filepath.Join(t.TempDir(), "unknown.json")
		if err = os.WriteFile(output, data, 0600); err != nil {
			t.Fatal(err)
		}
		if err = verify(rootDir(), output); err == nil {
			t.Fatal("freshness check ignored an unknown observation field")
		}
	})

	t.Run("ciphertext authentication", func(t *testing.T) {
		modified := cloneCapture(t, first)
		for _, files := range [][]fileFixture{modified.Vaults[0].Files, modified.Vaults[0].Migration.Before.Files, modified.Vaults[0].Migration.After.Files} {
			for index, file := range files {
				if file.Path != "entries/minimal.age" {
					continue
				}
				data, err := base64.StdEncoding.DecodeString(file.Content)
				if err != nil {
					t.Fatal(err)
				}
				data[len(data)-1] ^= 1
				files[index].Content = base64.StdEncoding.EncodeToString(data)
				files[index].SHA256 = hashBytes(data)
			}
		}
		if _, err := comparisonProjection(modified); err == nil {
			t.Fatal("authenticated ciphertext corruption accepted after recomputing public digest")
		}
	})
	t.Run("manifest binding", func(t *testing.T) {
		modified := cloneCapture(t, first)
		// Swap two valid authenticated envelopes and update their public file hashes;
		// the authenticated manifest must still bind the original entry ciphertexts.
		for _, files := range [][]fileFixture{modified.Vaults[0].Files, modified.Vaults[0].Migration.Before.Files, modified.Vaults[0].Migration.After.Files} {
			one, two := -1, -1
			for index, file := range files {
				if file.Path == "entries/full.age" {
					one = index
				}
				if file.Path == "entries/minimal.age" {
					two = index
				}
			}
			files[one].Content, files[two].Content = files[two].Content, files[one].Content
			files[one].Size, files[two].Size = files[two].Size, files[one].Size
			files[one].SHA256, files[two].SHA256 = files[two].SHA256, files[one].SHA256
		}
		if _, err := comparisonProjection(modified); err == nil {
			t.Fatal("manifest/ciphertext inconsistency accepted")
		}
	})
}

func TestClockProjectionPreservesOtherJSONBytes(t *testing.T) {
	input := []byte(`{"data":{"timestamp":"2026-10-03T00:00:00Z","number":1.00,"escaped":"\u003c"},"meta":{"created":"2026-10-03T00:00:00Z","updated":"2026-10-03T00:00:00Z","version":1}}`)
	got, err := normalizeEntry(input)
	if err != nil {
		t.Fatal(err)
	}
	want := []byte(`{"data":{"timestamp":"2026-10-03T00:00:00Z","number":1.00,"escaped":"\u003c"},"meta":{"created":"2000-01-01T00:00:00Z","updated":"2000-01-01T00:00:00Z","version":1}}`)
	if !bytes.Equal(got, want) {
		t.Fatal("normalization changed non-clock bytes")
	}
	for _, input := range []string{`{"meta":{"created":"invalid","updated":"invalid"}}`, `{"meta":{"created":"2026-10-03T00:00:00Z","updated":"2026-10-03T00:00:01Z"}}`} {
		if _, err := normalizeEntry([]byte(input)); err == nil {
			t.Fatal("invalid fresh clock relation accepted")
		}
	}
}
