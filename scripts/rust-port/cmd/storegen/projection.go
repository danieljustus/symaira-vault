package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"
	"reflect"
	"strings"
	"time"

	"filippo.io/age"
	"gopkg.in/yaml.v3"
)

// Raw captures remain authenticated interoperability vectors. Only this versioned
// comparison projection removes the randomness enumerated in store-normalization.md.
const comparisonVersion = "store-observation-v1"
const fixtureIdentity = "AGE-SECRET-KEY-1HS3YTK69EJH0ZYM8ANNNDWQMPT7ZMLPYGTMC47F5T4EDJ5N7EYMQ4L5CDL"
const normalizedTime = "2000-01-01T00:00:00Z"

type jsonEdit struct {
	start, end int
	value      []byte
}

// rewriteJSON preserves every unselected byte (including number representation,
// object order and escaping). Paths come from parsed tokens, not text matching.
func rewriteJSON(data []byte, replacement func([]string, any) (any, bool, error)) ([]byte, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var edits []jsonEdit
	var visit func([]string) error
	visit = func(parts []string) error {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		if delimiter, ok := token.(json.Delim); ok {
			switch delimiter {
			case '{':
				for decoder.More() {
					key, keyErr := decoder.Token()
					if keyErr != nil {
						return keyErr
					}
					name, ok := key.(string)
					if !ok {
						return errors.New("invalid JSON key")
					}
					if visitErr := visit(append(append([]string(nil), parts...), name)); visitErr != nil {
						return visitErr
					}
				}
			case '[':
				for index := 0; decoder.More(); index++ {
					if visitErr := visit(append(append([]string(nil), parts...), fmt.Sprint(index))); visitErr != nil {
						return visitErr
					}
				}
			default:
				return errors.New("unexpected JSON delimiter")
			}
			_, closeErr := decoder.Token()
			return closeErr
		}
		value, replace, err := replacement(parts, token)
		if err != nil || !replace {
			return err
		}
		original, err := json.Marshal(token)
		if err != nil {
			return err
		}
		end := int(decoder.InputOffset())
		start := end - len(original)
		if start < 0 || !bytes.Equal(data[start:end], original) {
			return errors.New("noncanonical selected JSON value")
		}
		encoded, err := json.Marshal(value)
		if err != nil {
			return err
		}
		edits = append(edits, jsonEdit{start, end, encoded})
		return nil
	}
	if err := visit(nil); err != nil {
		return nil, err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("trailing JSON data")
	}
	var out bytes.Buffer
	start := 0
	for _, edit := range edits {
		out.Write(data[start:edit.start])
		out.Write(edit.value)
		start = edit.end
	}
	out.Write(data[start:])
	return out.Bytes(), nil
}

func clockReplacement(value any) (any, bool, error) {
	text, ok := value.(string)
	if !ok {
		return nil, false, errors.New("fixture clock is not a string")
	}
	parsed, err := time.Parse(time.RFC3339Nano, text)
	if err != nil || parsed.IsZero() {
		return nil, false, errors.New("invalid fixture clock")
	}
	return normalizedTime, true, nil
}

func normalizeEntry(data []byte) ([]byte, error) {
	var entry struct {
		Meta struct{ Created, Updated string }
	}
	if err := json.Unmarshal(data, &entry); err != nil {
		return nil, err
	}
	if entry.Meta.Created == "" || entry.Meta.Created != entry.Meta.Updated {
		return nil, errors.New("fresh entry timestamps differ or are missing")
	}
	return rewriteJSON(data, func(parts []string, value any) (any, bool, error) {
		if len(parts) == 2 && parts[0] == "meta" && (parts[1] == "created" || parts[1] == "updated") {
			return clockReplacement(value)
		}
		return nil, false, nil
	})
}

func normalizeConfig(data []byte) ([]byte, error) {
	var node yaml.Node
	if err := yaml.Unmarshal(data, &node); err != nil {
		return nil, err
	}
	if len(node.Content) != 1 || node.Content[0].Kind != yaml.MappingNode {
		return nil, errors.New("invalid fixture config mapping")
	}
	found := false
	for index := 0; index < len(node.Content[0].Content); index += 2 {
		if node.Content[0].Content[index].Value != "vaultDir" {
			continue
		}
		value := node.Content[0].Content[index+1]
		basename := path.Base(strings.ReplaceAll(value.Value, "\\", "/"))
		if value.Kind != yaml.ScalarNode || value.Tag != "!!str" || !strings.HasPrefix(basename, "symvault-store-oracle-") || basename == "symvault-store-oracle-" {
			return nil, errors.New("config does not name a generated temporary vault")
		}
		value.Value = "<temporary-vault-root>"
		found = true
	}
	if !found {
		return nil, errors.New("fixture config lacks vaultDir")
	}
	return yaml.Marshal(&node)
}

func normalizeManifest(data []byte, raw map[string]fileFixture, plain map[string][]byte) ([]byte, error) {
	var manifest struct {
		Created, Updated string
		Entries          map[string]struct {
			SHA256 string
			Size   int64
			Mtime  string
		}
	}
	if err := json.Unmarshal(data, &manifest); err != nil {
		return nil, err
	}
	created, createdErr := time.Parse(time.RFC3339Nano, manifest.Created)
	updated, updatedErr := time.Parse(time.RFC3339Nano, manifest.Updated)
	if createdErr != nil || updatedErr != nil || updated.Before(created) {
		return nil, errors.New("invalid manifest clock ordering")
	}
	count := 0
	for name, entry := range manifest.Entries {
		file, ok := raw["entries/"+name+".age"]
		if !ok {
			file, ok = raw[name+".age"]
		}
		if !ok || file.SHA256 != entry.SHA256 || file.Size != entry.Size {
			return nil, errors.New("manifest ciphertext binding changed")
		}
		count++
	}
	for name := range plain {
		if strings.HasSuffix(name, ".age") && name != "identity.age" && name != "manifest.age" {
			count--
		}
	}
	if count != 0 {
		return nil, errors.New("manifest entry inventory changed")
	}
	return rewriteJSON(data, func(parts []string, value any) (any, bool, error) {
		if len(parts) == 1 && (parts[0] == "created" || parts[0] == "updated") {
			return clockReplacement(value)
		}
		if len(parts) != 3 || parts[0] != "entries" {
			return nil, false, nil
		}
		if parts[2] == "mtime" {
			return clockReplacement(value)
		}
		if parts[2] == "sha256" || parts[2] == "size" {
			payload, ok := plain["entries/"+parts[1]+".age"]
			if !ok {
				payload = plain[parts[1]+".age"]
			}
			normalized, err := normalizeEntry(payload)
			if err != nil {
				return nil, false, err
			}
			if parts[2] == "sha256" {
				return hashBytes(normalized), true, nil
			}
			return len(normalized), true, nil
		}
		return nil, false, nil
	})
}

func normalizeFiles(files []fileFixture) ([]fileFixture, error) {
	identity, err := age.ParseX25519Identity(fixtureIdentity)
	if err != nil {
		return nil, err
	}
	raw := make(map[string]fileFixture, len(files))
	plain := make(map[string][]byte, len(files))
	for _, file := range files {
		data, decodeErr := base64.StdEncoding.DecodeString(file.Content)
		if decodeErr != nil {
			return nil, errors.New("invalid fixture file encoding")
		}
		if int64(len(data)) != file.Size || hashBytes(data) != file.SHA256 {
			return nil, fmt.Errorf("%s fixture file integrity changed", file.Path)
		}
		if _, exists := raw[file.Path]; exists {
			return nil, errors.New("duplicate fixture file path")
		}
		raw[file.Path] = file
		if strings.HasSuffix(file.Path, ".age") {
			reader, decryptErr := age.Decrypt(bytes.NewReader(data), identity)
			if decryptErr != nil {
				return nil, fmt.Errorf("%s fixture authentication failed", file.Path)
			}
			data, err = io.ReadAll(reader)
			if err != nil {
				return nil, fmt.Errorf("%s fixture payload failed", file.Path)
			}
		}
		plain[file.Path] = data
	}
	output := append([]fileFixture(nil), files...)
	for index, file := range output {
		data := plain[file.Path]
		switch {
		case file.Path == "config.yaml":
			data, err = normalizeConfig(data)
		case file.Path == "manifest.age":
			data, err = normalizeManifest(data, raw, plain)
		case strings.HasSuffix(file.Path, ".age") && file.Path != "identity.age":
			data, err = normalizeEntry(data)
		}
		if err != nil {
			return nil, fmt.Errorf("normalize %s: %w", file.Path, err)
		}
		output[index].Content = base64.StdEncoding.EncodeToString(data)
		output[index].Size = int64(len(data))
		output[index].SHA256 = hashBytes(data)
	}
	return output, nil
}

func comparisonProjection(value fixture) ([]byte, error) {
	// Deep copy: deriving a projection must never modify captured oracle bytes.
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	var projected fixture
	if err = json.Unmarshal(encoded, &projected); err != nil {
		return nil, err
	}
	projected.Oracle.CaptureOS = "<native>"
	for index, vault := range projected.Vaults {
		if !reflect.DeepEqual(vault.Files, vault.Migration.After.Files) {
			return nil, errors.New("post-migration file snapshots disagree")
		}
		for j, entry := range vault.Entries {
			var compact bytes.Buffer
			if err = json.Compact(&compact, entry.Expected); err != nil {
				return nil, err
			}
			if compact.String() != entry.ExpectedJSON {
				return nil, errors.New("exact entry JSON and decoded observation disagree")
			}
			if !bytes.Equal(entry.Expected, entry.BeforeExpected) || entry.ExpectedJSON != entry.BeforeJSON {
				return nil, errors.New("entry changed across migration")
			}
			normalized, normalizeErr := normalizeEntry([]byte(entry.ExpectedJSON))
			if normalizeErr != nil {
				return nil, normalizeErr
			}
			vault.Entries[j].Expected = normalized
			vault.Entries[j].BeforeExpected = normalized
			vault.Entries[j].ExpectedJSON = string(normalized)
			vault.Entries[j].BeforeJSON = string(normalized)
		}
		vault.Files, err = normalizeFiles(vault.Files)
		if err != nil {
			return nil, err
		}
		vault.Migration.Before.Files, err = normalizeFiles(vault.Migration.Before.Files)
		if err != nil {
			return nil, err
		}
		vault.Migration.After.Files, err = normalizeFiles(vault.Migration.After.Files)
		if err != nil {
			return nil, err
		}
		// Windows stat reports generic writable file/directory bits, not Unix modes.
		// Only a Windows-labeled live capture receives this platform projection.
		if value.Oracle.CaptureOS == "windows" {
			normalizeMode := func(files []fileFixture, dirs []directoryFixture) error {
				for i := range files {
					if files[i].Mode != 0666 {
						return errors.New("unexpected Windows file mode")
					}
					files[i].Mode = 0600
				}
				for i := range dirs {
					if dirs[i].Mode != 0777 {
						return errors.New("unexpected Windows directory mode")
					}
					dirs[i].Mode = 0700
				}
				return nil
			}
			if err = normalizeMode(vault.Files, vault.Directories); err != nil {
				return nil, err
			}
			if err = normalizeMode(vault.Migration.Before.Files, vault.Migration.Before.Directories); err != nil {
				return nil, err
			}
			if err = normalizeMode(vault.Migration.After.Files, vault.Migration.After.Directories); err != nil {
				return nil, err
			}
		}
		projected.Vaults[index] = vault
	}
	return json.Marshal(struct {
		Version string  `json:"comparison_version"`
		Capture fixture `json:"capture"`
	}{comparisonVersion, projected})
}

func hashBytes(data []byte) string { sum := sha256.Sum256(data); return hex.EncodeToString(sum[:]) }
