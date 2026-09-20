// Command cxfgen freezes the CXF importer contract from an immutable Go tree.
// It creates only synthetic in-memory archives and never reads a user vault.
package main

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
)

const (
	oracleCommit  = "fca3f894"
	oracleRelease = "unreleased"
)

type oracleMeta struct {
	Commit          string   `json:"commit"`
	CommitSHA       string   `json:"commit_sha"`
	Release         string   `json:"release"`
	SourceFiles     []string `json:"source_files"`
	SourceDigest    string   `json:"source_digest"`
	GeneratorFiles  []string `json:"generator_files"`
	GeneratorDigest string   `json:"generator_digest"`
}

type fixture struct {
	SchemaVersion int               `json:"schema_version"`
	Oracle        oracleMeta        `json:"oracle"`
	Cases         []fixtureCase     `json:"cases"`
	Scope         map[string]string `json:"scope"`
}

type fixtureCase struct {
	ID       string   `json:"id"`
	InputB64 string   `json:"input_b64"`
	Expected expected `json:"expected"`
}

type expected struct {
	Entries       []entry `json:"entries,omitempty"`
	ErrorContains string  `json:"error_contains,omitempty"`
}

type entry struct {
	Path       string         `json:"path"`
	Data       map[string]any `json:"data"`
	Warnings   []string       `json:"warnings"`
	SecretType string         `json:"secret_type,omitempty"`
}

func main() {
	output := flag.String("output", "testdata/port/import/cxf.json", "fixture path")
	check := flag.Bool("check", false, "verify provenance and execute the detached oracle")
	flag.Parse()
	root := repositoryRoot()
	meta, err := metadata(root)
	if err != nil {
		fail(err)
	}
	if *check {
		if checkErr := checkFixture(root, *output, meta); checkErr != nil {
			fail(checkErr)
		}
		fmt.Println("PASS Go CXF oracle fixture (19 synthetic cases)")
		return
	}
	cases, err := runOracle(root)
	if err != nil {
		fail(err)
	}
	result := fixture{
		SchemaVersion: 1,
		Oracle:        meta,
		Cases:         cases,
		Scope: map[string]string{
			"source": "synthetic CXF zip bytes only; no vault, keychain, or home access",
			"native": "portable parser behavior only; privileged runtime remains unproven",
			"limits": "oversized source and entry limits are separately exercised by Rust unit/integration tests",
		},
	}
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		fail(err)
	}
	data = append(data, '\n')
	path := filepath.Join(root, *output)
	if err = os.MkdirAll(filepath.Dir(path), 0750); err != nil {
		fail(err)
	}
	if err = os.WriteFile(path, data, 0600); err != nil {
		fail(err)
	}
	fmt.Println("WROTE", *output)
}

func fail(err error) {
	if err != nil {
		panic(err)
	}
}

func repositoryRoot() string {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		panic("locate cxf generator")
	}
	root, err := filepath.Abs(filepath.Join(filepath.Dir(file), "..", "..", "..", ".."))
	fail(err)
	return root
}

func sourceFiles(root string) ([]string, error) {
	set := make(map[string]struct{})
	// These are the local Go packages in `go list -deps ./internal/importer`.
	// Keeping the closure explicit makes provenance reviewable while including
	// helpers pulled in by internal/importer -> crypto -> vault.
	for _, dir := range []string{
		"internal/config", "internal/crypto", "internal/errors", "internal/fsutil",
		"internal/fsutil/safepath", "internal/importer", "internal/mcp/masking",
		"internal/redact", "internal/secrets", "internal/vault", "internal/vault/taint",
	} {
		err := filepath.Walk(filepath.Join(root, dir), func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if info.IsDir() || !strings.HasSuffix(info.Name(), ".go") || strings.HasSuffix(info.Name(), "_test.go") {
				return nil
			}
			rel, err := filepath.Rel(root, path)
			if err != nil {
				return err
			}
			set[filepath.ToSlash(rel)] = struct{}{}
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	files := make([]string, 0, len(set))
	for file := range set {
		files = append(files, file)
	}
	sort.Strings(files)
	return files, nil
}

func gitShow(root, commit, name string) ([]byte, error) {
	// #nosec G204 -- fixed git operation with the pinned commit and repository source paths
	cmd := exec.Command("git", "-C", root, "show", commit+":"+name)
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("read pinned %s: %w", name, err)
	}
	return out, nil
}

func digestFiles(root, commit string, names []string) (string, error) {
	h := sha256.New()
	for _, name := range names {
		pinned, err := gitShow(root, commit, name)
		if err != nil {
			return "", err
		}
		// #nosec G304 -- source path enumerated from fixed repository directories
		current, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(name)))
		if err != nil {
			return "", fmt.Errorf("read current %s: %w", name, err)
		}
		if !bytes.Equal(current, pinned) {
			return "", fmt.Errorf("source %s differs from pinned oracle %s", name, commit)
		}
		_, _ = h.Write([]byte(name))
		_, _ = h.Write([]byte{0})
		_, _ = h.Write(pinned)
		_, _ = h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func digestCurrent(root string, names []string) (string, error) {
	h := sha256.New()
	for _, name := range names {
		// #nosec G304 -- generator path is a compiled-in repository filename
		data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(name)))
		if err != nil {
			return "", err
		}
		_, _ = h.Write([]byte(name))
		_, _ = h.Write([]byte{0})
		_, _ = h.Write(data)
		_, _ = h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func metadata(root string) (oracleMeta, error) {
	sources, err := sourceFiles(root)
	if err != nil {
		return oracleMeta{}, err
	}
	commitSHA, err := gitShowCommit(root, oracleCommit)
	if err != nil {
		return oracleMeta{}, err
	}
	sourceDigest, err := digestFiles(root, oracleCommit, sources)
	if err != nil {
		return oracleMeta{}, err
	}
	generatorFiles := []string{"scripts/rust-port/cmd/cxfgen/main.go"}
	generatorDigest, err := digestCurrent(root, generatorFiles)
	if err != nil {
		return oracleMeta{}, err
	}
	return oracleMeta{oracleCommit, commitSHA, oracleRelease, sources, sourceDigest, generatorFiles, generatorDigest}, nil
}

func gitShowCommit(root, commit string) (string, error) {
	// #nosec G204 -- resolves the compiled-in oracle commit using fixed git arguments
	out, err := exec.Command("git", "-C", root, "rev-parse", commit+"^{commit}").Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

func archiveTree(root string) (string, error) {
	// #nosec G204 -- archives only the compiled-in oracle commit; no shell
	out, err := exec.Command("git", "-C", root, "archive", "--format=tar", oracleCommit).Output()
	if err != nil {
		return "", err
	}
	tree, err := os.MkdirTemp("", "cxf-oracle-")
	if err != nil {
		return "", err
	}
	keep := false
	defer func() {
		if !keep {
			_ = os.RemoveAll(tree)
		}
	}()
	tr := tar.NewReader(bytes.NewReader(out))
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return "", err
		}
		name := filepath.Clean(filepath.FromSlash(h.Name))
		if name == "." || filepath.IsAbs(name) || strings.HasPrefix(name, ".."+string(filepath.Separator)) {
			return "", fmt.Errorf("unsafe oracle path %q", h.Name)
		}
		path := filepath.Join(tree, name)
		if h.FileInfo().IsDir() {
			if err = os.MkdirAll(path, 0750); err != nil {
				return "", err
			}
			continue
		}
		if err = os.MkdirAll(filepath.Dir(path), 0750); err != nil {
			return "", err
		}
		data, err := io.ReadAll(tr)
		if err != nil {
			return "", err
		}
		if err = os.WriteFile(path, data, 0600); err != nil {
			return "", err
		}
	}
	keep = true
	return tree, nil
}

const oracleProgram = `package main

import (
  "archive/zip"
  "bytes"
  "encoding/base64"
  "encoding/json"
  "fmt"
  "os"
 "sort"
  "strings"
  "time"

  "github.com/danieljustus/symaira-vault/internal/importer"
)

type Case struct { ID string ` + "`json:\"id\"`" + `; InputB64 string ` + "`json:\"input_b64\"`" + `; Expected Expected ` + "`json:\"expected\"`" + ` }
type Expected struct { Entries []Entry ` + "`json:\"entries,omitempty\"`" + `; ErrorContains string ` + "`json:\"error_contains,omitempty\"`" + ` }
type Entry struct { Path string ` + "`json:\"path\"`" + `; Data map[string]any ` + "`json:\"data\"`" + `; Warnings []string ` + "`json:\"warnings\"`" + `; SecretType string ` + "`json:\"secret_type,omitempty\"`" + ` }
func fail(e error) { if e != nil { panic(e) } }
func b64(v []byte) string { return base64.StdEncoding.EncodeToString(v) }
func zipData(files map[string][]byte) []byte { var b bytes.Buffer; z:=zip.NewWriter(&b); names:=make([]string,0,len(files)); for name:=range files { names=append(names,name) }; sort.Strings(names); for _,name:=range names { data:=files[name]; h:=&zip.FileHeader{Name:name,Method:zip.Deflate}; h.SetModTime(time.Unix(0,0)); w,e:=z.CreateHeader(h);fail(e);_,e=w.Write(data);fail(e) }; fail(z.Close()); return b.Bytes() }
func run(id string, archive []byte) Case { imp,e:=importer.New(importer.FormatCXF);fail(e); got,err:=imp.Parse(bytes.NewReader(archive)); c:=Case{ID:id,InputB64:b64(archive)}; if err!=nil { text:=err.Error(); marker:=text; for _,candidate:=range []string{"open cxf zip","no CXF JSON document","parse CXF JSON document"} { if strings.Contains(text,candidate) { marker=candidate; break } }; c.Expected.ErrorContains=marker; return c }; c.Expected.Entries=make([]Entry,0,len(got)); for _,entry:=range got { st:="";if entry.SecretMetadata!=nil {st=string(entry.SecretMetadata.Type)};c.Expected.Entries=append(c.Expected.Entries,Entry{entry.Path,entry.Data,entry.Warnings,st}) }; return c }
func payload() []byte {
  field := func(value string) map[string]any { return map[string]any{"value": value} }
  login := map[string]any{
    "id": "login", "title": "Login / Main",
    "scope": map[string]any{"urls": []string{" https://example.test/login ", "https://example.test"}},
    "tags": []string{"fixture", "nested"},
    "credentials": []any{
      map[string]any{"type": "basic-auth", "username": field("fixture-user"), "password": field("fixture-pass")},
      map[string]any{"type": "totp", "secret": "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP", "algorithm": "sha256", "digits": 8, "period": 60},
    },
  }
  passkeys := map[string]any{
    "id": "passkeys", "title": "Passkeys",
    "credentials": []any{
      map[string]any{"type": "passkey", "credentialId": "one", "rpId": "example.test"},
      map[string]any{"type": "passkey", "credentialId": "two", "rpId": "example.test"},
    },
  }
  notes := map[string]any{
    "id": "notes", "title": "Notes",
    "credentials": []any{
      map[string]any{"type": "note", "content": field("first")},
      map[string]any{"type": "note", "content": field("second")},
    },
  }
  ssh := map[string]any{
    "id": "ssh", "title": "SSH",
    "credentials": []any{map[string]any{"type": "cryptographic-key", "privateKey": "dGVzdC1rZXktbWF0ZXJpYWw"}},
  }
  card := map[string]any{
    "id": "card", "title": "Card",
    "credentials": []any{map[string]any{
      "type": "credit-card", "number": field("4111111111111111"), "fullName": field("Fixture User"),
      "verificationNumber": field("123"), "expiryDate": field("2027-08"), "cardType": field("visa"),
    }},
  }
  mixed := map[string]any{
    "id": "mixed", "title": "Mixed",
    "credentials": []any{
      map[string]any{"type": "address", "city": field("fixture")},
      map[string]any{"type": "file", "name": "fixture.txt"},
      map[string]any{"type": "totp", "secret": "not-a-valid-base32!!"},
      map[string]any{"type": "mystery"},
      map[string]any{"type": "basic-auth", "username": field("u"), "password": field("p")},
    },
  }
  x := map[string]any{
    "version": map[string]any{"major": 1, "minor": 0},
    "accounts": []any{map[string]any{
      "id": "acct",
      "collections": []any{map[string]any{
        "title": "Work", "items": []any{map[string]any{"item": "login"}},
        "subCollections": []any{map[string]any{"title": "Nested", "items": []any{map[string]any{"item": "login"}}}},
      }},
      "items": []any{login, passkeys, notes, ssh, card, mixed},
    }},
  }
  b, e := json.Marshal(x)
  fail(e)
  return b
}
func nullPayload() []byte {
  x := map[string]any{
    "version": map[string]any{"major": 1, "minor": 0},
    "accounts": []any{nil, map[string]any{
      "collections": []any{nil, map[string]any{
        "title": nil, "name": "Legacy", "items": []any{nil, map[string]any{"item": "null-item"}},
        "subCollections": []any{nil},
      }},
      "items": []any{nil, map[string]any{
        "id": "null-item", "title": nil, "name": "Null Name", "scope": nil,
        "credentials": []any{nil, map[string]any{"type": "basic-auth", "username": nil, "password": map[string]any{"value": nil}}},
        "tags": []any{nil, "tag"},
      }},
    }},
  }
  b, e := json.Marshal(x); fail(e); return b
}
func malformedCredentialPayload() []byte {
  item := map[string]any{
    "id": "malformed", "title": "Malformed Credentials", "tags": []string{"fixture"},
    "credentials": []any{
      map[string]any{"type": "basic-auth", "username": 7, "password": map[string]any{"value": "ok"}},
      map[string]any{"type": "note", "content": 7},
      map[string]any{"type": "totp", "secret": 7, "algorithm": "SHA1", "digits": 6, "period": 30},
      map[string]any{"type": "cryptographic-key", "keyType": 7, "privateKey": "fixture-key"},
      map[string]any{"type": "credit-card", "number": 7, "fullName": "Fixture User", "cardType": "visa", "verificationNumber": "123", "expiryDate": "2027-08"},
      7, "not-an-object", nil,
    },
  }
  x := map[string]any{
    "version": map[string]any{"major": 1, "minor": 0},
    "accounts": []any{map[string]any{"id": "account", "items": []any{item}}},
  }
  b, e := json.Marshal(x); fail(e); return b
}

func totpEdgesPayload() []byte {
 items:=[]any{}
 for n, credential := range []map[string]any{
 {"type":"totp","secret":"JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP&ignored=value"},
 {"type":"totp","secret":" JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP ","algorithm":" sha256 ","digits":8,"period":45},
 {"type":"totp","secret":"JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP","digits":7},
 {"type":"totp","secret":"JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP","period":int64(9223372036854775807)},
 {"type":"totp","secret":"JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP","algorithm":"SHA1&digits=8"},
 } { items=append(items,map[string]any{"title":fmt.Sprintf("totp-%d",n),"tags":[]string{"fixture"},"credentials":[]any{credential}}) }
 b,e:=json.Marshal(map[string]any{"accounts":[]any{map[string]any{"items":items}}});fail(e);return b
}
func malformedContainerPayload(field string) []byte {
  item := map[string]any{"id": "item", "title": "Item", "credentials": []any{map[string]any{"type": "note", "content": "ok"}}}
  account := map[string]any{"id": "account", "items": []any{item}}
  switch field {
  case "credentials":
    item["credentials"] = "wrong"
  case "tags":
    item["tags"] = []any{7}
  }
  x := map[string]any{"version": map[string]any{"major": 1, "minor": 0}, "accounts": []any{account}}
  b, e := json.Marshal(x); fail(e); return b
}

func invalidTypedPayload(kind string) []byte {
  item := map[string]any{"id": "item", "title": "Item", "credentials": []any{map[string]any{"type": "note", "content": "ok"}}}
  account := map[string]any{"id": "account", "collections": []any{}, "items": []any{item}}
  x := map[string]any{"version": map[string]any{"major": 1, "minor": 0}, "accounts": []any{account}}
  switch kind {
  case "version":
    x["version"] = map[string]any{"major": "wrong", "minor": 0}
  case "account-id":
    account["id"] = 7
  case "account-username":
    account["username"] = 7
  case "account-email":
    account["email"] = []any{"wrong"}
  case "collection-id":
    account["collections"] = []any{map[string]any{"id": 7, "title": "Collection", "items": []any{}}}
  case "linked-account":
    account["collections"] = []any{map[string]any{"id": "collection", "title": "Collection", "items": []any{map[string]any{"item": "item", "account": 7}}}}
  }
  b, e := json.Marshal(x); fail(e); return b
}
func main() { p:=payload(); n:=nullPayload(); cases:=[]Case{run("CXF-019-totp-structured",zipData(map[string][]byte{"payload.json":totpEdgesPayload()})),run("CXF-001-features",zipData(map[string][]byte{"manifest.json":[]byte("{\"version\":1}"),"nested/payload.json":p})),run("CXF-002-preferred-payload",zipData(map[string][]byte{"manifest.json":[]byte("{\"accounts\":[]}"),"nested/payload.json":p,"export.json":[]byte("{\"accounts\":[]}")})),run("CXF-003-largest-json",zipData(map[string][]byte{"manifest.json":[]byte("{\"accounts\":[]}"),"export.json":p})),run("CXF-004-invalid-zip",[]byte("not a zip archive")),run("CXF-005-no-json",zipData(map[string][]byte{"readme.txt":[]byte("fixture")})),run("CXF-006-invalid-json",zipData(map[string][]byte{"manifest.json":[]byte("{not-json")})),run("CXF-007-null-fields",zipData(map[string][]byte{"nested/payload.json":n})),run("CXF-008-trailing-json",zipData(map[string][]byte{"nested/payload.json":append(n, []byte(" trailing")...)})),run("CXF-009-invalid-version-type",zipData(map[string][]byte{"nested/payload.json":invalidTypedPayload("version")})),run("CXF-010-invalid-account-id",zipData(map[string][]byte{"nested/payload.json":invalidTypedPayload("account-id")})),run("CXF-011-invalid-collection-id",zipData(map[string][]byte{"nested/payload.json":invalidTypedPayload("collection-id")})),run("CXF-012-invalid-linked-account",zipData(map[string][]byte{"nested/payload.json":invalidTypedPayload("linked-account")})),run("CXF-013-null-top-level",zipData(map[string][]byte{"nested/payload.json":[]byte("null")})),run("CXF-014-malformed-credential-values",zipData(map[string][]byte{"nested/payload.json":malformedCredentialPayload()})),run("CXF-015-malformed-credentials-container",zipData(map[string][]byte{"nested/payload.json":malformedContainerPayload("credentials")})),run("CXF-016-malformed-tags-container",zipData(map[string][]byte{"nested/payload.json":malformedContainerPayload("tags")})),run("CXF-017-invalid-account-username",zipData(map[string][]byte{"nested/payload.json":invalidTypedPayload("account-username")})),run("CXF-018-invalid-account-email",zipData(map[string][]byte{"nested/payload.json":invalidTypedPayload("account-email")}))}; enc:=json.NewEncoder(os.Stdout);enc.SetEscapeHTML(false);fail(enc.Encode(cases)) }
`

func runOracle(root string) ([]fixtureCase, error) {
	tree, err := archiveTree(root)
	if err != nil {
		return nil, err
	}
	defer func() { _ = os.RemoveAll(tree) }()
	path := filepath.Join(tree, "cmd", "cxforacle", "main.go")
	if err = os.MkdirAll(filepath.Dir(path), 0750); err != nil {
		return nil, err
	}
	if err = os.WriteFile(path, []byte(oracleProgram), 0600); err != nil {
		return nil, err
	}
	cmd := exec.Command("go", "run", "./cmd/cxforacle")
	cmd.Dir = tree
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("detached CXF oracle: %w: %s", err, out)
	}
	var cases []fixtureCase
	if err = json.Unmarshal(out, &cases); err != nil {
		return nil, err
	}
	return cases, nil
}

func checkFixture(root, requested string, meta oracleMeta) error {
	// #nosec G304 -- local CLI explicitly selects the fixture file to verify
	data, err := os.ReadFile(filepath.Join(root, requested))
	if err != nil {
		return err
	}
	var got fixture
	if err = json.Unmarshal(data, &got); err != nil {
		return err
	}
	if got.SchemaVersion != 1 || got.Oracle.Commit != meta.Commit || got.Oracle.CommitSHA != meta.CommitSHA ||
		got.Oracle.SourceDigest != meta.SourceDigest || got.Oracle.GeneratorDigest != meta.GeneratorDigest ||
		!sameStrings(got.Oracle.SourceFiles, meta.SourceFiles) || !sameStrings(got.Oracle.GeneratorFiles, meta.GeneratorFiles) {
		return errors.New("CXF fixture provenance changed; regenerate from the pinned Go oracle")
	}
	want, err := runOracle(root)
	if err != nil {
		return err
	}
	if len(got.Cases) != len(want) {
		return fmt.Errorf("CXF case cardinality %d, want %d", len(got.Cases), len(want))
	}
	for i := range want {
		if got.Cases[i].ID != want[i].ID || got.Cases[i].InputB64 != want[i].InputB64 || !sameJSON(got.Cases[i].Expected, want[i].Expected) {
			return fmt.Errorf("CXF case %d (%s) drifted; regenerate from the Go oracle", i, want[i].ID)
		}
	}
	return nil
}

func sameStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func sameJSON(a, b any) bool {
	x, err := json.Marshal(a)
	if err != nil {
		return false
	}
	y, err := json.Marshal(b)
	if err != nil {
		return false
	}
	return bytes.Equal(x, y)
}
