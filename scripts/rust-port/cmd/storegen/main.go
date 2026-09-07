// Command storegen freezes the read-only vault layout and entry contract.
package main

import (
	"archive/tar"
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
	"reflect"
	"runtime"
	"sort"
	"strings"
)

const (
	maxArchiveBytes int64 = 64 << 20
	oracleCommit          = "caadd5e"
	oracleRelease         = "v0.22.1"
)

var sourceFiles = []string{
	"internal/config/config.go", "internal/config/config_load.go", "internal/config/config_save.go",
	"internal/config/paths.go", "internal/config/schema.go", "internal/fsutil/reexport.go",
	"internal/vault/entry.go", "internal/vault/entry_readwrite.go", "internal/vault/entry_validate.go",
	"internal/vault/recipients.go", "internal/vault/types.go", "internal/vault/vault.go",
}
var generatorFiles = []string{"scripts/rust-port/cmd/storegen/main.go", "scripts/rust-port/cmd/storegen/main_test.go"}
var requiredVaults = []string{"fresh", "legacy"}
var requiredEntries = []string{"minimal", "full", "nested/large"}
var requiredTypeVectors = []string{"empty", "ssh", "certificate", "database", "github_pat", "github_fine_grained", "github_malformed", "aws", "aws_malformed", "totp", "totp_malformed", "jwt", "jwt_malformed", "basic", "basic_malformed", "generic_api_key", "generic_malformed", "password", "explicit_custom", "explicit_payment", "unknown_explicit", "path_seed", "field_certificate", "field_connection_string", "path_api_key"}

// oracleProgram is deliberately compiled and run from an extracted caadd5e
// tree. storegen itself never imports the current vault implementation.
const oracleProgram = `package main

import (
  "crypto/sha256"
  "encoding/base64"
  "encoding/hex"
  "encoding/json"
  "errors"
  "fmt"
  "os"
  "path/filepath"
  "sort"
  "strings"

  "filippo.io/age"
  vaultconfig "github.com/danieljustus/symaira-vault/internal/config"
  vaultpkg "github.com/danieljustus/symaira-vault/internal/vault"
)

const identityText = "AGE-SECRET-KEY-1HS3YTK69EJH0ZYM8ANNNDWQMPT7ZMLPYGTMC47F5T4EDJ5N7EYMQ4L5CDL"

type fileFixture struct { Path string ~BT~json:"path"~BT~; Mode uint32 ~BT~json:"mode"~BT~; Size int64 ~BT~json:"size"~BT~; SHA256 string ~BT~json:"sha256"~BT~; Content string ~BT~json:"content"~BT~ }
type directoryFixture struct { Path string ~BT~json:"path"~BT~; Mode uint32 ~BT~json:"mode"~BT~ }
type entryFixture struct { Name string ~BT~json:"name"~BT~; Path string ~BT~json:"path"~BT~; StoragePath string ~BT~json:"storage_path"~BT~; Expected json.RawMessage ~BT~json:"expected"~BT~; ExpectedJSON string ~BT~json:"expected_json"~BT~; BeforeExpected json.RawMessage ~BT~json:"before_expected,omitempty"~BT~; BeforeJSON string ~BT~json:"before_json,omitempty"~BT~ }
type presence struct { Config bool ~BT~json:"config"~BT~; Identity bool ~BT~json:"identity"~BT~; Recipients bool ~BT~json:"recipients"~BT~ }
type tree struct { Files []fileFixture ~BT~json:"files"~BT~; Directories []directoryFixture ~BT~json:"directories"~BT~ }
type migration struct { Before tree ~BT~json:"before"~BT~; After tree ~BT~json:"after"~BT~; Marker string ~BT~json:"marker"~BT~; MarkerSHA256 string ~BT~json:"marker_sha256"~BT~; DataPreserved bool ~BT~json:"data_preserved"~BT~ }
type vaultFixture struct { Name string ~BT~json:"name"~BT~; Layout string ~BT~json:"layout"~BT~; Files []fileFixture ~BT~json:"files"~BT~; Directories []directoryFixture ~BT~json:"directories"~BT~; Entries []entryFixture ~BT~json:"entries"~BT~; Presence presence ~BT~json:"presence"~BT~; Migration migration ~BT~json:"migration"~BT~; TypeVectors []typeVector ~BT~json:"type_vectors"~BT~ }
type entrySpec struct { name, path string; data map[string]any; secretMeta map[string]any }
type typeVector struct { Name string ~BT~json:"name"~BT~; Value string ~BT~json:"value"~BT~; Path string ~BT~json:"path,omitempty"~BT~; Field string ~BT~json:"field,omitempty"~BT~; Explicit string ~BT~json:"explicit,omitempty"~BT~; Expected string ~BT~json:"expected"~BT~ }

func specs() []entrySpec { return []entrySpec{
  {name:"minimal", path:"minimal", data:map[string]any{"username":"fixture-user", "password":"fake-password-v1"}},
  {name:"full", path:"full", data:map[string]any{"username":"fixture-full-user", "url":"https://example.invalid/fixture", "api_key":"«redacted:AKIA…»", "nested":map[string]any{"region":"test-region", "flags":[]any{true,false,7}}, "items":[]any{"one",map[string]any{"two":"three"}}}, secretMeta:map[string]any{"type":"custom", "usage_hint":"fixture only", "auto_rotate":true}},
  {name:"nested/large", path:"nested/large", data:map[string]any{"payload":strings.Repeat("large-fixture-value-",5000), "count":5000, "enabled":true, "nested":map[string]any{"leaf":"deep-fixture-value"}}},
} }

func typeVectors() []typeVector {
  vectors:=[]typeVector{
    {Name:"empty",Value:""}, {Name:"ssh",Value:"-----BEGIN OPENSSH PRIVATE KEY-----"}, {Name:"certificate",Value:"-----BEGIN CERTIFICATE-----"},
    {Name:"database",Value:"postgres://fixture"}, {Name:"github_pat",Value:"ghp_"+strings.Repeat("a",36)},
    {Name:"github_fine_grained",Value:"github_pat_"+strings.Repeat("a",22)+"_"+strings.Repeat("b",59)}, {Name:"github_malformed",Value:"ghp_"+strings.Repeat("a",35)+"!"},
    {Name:"aws",Value:"AKIA"+strings.Repeat("A",16)}, {Name:"aws_malformed",Value:"AKIA"+strings.Repeat("A",15)+"!"}, {Name:"totp",Value:strings.Repeat("A",16)},
    {Name:"totp_malformed",Value:"ABCDEFGHJKLMNPQ0"}, {Name:"jwt",Value:"a.b.c"}, {Name:"jwt_malformed",Value:"a.b."}, {Name:"basic",Value:"user:pass"},
    {Name:"basic_malformed",Value:"user:"}, {Name:"generic_api_key",Value:strings.Repeat("x",32)}, {Name:"generic_malformed",Value:strings.Repeat("x",31)+"!"}, {Name:"password",Value:"ordinary"},
    {Name:"explicit_custom",Value:"ordinary",Explicit:"custom"}, {Name:"explicit_payment",Value:"ordinary",Explicit:"payment"}, {Name:"unknown_explicit",Value:"ordinary",Explicit:"not-a-type"},
    {Name:"path_seed",Value:"ordinary",Path:"wallet/seed"}, {Name:"field_certificate",Value:"ordinary",Field:"cert_pem"}, {Name:"field_connection_string",Value:"ordinary",Field:"connection_string"}, {Name:"path_api_key",Value:"ordinary",Path:"service/api-key"},
  }
  for i:=range vectors { if vectors[i].Path!=""||vectors[i].Field!=""||vectors[i].Explicit!="" { vectors[i].Expected=string(vaultpkg.InferSecretType(vectors[i].Path,vectors[i].Field,vectors[i].Value,vectors[i].Explicit)) } else { vectors[i].Expected=string(vaultpkg.DetectSecretType(vectors[i].Value)) } }
  return vectors
}

func snapshot(root string) (tree,error) { var files []fileFixture; var dirs []directoryFixture
  err:=filepath.Walk(root,func(path string, info os.FileInfo, walkErr error) error { if walkErr!=nil{return walkErr}; if path==root{return nil}; rel,err:=filepath.Rel(root,path);if err!=nil{return err}; rel=filepath.Clean(rel); mode:=uint32(info.Mode().Perm()); if info.IsDir(){dirs=append(dirs,directoryFixture{filepath.ToSlash(rel),mode});return nil};if !info.Mode().IsRegular(){return errors.New("non-regular fixture item")};data,err:=os.ReadFile(path);if err!=nil{return err};sum:=sha256.Sum256(data);files=append(files,fileFixture{filepath.ToSlash(rel),mode,int64(len(data)),hex.EncodeToString(sum[:]),base64.StdEncoding.EncodeToString(data)});return nil })
  sort.Slice(files,func(i,j int)bool{return files[i].Path<files[j].Path});sort.Slice(dirs,func(i,j int)bool{return dirs[i].Path<dirs[j].Path});return tree{files,dirs},err }
func fixedIdentity()(*age.X25519Identity,error){return age.ParseX25519Identity(identityText)}
func treeHas(tree tree,path string) bool {for _,f:=range tree.Files{if f.Path==path{return true}};return false}
func build(legacy bool)(vaultFixture,error){
  dir,err:=os.MkdirTemp("","symvault-store-oracle-");if err!=nil{return vaultFixture{},err};defer os.RemoveAll(dir)
  identity,err:=fixedIdentity();if err!=nil{return vaultFixture{},err}; legacyMode:=legacy;cfg:=vaultconfig.Default();cfg.VaultDir=dir;cfg.Vault=&vaultconfig.VaultConfig{FormatVersion:2,LegacyMode:&legacyMode,SearchIndex:false}
  if err=vaultpkg.Init(dir,identity,cfg);err!=nil{return vaultFixture{},fmt.Errorf("init: %w",err)}
  if err=os.WriteFile(filepath.Join(dir,"recipients.txt"),[]byte(identity.Recipient().String()+"\n"),0600);err!=nil{return vaultFixture{},err}
  entries:=make([]entryFixture,0,len(specs()))
  for _,spec:=range specs(){e:=&vaultpkg.Entry{Data:spec.data};if spec.secretMeta!=nil{raw,_:=json.Marshal(spec.secretMeta);if err=json.Unmarshal(raw,&e.SecretMetadata);err!=nil{return vaultFixture{},err}}
    if err=vaultpkg.WriteEntry(dir,spec.path,e,identity);err!=nil{return vaultFixture{},fmt.Errorf("write %s: %w",spec.path,err)}
    entries=append(entries,entryFixture{Name:spec.name,Path:spec.path})
  }
  if legacy { // Construct the pre-migration tree exactly; Open below performs the real migration.
    entriesDir:=filepath.Join(dir,"entries"); for _,spec:=range specs(){src:=filepath.Join(entriesDir,filepath.FromSlash(spec.path)+".age");dst:=filepath.Join(dir,filepath.FromSlash(spec.path)+".age");if err=os.MkdirAll(filepath.Dir(dst),0700);err!=nil{return vaultFixture{},err};if err=os.Rename(src,dst);err!=nil{return vaultFixture{},err}};if err=os.RemoveAll(entriesDir);err!=nil{return vaultFixture{},err}
  }
  before,err:=snapshot(dir);if err!=nil{return vaultFixture{},err}
  for _,spec:=range specs(){got,readErr:=vaultpkg.ReadEntry(dir,spec.path,identity);if readErr!=nil{return vaultFixture{},fmt.Errorf("pre-read %s: %w",spec.path,readErr)};raw,_:=json.Marshal(got);for i:=range entries{if entries[i].Name==spec.name{entries[i].BeforeExpected=raw;entries[i].BeforeJSON=string(raw)}}}
  if _,err=vaultpkg.Open(dir,identity);err!=nil{return vaultFixture{},fmt.Errorf("open migration: %w",err)}
  after,err:=snapshot(dir);if err!=nil{return vaultFixture{},err}
  for _,spec:=range specs(){got,readErr:=vaultpkg.ReadEntry(dir,spec.path,identity);if readErr!=nil{return vaultFixture{},fmt.Errorf("post-read %s: %w",spec.path,readErr)};raw,_:=json.Marshal(got);storage:=filepath.Join(dir,"entries",filepath.FromSlash(spec.path)+".age");if legacy{storage=filepath.Join(dir,"entries",filepath.FromSlash(spec.path)+".age")};rel,_:=filepath.Rel(dir,storage);for i:=range entries{if entries[i].Name==spec.name{entries[i].Expected=raw;entries[i].ExpectedJSON=string(raw);entries[i].Path=spec.path;entries[i].StoragePath=filepath.ToSlash(rel)}}}
  markerBytes,_:=os.ReadFile(filepath.Join(dir,".symvault-migrated"));markerHash:=sha256.Sum256(markerBytes);dataPreserved:=true;for _,e:=range entries{if len(e.BeforeExpected)==0||len(e.Expected)==0||string(e.BeforeExpected)!=string(e.Expected){dataPreserved=false}}
  return vaultFixture{Name:map[bool]string{true:"legacy",false:"fresh"}[legacy],Layout:map[bool]string{true:"legacy",false:"fresh"}[legacy],Files:after.Files,Directories:after.Directories,Entries:entries,Presence:presence{true,true,true},Migration:migration{before,after,".symvault-migrated",hex.EncodeToString(markerHash[:]),dataPreserved},TypeVectors:typeVectors()},nil
}
func main(){legacy:=false;if len(os.Args)>1&&os.Args[1]=="--legacy"{legacy=true};v,err:=build(legacy);if err!=nil{fmt.Fprintln(os.Stderr,err);os.Exit(1)};json.NewEncoder(os.Stdout).Encode(v)}
`

type fixture struct {
	SchemaVersion int             `json:"schema_version"`
	Oracle        oracle          `json:"oracle"`
	Vaults        []vaultFixture  `json:"vaults"`
	Malformed     []malformedCase `json:"malformed_cases"`
}
type oracle struct {
	Commit          string   `json:"commit"`
	Release         string   `json:"release"`
	SourceFiles     []string `json:"source_files"`
	SourceDigest    string   `json:"source_digest"`
	GeneratorFiles  []string `json:"generator_files"`
	GeneratorDigest string   `json:"generator_digest"`
}
type vaultFixture struct {
	Name        string             `json:"name"`
	Layout      string             `json:"layout"`
	Files       []fileFixture      `json:"files"`
	Directories []directoryFixture `json:"directories"`
	Entries     []entryFixture     `json:"entries"`
	Presence    presence           `json:"presence"`
	Migration   migration          `json:"migration"`
	TypeVectors []typeVector       `json:"type_vectors"`
}
type presence struct {
	Config     bool `json:"config"`
	Identity   bool `json:"identity"`
	Recipients bool `json:"recipients"`
}
type tree struct {
	Files       []fileFixture      `json:"files"`
	Directories []directoryFixture `json:"directories"`
}
type migration struct {
	Before        tree   `json:"before"`
	After         tree   `json:"after"`
	Marker        string `json:"marker"`
	MarkerSHA256  string `json:"marker_sha256"`
	DataPreserved bool   `json:"data_preserved"`
}
type directoryFixture struct {
	Path string `json:"path"`
	Mode uint32 `json:"mode"`
}
type fileFixture struct {
	Path    string `json:"path"`
	Mode    uint32 `json:"mode"`
	Size    int64  `json:"size"`
	SHA256  string `json:"sha256"`
	Content string `json:"content"`
}
type entryFixture struct {
	Name           string          `json:"name"`
	Path           string          `json:"path"`
	StoragePath    string          `json:"storage_path"`
	Expected       json.RawMessage `json:"expected"`
	ExpectedJSON   string          `json:"expected_json"`
	BeforeExpected json.RawMessage `json:"before_expected,omitempty"`
	BeforeJSON     string          `json:"before_json,omitempty"`
}
type typeVector struct {
	Name     string `json:"name"`
	Value    string `json:"value"`
	Path     string `json:"path,omitempty"`
	Field    string `json:"field,omitempty"`
	Explicit string `json:"explicit,omitempty"`
	Expected string `json:"expected"`
}
type malformedCase struct {
	Name  string `json:"name"`
	Input string `json:"input"`
	Path  string `json:"path"`
}

func rootDir() string {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		panic("locate storegen")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", "..", "..", ".."))
}
func digest(root string, names []string, pinned bool) (string, error) {
	sorted := append([]string(nil), names...)
	sort.Strings(sorted)
	h := sha256.New()
	for _, name := range sorted {
		var data []byte
		var err error
		if pinned {
			data, err = exec.Command("git", "-C", root, "show", oracleCommit+":"+name).Output() // #nosec G204 -- executable is fixed git; name is from the compile-time oracle file list
		} else {
			data, err = os.ReadFile(filepath.Join(root, name)) // #nosec G304 -- name is from the compile-time oracle file list
		}
		if err != nil {
			return "", fmt.Errorf("digest %s: %w", name, err)
		}
		h.Write([]byte(name))
		h.Write([]byte{0})
		h.Write(data)
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
func authoritative(root string) (oracle, error) {
	sd, err := digest(root, sourceFiles, true)
	if err != nil {
		return oracle{}, err
	}
	gd, err := digest(root, generatorFiles, false)
	if err != nil {
		return oracle{}, err
	}
	return oracle{oracleCommit, oracleRelease, append([]string(nil), sourceFiles...), sd, append([]string(nil), generatorFiles...), gd}, nil
}
func extractOracleTree(root string) (string, error) {
	dir, err := os.MkdirTemp("", "symvault-store-detached-")
	if err != nil {
		return "", err
	}
	cmd := exec.Command("git", "-C", root, "archive", "--format=tar", oracleCommit) // #nosec G204 -- executable and commit are fixed; root is the selected oracle repository
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return "", err
	}
	if err = cmd.Start(); err != nil {
		return "", err
	}
	tr := tar.NewReader(stdout)
	for {
		hdr, e := tr.Next()
		if errors.Is(e, io.EOF) {
			break
		}
		if e != nil {
			_ = cmd.Wait()
			_ = os.RemoveAll(dir)
			return "", e
		}
		name := filepath.Clean(hdr.Name)
		if name == "." || strings.HasPrefix(name, ".."+string(filepath.Separator)) {
			_ = cmd.Wait()
			_ = os.RemoveAll(dir)
			return "", errors.New("unsafe oracle archive path")
		}
		out := filepath.Join(dir, name)
		switch hdr.Typeflag {
		case tar.TypeDir:
			if e = os.MkdirAll(out, 0750); e != nil {
				return "", e
			}
		case tar.TypeReg:
			if e = os.MkdirAll(filepath.Dir(out), 0750); e != nil {
				return "", e
			}
			if hdr.Mode < 0 || hdr.Mode > int64(^uint32(0)) {
				return "", fmt.Errorf("invalid archive mode %d", hdr.Mode)
			}
			f, e := os.OpenFile(out, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, os.FileMode(uint32(hdr.Mode))) // #nosec G304 -- cleaned archive names cannot escape the controlled tree
			if e != nil {
				return "", e
			}
			n, e := io.Copy(f, io.LimitReader(tr, maxArchiveBytes+1))
			if e == nil && n > maxArchiveBytes {
				e = fmt.Errorf("archive exceeds %d bytes", maxArchiveBytes)
			}
			ce := f.Close()
			if e != nil {
				return "", e
			}
			if ce != nil {
				return "", ce
			}
		}
	}
	if err = cmd.Wait(); err != nil {
		_ = os.RemoveAll(dir)
		return "", fmt.Errorf("git archive: %w", err)
	}
	return dir, nil
}
func runOracle(root string, legacy bool) (vaultFixture, error) {
	tree, err := extractOracleTree(root)
	if err != nil {
		return vaultFixture{}, err
	}
	defer func() { _ = os.RemoveAll(tree) }()
	mainPath := filepath.Join(tree, "cmd", "storeoracle", "main.go")
	if err = os.MkdirAll(filepath.Dir(mainPath), 0750); err != nil {
		return vaultFixture{}, err
	}
	if err = os.WriteFile(mainPath, []byte(strings.ReplaceAll(oracleProgram, "~BT~", "`")), 0600); err != nil {
		return vaultFixture{}, err
	}
	args := []string{"run", "./cmd/storeoracle"}
	if legacy {
		args = append(args, "--legacy")
	}
	cmd := exec.Command("go", args...)
	cmd.Dir = tree
	out, err := cmd.CombinedOutput()
	if err != nil {
		return vaultFixture{}, fmt.Errorf("detached oracle: %w: %s", err, out)
	}
	var v vaultFixture
	if err = json.Unmarshal(out, &v); err != nil {
		return vaultFixture{}, fmt.Errorf("detached oracle output: %w", err)
	}
	return v, nil
}
func migrationFilesPreserved(x vaultFixture) bool {
	before := make(map[string]string, len(x.Migration.Before.Files))
	for _, file := range x.Migration.Before.Files {
		before[strings.TrimPrefix(file.Path, "entries/")] = file.SHA256
	}
	after := make(map[string]string, len(x.Migration.After.Files))
	for _, file := range x.Migration.After.Files {
		if file.Path != ".symvault-migrated" {
			after[strings.TrimPrefix(file.Path, "entries/")] = file.SHA256
		}
	}
	if len(before) != len(after) {
		return false
	}
	for path, digest := range before {
		if after[path] != digest {
			return false
		}
	}
	for _, entry := range x.Entries {
		if entry.BeforeJSON != entry.ExpectedJSON {
			return false
		}
	}
	return true
}

func validate(v fixture, expected oracle) error {
	if err := validateProvenance(v, expected); err != nil {
		return err
	}
	if len(v.Vaults) != 2 {
		return fmt.Errorf("vault cardinality %d, want 2", len(v.Vaults))
	}
	for i, x := range v.Vaults {
		if err := validateVault(i, x); err != nil {
			return err
		}
	}
	if len(v.Malformed) != 3 || v.Malformed[0].Name != "empty" || v.Malformed[1].Name != "not_age" || v.Malformed[2].Name != "bad_stanza" {
		return errors.New("malformed case cardinality/order changed")
	}
	return nil
}

func validateProvenance(v fixture, expected oracle) error {
	if v.SchemaVersion != 1 || v.Oracle.Commit != expected.Commit || v.Oracle.Release != expected.Release || v.Oracle.SourceDigest != expected.SourceDigest || v.Oracle.GeneratorDigest != expected.GeneratorDigest || len(v.Oracle.SourceFiles) != len(sourceFiles) || len(v.Oracle.GeneratorFiles) != len(generatorFiles) {
		return errors.New("store fixture provenance changed")
	}
	return nil
}

func validateVault(i int, x vaultFixture) error {
	if x.Name != requiredVaults[i] || x.Layout != requiredVaults[i] || len(x.Entries) != len(requiredEntries) {
		return fmt.Errorf("vault %d identity/cardinality changed: name=%q layout=%q entries=%d files=%d before=%d after=%d data_preserved=%v marker=%q", i, x.Name, x.Layout, len(x.Entries), len(x.Files), len(x.Migration.Before.Files), len(x.Migration.After.Files), x.Migration.DataPreserved, x.Migration.Marker)
	}
	if len(x.Files) != 9 || len(x.Migration.Before.Files) != 8 || len(x.Migration.After.Files) != 9 {
		return fmt.Errorf("%s file cardinality changed", x.Name)
	}
	if err := validateVaultDirectories(x); err != nil {
		return err
	}
	if err := validateVaultFiles(x); err != nil {
		return err
	}
	return validateVaultEntries(x)
}

func validateVaultDirectories(x vaultFixture) error {
	wantDirs := []string{"entries", "entries/nested"}
	beforeDirs := []string{"entries", "entries/nested"}
	if x.Name == "legacy" {
		wantDirs = []string{"entries", "entries/nested", "nested"}
		beforeDirs = []string{"nested"}
	}
	gotDirs := make([]string, 0, len(x.Directories))
	for _, directory := range x.Directories {
		gotDirs = append(gotDirs, directory.Path)
	}
	if !reflect.DeepEqual(gotDirs, wantDirs) {
		return fmt.Errorf("%s directory path array changed", x.Name)
	}
	gotBeforeDirs := make([]string, 0, len(x.Migration.Before.Directories))
	for _, directory := range x.Migration.Before.Directories {
		gotBeforeDirs = append(gotBeforeDirs, directory.Path)
	}
	if !reflect.DeepEqual(gotBeforeDirs, beforeDirs) {
		return fmt.Errorf("%s pre-migration directory path array changed", x.Name)
	}
	return nil
}

func validateVaultFiles(x vaultFixture) error {
	wantAfter := []string{".lock", ".symvault-migrated", "config.yaml", "entries/full.age", "entries/minimal.age", "entries/nested/large.age", "identity.age", "manifest.age", "recipients.txt"}
	gotAfter := make([]string, 0, len(x.Files))
	for _, file := range x.Files {
		gotAfter = append(gotAfter, file.Path)
	}
	if !reflect.DeepEqual(gotAfter, wantAfter) {
		return fmt.Errorf("%s file path array changed", x.Name)
	}
	if len(x.Files) == 0 || len(x.Migration.Before.Files) == 0 || len(x.Migration.After.Files) == 0 || !x.Migration.DataPreserved || !migrationFilesPreserved(x) || x.Migration.Marker != ".symvault-migrated" {
		return fmt.Errorf("%s migration evidence incomplete", x.Name)
	}
	return nil
}

func validateVaultEntries(x vaultFixture) error {
	for j, e := range x.Entries {
		if e.Name != requiredEntries[j] || e.Path == "" || e.StoragePath == "" || len(e.Expected) == 0 || e.ExpectedJSON == "" || len(e.BeforeExpected) == 0 || e.BeforeJSON == "" {
			return fmt.Errorf("incomplete %s entry %d", x.Name, j)
		}
	}
	if len(x.TypeVectors) != len(requiredTypeVectors) {
		return fmt.Errorf("%s type vector cardinality changed", x.Name)
	}
	for i, vector := range x.TypeVectors {
		if vector.Name != requiredTypeVectors[i] || vector.Expected == "" {
			return fmt.Errorf("incomplete %s type vector %d", x.Name, i)
		}
	}
	return nil
}

func build(root string) (fixture, error) {
	meta, err := authoritative(root)
	if err != nil {
		return fixture{}, err
	}
	fresh, err := runOracle(root, false)
	if err != nil {
		return fixture{}, err
	}
	legacy, err := runOracle(root, true)
	if err != nil {
		return fixture{}, err
	}
	return fixture{1, meta, []vaultFixture{fresh, legacy}, []malformedCase{{"empty", "", "malformed/empty"}, {"not_age", "not an age envelope\n", "malformed/not_age"}, {"bad_stanza", "age-encryption.org/v1\n-> bad\n--- header end\n", "malformed/bad_stanza"}}}, nil
}
func verify(root, path string) error {
	data, err := os.ReadFile(path) // #nosec G304 -- path is the explicit generated fixture path supplied by the caller
	if err != nil {
		return err
	}
	var v fixture
	if err = json.Unmarshal(data, &v); err != nil {
		return err
	}
	expected, err := authoritative(root)
	if err != nil {
		return err
	}
	return validate(v, expected)
}
func main() {
	output := flag.String("output", "testdata/port/store/store.json", "fixture path")
	check := flag.Bool("check", false, "verify fixture provenance and cardinalities")
	flag.Parse()
	root := rootDir()
	if *check {
		if err := verify(root, *output); err != nil {
			fmt.Fprintln(os.Stderr, "FAIL store fixture:", err)
			os.Exit(1)
		}
		fmt.Println("PASS store fixture (2 vaults, 6 entries, 3 malformed)")
		return
	}
	v, err := build(root)
	if err != nil {
		fmt.Fprintln(os.Stderr, "FAIL generate store fixture:", err)
		os.Exit(1)
	}
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		panic(err)
	}
	data = append(data, '\n')
	if err = os.MkdirAll(filepath.Dir(*output), 0750); err != nil {
		panic(err)
	}
	if err = os.WriteFile(*output, data, 0600); err != nil {
		panic(err)
	}
	fmt.Println("WROTE", *output)
}
