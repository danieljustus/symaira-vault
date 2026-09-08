// Command syncgen freezes RUST-008 behavior from the pinned Go production tree.
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
	oracleCommit  = "caadd5e"
	oracleRelease = "v0.22.1"
)

// These are the production paths that the detached oracle imports and exercises.
// The digest is over the pinned Git bytes, not over the working tree.
var sourceRoots = []string{
	"internal/git", "internal/vault", "internal/importer", "internal/exporter",
	"internal/intake", "cmd/admin",
}
var generatorFiles = []string{"scripts/rust-port/cmd/syncgen/main.go"}

const oracleProgram = `package main

import (
  "archive/tar"
  "archive/zip"
  "bytes"
  "compress/gzip"
  "crypto/sha256"
  "encoding/base64"
  "encoding/hex"
  "encoding/json"
  "fmt"
  "io"
  "os"
  "os/exec"
  "path/filepath"
  "sort"
  "strings"
  "time"

  vaultsync "github.com/danieljustus/symaira-vault/internal/vault/sync"
  vault "github.com/danieljustus/symaira-vault/internal/vault"
  "github.com/danieljustus/symaira-vault/internal/git"
  "github.com/danieljustus/symaira-vault/internal/importer"
  "github.com/danieljustus/symaira-vault/internal/exporter"
  "github.com/danieljustus/symaira-vault/internal/intake"
  admin "github.com/danieljustus/symaira-vault/cmd/admin"
)

type Case struct { ID string ~BT~json:"id"~BT~; Seam string ~BT~json:"seam"~BT~; Input any ~BT~json:"input"~BT~; Expected any ~BT~json:"expected"~BT~ }
type File struct { Path string ~BT~json:"path"~BT~; Mode uint32 ~BT~json:"mode"~BT~; Size int64 ~BT~json:"size"~BT~; SHA256 string ~BT~json:"sha256"~BT~; Data string ~BT~json:"data,omitempty"~BT~ }
type Entry struct { Path string ~BT~json:"path"~BT~; Data map[string]any ~BT~json:"data"~BT~; Warnings []string ~BT~json:"warnings"~BT~; SecretType string ~BT~json:"secret_type,omitempty"~BT~ }
type Provenance struct { SourceName string ~BT~json:"source_name"~BT~; SourceType string ~BT~json:"source_type"~BT~; Size int64 ~BT~json:"size"~BT~; SHA256 string ~BT~json:"sha256"~BT~ }

type Oracle struct { Commit string ~BT~json:"commit"~BT~; Release string ~BT~json:"release"~BT~; SourceFiles []string ~BT~json:"source_files"~BT~; SourceDigest string ~BT~json:"source_digest"~BT~; GeneratorFiles []string ~BT~json:"generator_files"~BT~; GeneratorDigest string ~BT~json:"generator_digest"~BT~ }
type Fixture struct { SchemaVersion int ~BT~json:"schema_version"~BT~; Oracle Oracle ~BT~json:"oracle"~BT~; Cases []Case ~BT~json:"cases"~BT~; Scope map[string]string ~BT~json:"scope"~BT~ }
func fail(err error) { if err != nil { panic(err) } }
func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }
func hash(b []byte) string { s:=sha256.Sum256(b); return hex.EncodeToString(s[:]) }
func run(dir string, args ...string) { c:=exec.Command(args[0], args[1:]...); c.Dir=dir; if out,e:=c.CombinedOutput(); e!=nil { panic(fmt.Errorf("%v: %w: %s",args,e,out)) } }
func gitOut(dir string, args ...string) string { c:=exec.Command("git", append([]string{"-C",dir},args...)...); out,e:=c.Output(); fail(e); return strings.TrimSpace(string(out)) }
func snapshot(root string) []File { var out []File; fail(filepath.Walk(root,func(p string, info os.FileInfo, e error) error { fail(e); if p==root{return nil}; rel,e:=filepath.Rel(root,p);fail(e); rel=filepath.ToSlash(rel); if info.IsDir(){return nil}; data,e:=os.ReadFile(p);fail(e); out=append(out,File{Path:rel,Mode:uint32(info.Mode().Perm()),Size:int64(len(data)),SHA256:hash(data),Data:b64(data)}); return nil })); sort.Slice(out,func(i,j int)bool{return out[i].Path<out[j].Path}); return out }
func archiveSnapshot(p string) []File { f,e:=os.Open(p);fail(e); defer f.Close(); gz,e:=gzip.NewReader(f);fail(e); defer gz.Close(); tr:=tar.NewReader(gz); var out []File; for { h,e:=tr.Next(); if e==io.EOF{break};fail(e); if h.Typeflag==tar.TypeDir{out=append(out,File{Path:filepath.ToSlash(h.Name),Mode:uint32(h.Mode)});continue}; data,e:=io.ReadAll(tr);fail(e); out=append(out,File{Path:filepath.ToSlash(h.Name),Mode:uint32(h.Mode),Size:int64(len(data)),SHA256:hash(data),Data:b64(data)}) }; sort.Slice(out,func(i,j int)bool{return out[i].Path<out[j].Path});return out }
func normalizeEntries(es []importer.ImportedEntry) []Entry { out:=make([]Entry,0,len(es)); for _,e:=range es { st:=""; if e.SecretMetadata!=nil {st=string(e.SecretMetadata.Type)}; out=append(out,Entry{e.Path,e.Data,e.Warnings,st}) }; return out }
func onePux() []byte { var buf bytes.Buffer; zw:=zip.NewWriter(&buf); fh:=&zip.FileHeader{Name:"export.json",Method:zip.Deflate};fh.SetModTime(time.Unix(0,0));w,e:=zw.CreateHeader(fh);fail(e); _,e=w.Write([]byte("{\"accounts\":[{\"vaults\":[{\"items\":[{\"categoryUuid\":\"001\",\"title\":\"Work Login\",\"details\":{\"loginFields\":[{\"designation\":\"username\",\"value\":\"fixture-user\"},{\"designation\":\"password\",\"value\":\"fixture-pass\"}],\"notesPlain\":\"fixture-note\"},\"overview\":{\"urls\":[{\"url\":\"https://example.test\"}],\"tags\":[\"work\"]}}]}]}]}"));fail(e);fail(zw.Close());return buf.Bytes() }
func caseGit() Case { root,e:=os.MkdirTemp("","sync-git-");fail(e);defer os.RemoveAll(root); fail(git.Init(root)); fail(git.CreateGitignore(root)); fail(os.Mkdir(filepath.Join(root,"entries"),0700)); fail(os.WriteFile(filepath.Join(root,"entries","one.age"),[]byte("cipher-one"),0600)); fail(git.AutoCommitWithOptions(root,git.CommitOptions{Message:"fixture commit",Author:"Fixture",Email:"fixture@example.com"})); status:=gitOut(root,"status","--porcelain=v1","--untracked-files=all"); return Case{"GIT-001-local","GIT-001",map[string]any{"message":"fixture commit","author":"Fixture"},map[string]any{"status":status,"commit_message":gitOut(root,"log","-1","--format=%s"),"commit_author":gitOut(root,"log","-1","--format=%an"),"gitignore_sha256":hash(mustRead(filepath.Join(root,".gitignore")))}} }
func caseRemote() Case { root,e:=os.MkdirTemp("","sync-remote-");fail(e);defer os.RemoveAll(root); remote:=filepath.Join(root,"remote.git"); local:=filepath.Join(root,"local"); other:=filepath.Join(root,"other"); run(root,"git","init","--bare",remote); run(root,"git","-C",remote,"symbolic-ref","HEAD","refs/heads/master"); fail(git.Init(local)); fail(git.AddRemote(local,"origin",remote)); fail(os.WriteFile(filepath.Join(local,"entry.age"),[]byte("one"),0600)); fail(git.AutoCommit(local,"first")); push:=git.PushWithResult(local); run(local,"git","branch","--set-upstream-to=origin/master","master"); fail(os.WriteFile(filepath.Join(local,"entry.age"),[]byte("local"),0600)); fail(git.AutoCommit(local,"local")); run(root,"git","clone",remote,other); fail(os.WriteFile(filepath.Join(other,"entry.age"),[]byte("remote"),0600)); run(other,"git","config","user.name","Other");run(other,"git","config","user.email","other@example.com");run(other,"git","add","--all");run(other,"git","commit","-m","remote");run(other,"git","push","origin","HEAD"); pull:=git.PullWithResult(local); return Case{"GIT-002-local-bare","GIT-002",map[string]any{"branch":"master","entry":"entry.age","first_bytes":"one","first_commit":"first","local_bytes":"local","local_commit":"local","remote":"origin","remote_bytes":"remote","remote_commit":"remote"},map[string]any{"push_success":push.Success,"push_skipped":push.Skipped,"push_has_remote":push.HasRemote,"pull_success":pull.Success,"pull_updated":pull.Updated,"pull_skipped":pull.Skipped,"pull_has_remote":pull.HasRemote,"pull_error":func() string { if pull.Error != nil { return pull.Error.Error() }; return "" }(),"remote_url_present":pull.RemoteURL!="","final_sha256":hash(mustRead(filepath.Join(local,"entry.age")))}} }
func mustRead(p string) []byte { b,e:=os.ReadFile(p);fail(e);return b }
func caseReconcile() Case { a:=vault.EntryMetadata{Version:1,Updated:time.Date(2026,1,1,0,0,0,0,time.UTC)}; b:=vault.EntryMetadata{Version:2,Updated:time.Date(2026,1,2,0,0,0,0,time.UTC)}; w,l:=vaultsync.WinnerByVersion("entries/item.age",a,b); root,e:=os.MkdirTemp("","sync-conflict-");fail(e);defer os.RemoveAll(root); p:=filepath.Join(root,"item.age");fail(os.WriteFile(p,[]byte("loser-bytes"),0600)); cp,e:=vaultsync.ReconcileConflict(p);fail(e); return Case{"GIT-003-conflict","GIT-003",map[string]any{"winner_version":w.Version,"loser_version":l.Version},map[string]any{"winner_version":w.Version,"loser_version":l.Version,"conflict_bytes":string(mustRead(cp)),"source_bytes":string(mustRead(p))}} }
func caseImports() Case { csvData:=[]byte("title,username,password,url\nExample,fixture-user,fixture-pass,https://example.test\n"); ci,e:=importer.NewCSV("").Parse(bytes.NewReader(csvData));fail(e); bw:=[]byte("{\"folders\":[{\"id\":\"f\",\"name\":\"Work\"}],\"items\":[{\"type\":1,\"name\":\"Login\",\"folderId\":\"f\",\"notes\":\"fixture-note\",\"login\":{\"username\":\"fixture-user\",\"password\":\"fixture-pass\",\"uris\":[{\"uri\":\"https://example.test\"}]}}]}"); bi,e:=importer.New(importer.FormatBitwarden);fail(e); be,e:=bi.Parse(bytes.NewReader(bw));fail(e); one,e:=importer.New(importer.Format1Password);fail(e); oneBytes:=onePux(); oe,e:=one.Parse(bytes.NewReader(oneBytes));fail(e); return Case{"IO-001-imports","IO-001",map[string]any{"csv":b64(csvData),"bitwarden":b64(bw),"onepux":b64(oneBytes)},map[string]any{"csv":normalizeEntries(ci),"bitwarden":normalizeEntries(be),"onepux":normalizeEntries(oe),"pass_adapter":"not exercised: requires external gpg"}}}
func caseExport() Case { es:=[]exporter.ExportEntry{{Path:"Example",Data:map[string]any{"username":"fixture-user","password":"fixture-pass","url":"https://example.test"}},{Path:"Other",Data:map[string]any{"password":"second-pass","notes":"fixture-note"}}}; var j,c bytes.Buffer; fail((&exporter.JSONExporter{}).Export(&j,es,nil)); fail((&exporter.CSVExporter{}).Export(&c,es,nil)); return Case{"IO-002-export","IO-002",map[string]any{"entries":es},map[string]any{"json_b64":b64(j.Bytes()),"csv_b64":b64(c.Bytes())}} }
func caseArchive() Case { root,e:=os.MkdirTemp("","sync-archive-");fail(e);defer os.RemoveAll(root); output,e:=os.MkdirTemp("","sync-archive-output-");fail(e);defer os.RemoveAll(output); dst:=filepath.Join(output,"restored"); arc:=filepath.Join(output,"backup.tar.gz"); fail(os.Mkdir(filepath.Join(root,"entries"),0700)); for p,d:=range map[string][]byte{"identity.age":[]byte("identity"),"config.yaml":[]byte("vault_dir: fixture\n"),"entries/item.age":[]byte("ciphertext")} { fail(os.WriteFile(filepath.Join(root,filepath.FromSlash(p)),d,0600)) }; fail(admin.CreateBackup(root,arc,false)); members:=archiveSnapshot(arc); fail(admin.RestoreBackup(arc,dst)); return Case{"IO-002-archive","IO-002",map[string]any{"exclude_git":false},map[string]any{"archive_members":members,"restored_files":snapshot(dst)}} }
func caseIntake() Case { root,e:=os.MkdirTemp("","sync-intake-");fail(e);defer os.RemoveAll(root); p:=filepath.Join(root,"credentials.env"); data:=[]byte("USERNAME=fixture-user\nPASSWORD=fixture-pass\n");fail(os.WriteFile(p,data,0600)); old:=time.Unix(1700000000,0);fail(os.Chtimes(p,old,old)); spool,e:=intake.NewSpool();fail(e);defer spool.Remove(); r,e:=intake.ProcessFile(spool,p,intake.DefaultOptions());fail(e); prov:=Provenance{r.Provenance.SourceName,string(r.Provenance.SourceType),r.Provenance.Size,r.Provenance.SHA256}; var sug []map[string]any; for _,s:=range r.Suggestions {sug=append(sug,map[string]any{"path":s.Path,"field":s.Field,"confidence":s.Confidence,"attachment":s.Attachment})}; return Case{"IO-003-portable-intake","IO-003",map[string]any{"name":"credentials.env","data_b64":b64(data),"mtime_unix":old.Unix()},map[string]any{"status":r.Status,"provenance":prov,"suggestions":sug,"source_unchanged":string(mustRead(p))==string(data),"native_watcher":"unproven"}} }
func main(){ f:=Fixture{SchemaVersion:1,Scope:map[string]string{"native_watcher":"unproven; polling/process evidence is portable only","pass_import":"unproven; production path requires external gpg","archive_bytes":"not a byte contract; compare member manifest and restore result","candidate_gaps":"GIT-002 divergent-pull parity and IO-003 native watcher remain unproven"}}; f.Cases=[]Case{caseGit(),caseRemote(),caseReconcile(),caseImports(),caseExport(),caseArchive(),caseIntake()}; enc:=json.NewEncoder(os.Stdout);enc.SetEscapeHTML(false);fail(enc.Encode(f)) }
`

type OracleMeta struct {
	Commit          string   `json:"commit"`
	Release         string   `json:"release"`
	SourceFiles     []string `json:"source_files"`
	SourceDigest    string   `json:"source_digest"`
	GeneratorFiles  []string `json:"generator_files"`
	GeneratorDigest string   `json:"generator_digest"`
}
type Case struct {
	ID       string          `json:"id"`
	Seam     string          `json:"seam"`
	Input    json.RawMessage `json:"input"`
	Expected json.RawMessage `json:"expected"`
}
type Fixture struct {
	SchemaVersion int               `json:"schema_version"`
	Oracle        OracleMeta        `json:"oracle"`
	Cases         []Case            `json:"cases"`
	Scope         map[string]string `json:"scope"`
}

func rootDir() string {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		panic("locate syncgen")
	}
	root, err := canonicalDir(filepath.Join(filepath.Dir(file), "..", "..", "..", ".."))
	if err != nil {
		panic(fmt.Errorf("locate repository root: %w", err))
	}
	return root
}

func canonicalDir(path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	clean := filepath.Clean(abs)
	info, err := os.Stat(clean)
	if err != nil {
		return "", err
	}
	if !info.IsDir() {
		return "", fmt.Errorf("%s is not a directory", clean)
	}
	resolved, err := filepath.EvalSymlinks(clean)
	if err != nil {
		return "", err
	}
	return filepath.Abs(resolved)
}

func safeRelativePath(path string) (string, error) {
	if path == "" || strings.IndexByte(path, 0) >= 0 || filepath.IsAbs(path) || filepath.VolumeName(path) != "" {
		return "", fmt.Errorf("path must be a non-empty relative path")
	}
	if runtime.GOOS != "windows" && strings.ContainsRune(path, '\\') {
		return "", fmt.Errorf("path contains an unsupported separator")
	}
	clean := filepath.Clean(filepath.FromSlash(path))
	if clean == "." || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("path escapes its root")
	}
	return clean, nil
}

func fixturePath(root, requested string) (string, error) {
	base := filepath.Join(root, "testdata", "port")
	var candidate string
	if filepath.IsAbs(requested) {
		candidate = filepath.Clean(requested)
	} else {
		relative, err := safeRelativePath(requested)
		if err != nil {
			return "", err
		}
		candidate = filepath.Join(root, relative)
	}
	relative, err := filepath.Rel(base, candidate)
	if err != nil {
		return "", err
	}
	return safeRelativePath(relative)
}

func openFixtureRoot(root string) (*os.Root, error) {
	return os.OpenRoot(filepath.Join(root, "testdata", "port"))
}

func trustedGitExecutable() (string, error) {
	path, err := exec.LookPath("git")
	if err != nil {
		return "", fmt.Errorf("locate git: %w", err)
	}
	path = filepath.Clean(path)
	if !filepath.IsAbs(path) {
		return "", fmt.Errorf("git executable path is not absolute")
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "", fmt.Errorf("resolve git executable: %w", err)
	}
	resolved, err = filepath.Abs(resolved)
	if err != nil {
		return "", err
	}
	base := strings.ToLower(filepath.Base(resolved))
	if base != "git" && base != "git.exe" {
		return "", fmt.Errorf("unexpected git executable %q", base)
	}
	info, err := os.Stat(resolved)
	if err != nil {
		return "", err
	}
	if info.IsDir() {
		return "", fmt.Errorf("git executable is a directory")
	}
	return resolved, nil
}

func newGitCommand(root string) (*exec.Cmd, error) {
	root, err := canonicalDir(root)
	if err != nil {
		return nil, fmt.Errorf("validate repository root: %w", err)
	}
	git, err := trustedGitExecutable()
	if err != nil {
		return nil, err
	}
	cmd := exec.Command("git")
	if cmd.Err != nil {
		return nil, cmd.Err
	}
	cmd.Path = git
	cmd.Dir = root
	cmd.Args = []string{git}
	return cmd, nil
}

func gitLsTree(root, dir string) ([]byte, error) {
	dir, err := safeRelativePath(dir)
	if err != nil {
		return nil, fmt.Errorf("unsafe source root %q: %w", dir, err)
	}
	cmd, err := newGitCommand(root)
	if err != nil {
		return nil, err
	}
	cmd.Args = append(cmd.Args, "ls-tree", "-r", "--name-only", oracleCommit, "--", filepath.ToSlash(dir))
	return cmd.Output()
}

func gitShow(root, name string) ([]byte, error) {
	name, err := safeRelativePath(name)
	if err != nil {
		return nil, fmt.Errorf("unsafe source path %q: %w", name, err)
	}
	cmd, err := newGitCommand(root)
	if err != nil {
		return nil, err
	}
	cmd.Args = append(cmd.Args, "show", oracleCommit+":"+filepath.ToSlash(name))
	return cmd.Output()
}

func gitArchive(root string, output io.Writer) error {
	cmd, err := newGitCommand(root)
	if err != nil {
		return err
	}
	cmd.Args = append(cmd.Args, "archive", "--format=tar", oracleCommit)
	cmd.Stdout = output
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("git archive: %w: %s", err, stderr.String())
	}
	return nil
}

func sourceFiles(root string) ([]string, error) {
	var files []string
	for _, dir := range sourceRoots {
		out, e := gitLsTree(root, dir)
		if e != nil {
			return nil, e
		}
		for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
			if strings.HasSuffix(line, ".go") && !strings.HasSuffix(line, "_test.go") {
				files = append(files, line)
			}
		}
	}
	sort.Strings(files)
	return files, nil
}
func digest(root string, names []string, pinned bool) (string, error) {
	h := sha256.New()
	var repository *os.Root
	if !pinned {
		var err error
		repository, err = os.OpenRoot(root)
		if err != nil {
			return "", err
		}
		defer func() { _ = repository.Close() }()
	}
	for _, name := range names {
		var data []byte
		var e error
		if pinned {
			data, e = gitShow(root, name)
		} else {
			cleanName, err := safeRelativePath(name)
			if err != nil {
				return "", fmt.Errorf("digest %s: %w", name, err)
			}
			data, e = repository.ReadFile(cleanName)
		}
		if e != nil {
			return "", fmt.Errorf("digest %s: %w", name, e)
		}
		h.Write([]byte(name))
		h.Write([]byte{0})
		h.Write(data)
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
func metadata(root string) (OracleMeta, error) {
	src, e := sourceFiles(root)
	if e != nil {
		return OracleMeta{}, e
	}
	sd, e := digest(root, src, true)
	if e != nil {
		return OracleMeta{}, e
	}
	gd, e := digest(root, generatorFiles, false)
	if e != nil {
		return OracleMeta{}, e
	}
	return OracleMeta{oracleCommit, oracleRelease, src, sd, generatorFiles, gd}, nil
}
func extract(root string) (string, error) {
	dir, e := os.MkdirTemp("", "sync-oracle-")
	if e != nil {
		return "", e
	}
	keep := false
	defer func() {
		if !keep {
			_ = os.RemoveAll(dir)
		}
	}()
	archive, e := os.CreateTemp("", "sync-oracle-*.tar")
	if e != nil {
		return "", e
	}
	ap := archive.Name()
	defer func() {
		_ = archive.Close()
		_ = os.Remove(ap)
	}()
	if e = gitArchive(root, archive); e != nil {
		return "", e
	}
	if _, e = archive.Seek(0, io.SeekStart); e != nil {
		return "", fmt.Errorf("rewind oracle archive: %w", e)
	}
	tr := tar.NewReader(archive)
	for {
		h, e := tr.Next()
		if errors.Is(e, io.EOF) {
			break
		}
		if e != nil {
			return "", e
		}
		name, err := safeRelativePath(h.Name)
		if err != nil {
			return "", fmt.Errorf("unsafe oracle path %q: %w", h.Name, err)
		}
		out := filepath.Join(dir, name)
		switch h.Typeflag {
		case tar.TypeDir:
			e = os.MkdirAll(out, 0750)
		case tar.TypeReg:
			e = os.MkdirAll(filepath.Dir(out), 0750)
			if e == nil {
				data := make([]byte, h.Size)
				_, e = io.ReadFull(tr, data)
				if e == nil {
					e = os.WriteFile(out, data, 0600)
				}
			}
		}
		if e != nil {
			return "", e
		}
	}
	keep = true
	return dir, nil
}
func runOracle(root string) ([]Case, error) {
	tree, e := extract(root)
	if e != nil {
		return nil, e
	}
	defer func() { _ = os.RemoveAll(tree) }()
	p := filepath.Join(tree, "cmd", "syncoracle", "main.go")
	if e = os.MkdirAll(filepath.Dir(p), 0750); e != nil {
		return nil, e
	}
	if e = os.WriteFile(p, []byte(strings.ReplaceAll(oracleProgram, "~BT~", "`")), 0600); e != nil {
		return nil, e
	}
	cmd := exec.Command("go", "run", "./cmd/syncoracle")
	cmd.Dir = tree
	out, e := cmd.CombinedOutput()
	if e != nil {
		return nil, fmt.Errorf("detached oracle: %w: %s", e, out)
	}
	var raw struct {
		Cases []struct {
			ID       string          `json:"id"`
			Seam     string          `json:"seam"`
			Input    json.RawMessage `json:"input"`
			Expected json.RawMessage `json:"expected"`
		} `json:"cases"`
	}
	if e = json.Unmarshal(out, &raw); e != nil {
		return nil, e
	}
	cases := make([]Case, len(raw.Cases))
	for i, c := range raw.Cases {
		cases[i] = Case{c.ID, c.Seam, c.Input, c.Expected}
	}
	return cases, nil
}
func load(fixtures *os.Root, path string) (Fixture, error) {
	path, e := safeRelativePath(path)
	if e != nil {
		return Fixture{}, e
	}
	b, e := fixtures.ReadFile(path)
	if e != nil {
		return Fixture{}, e
	}
	var f Fixture
	e = json.Unmarshal(b, &f)
	return f, e
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

func sameJSON(a, b json.RawMessage) bool {
	var x, y any
	if json.Unmarshal(a, &x) != nil || json.Unmarshal(b, &y) != nil {
		return false
	}
	ax, err := json.Marshal(x)
	if err != nil {
		return false
	}
	by, err := json.Marshal(y)
	if err != nil {
		return false
	}
	return bytes.Equal(ax, by)
}
func validate(root string, fixtures *os.Root, path string) error {
	f, e := load(fixtures, path)
	if e != nil {
		return e
	}
	meta, e := metadata(root)
	if e != nil {
		return e
	}
	if f.SchemaVersion != 1 || f.Oracle.Commit != meta.Commit || f.Oracle.Release != meta.Release ||
		f.Oracle.SourceDigest != meta.SourceDigest || f.Oracle.GeneratorDigest != meta.GeneratorDigest ||
		!sameStrings(f.Oracle.SourceFiles, meta.SourceFiles) || !sameStrings(f.Oracle.GeneratorFiles, meta.GeneratorFiles) {
		return errors.New("sync fixture provenance changed; regenerate from the pinned Go oracle")
	}
	got, e := runOracle(root)
	if e != nil {
		return e
	}
	if len(got) != len(f.Cases) {
		return fmt.Errorf("sync case cardinality %d, want %d", len(f.Cases), len(got))
	}
	for i := range got {
		if got[i].ID != f.Cases[i].ID || got[i].Seam != f.Cases[i].Seam ||
			!sameJSON(got[i].Input, f.Cases[i].Input) || !sameJSON(got[i].Expected, f.Cases[i].Expected) {
			return fmt.Errorf("sync case %d (%s) drifted; regenerate from the Go oracle", i, f.Cases[i].ID)
		}
	}
	return nil
}

func writeFixture(fixtures *os.Root, path string, data []byte, check bool) error {
	path, err := safeRelativePath(path)
	if err != nil {
		return err
	}
	if check {
		existing, err := fixtures.ReadFile(path)
		if err != nil {
			return err
		}
		if !bytes.Equal(existing, data) {
			return fmt.Errorf("%s is stale; regenerate from the pinned Go oracle", path)
		}
		return nil
	}
	if dir := filepath.Dir(path); dir != "." {
		if err := fixtures.MkdirAll(dir, 0750); err != nil {
			return err
		}
	}
	return fixtures.WriteFile(path, data, 0600)
}

func main() {
	output := flag.String("output", "testdata/port/sync/sync.json", "fixture path")
	check := flag.Bool("check", false, "verify provenance and execute the detached oracle")
	flag.Parse()
	root := rootDir()
	fixtures, err := openFixtureRoot(root)
	if err != nil {
		panic(err)
	}
	outputPath, err := fixturePath(root, *output)
	if err != nil {
		fmt.Fprintln(os.Stderr, "FAIL sync fixture path:", err)
		os.Exit(1)
	}
	if *check {
		if e := validate(root, fixtures, outputPath); e != nil {
			fmt.Fprintln(os.Stderr, "FAIL sync fixture:", e)
			_ = fixtures.Close()
			os.Exit(1)
		}
		fmt.Println("PASS Go sync oracle fixture (7 cases; candidate gaps remain explicitly unproven)")
		_ = fixtures.Close()
		return
	}
	meta, e := metadata(root)
	if e != nil {
		panic(e)
	}
	cases, e := runOracle(root)
	if e != nil {
		panic(e)
	}
	f := Fixture{1, meta, cases, map[string]string{"native_watcher": "unproven; pinned Go production Watcher is polling-only; no native event backend to execute", "pass_import": "unproven; production path requires external gpg", "archive_bytes": "not a byte contract; compare member manifest and restore result", "candidate_gaps": "IO-003 native watcher remains unproven; pinned Go production Watcher is polling-only"}}
	data, e := json.MarshalIndent(f, "", "  ")
	if e != nil {
		panic(e)
	}
	data = append(data, '\n')
	if e = writeFixture(fixtures, outputPath, data, false); e != nil {
		panic(e)
	}
	_ = fixtures.Close()
	fmt.Println("WROTE", *output)
}
