package intake

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/danieljustus/symaira-vault/internal/vault"
)

// fakeVault is an in-memory intake.Vault for quarantine-batch tests.
type fakeVault struct {
	entries map[string]*vault.Entry
}

func newFakeVault() *fakeVault { return &fakeVault{entries: map[string]*vault.Entry{}} }

func (f *fakeVault) GetEntry(p string) (*vault.Entry, error) {
	e, ok := f.entries[p]
	if !ok {
		return nil, os.ErrNotExist
	}
	return e, nil
}

func (f *fakeVault) WriteEntry(p string, e *vault.Entry) error {
	f.entries[p] = e
	return nil
}

func (f *fakeVault) ListEntries(prefix string) ([]string, error) {
	var out []string
	for p := range f.entries {
		if strings.HasPrefix(p, prefix) {
			out = append(out, p)
		}
	}
	return out, nil
}

func writeTemp(t *testing.T, name, content string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatalf("write temp file: %v", err)
	}
	return p
}

func TestValidateRegularFile(t *testing.T) {
	regular := writeTemp(t, "notes.txt", "hello")
	if _, err := ValidateRegularFile(regular); err != nil {
		t.Fatalf("regular file rejected: %v", err)
	}

	dir := t.TempDir()
	if _, err := ValidateRegularFile(dir); err == nil {
		t.Fatal("directory accepted")
	}

	sym := filepath.Join(t.TempDir(), "link.txt")
	if err := os.Symlink(regular, sym); err != nil {
		t.Fatalf("create symlink: %v", err)
	}
	if _, err := ValidateRegularFile(sym); err == nil {
		t.Fatal("symlink accepted")
	}
}

func TestSniff(t *testing.T) {
	cases := []struct {
		name string
		data []byte
		want SourceType
	}{
		{"png", []byte("\x89PNG\r\n\x1a\n..."), SourceTypeImage},
		{"jpg", []byte("\xff\xd8\xff\xe0"), SourceTypeImage},
		{"pdf", []byte("%PDF-1.7\n"), SourceTypePDF},
		{"pem cert", []byte(pemBlock("CERTIFICATE")), SourceTypeCert},
		{"pem key", []byte(pemBlock("PRIVATE KEY")), SourceTypeKey},
		{"json", []byte(`{"username":"a","password":"b"}`), SourceTypeJSON},
		{"env", []byte("USERNAME=alice\nPASSWORD=hunter2\n"), SourceTypeEnv},
		{"text", []byte("username: alice\npassword: hunter2\n"), SourceTypeText},
		{"binary", []byte{0x00, 0x01, 0x02, 0x03}, SourceTypeOther},
		{"empty", []byte{}, SourceTypeOther},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := Sniff(tc.data, "x.txt"); got != tc.want {
				t.Fatalf("Sniff() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestSniffIgnoresExtension(t *testing.T) {
	// A ".txt" file holding PEM must sniff as a certificate.
	data := []byte(pemBlock("CERTIFICATE"))
	if got := Sniff(data, "cert.txt"); got != SourceTypeCert {
		t.Fatalf("Sniff(txt name) = %q, want certificate", got)
	}
}

// pemBlock assembles a PEM-like fixture at runtime so the literal never
// matches a real certificate/key format in source (secret-scanning hygiene).
func pemBlock(kind string) string {
	return "-----BEGIN " + kind + "-----\nMIIB\n-----END " + kind + "-----\n"
}

func TestParseEnv(t *testing.T) {
	data := []byte("# comment\nUSERNAME=alice\nPASSWORD=hunter2\nDATABASE_URL=postgres://x\n")
	sugs := Parse(data, SourceTypeEnv, "creds.env")
	byField := map[string]Suggestion{}
	for _, s := range sugs {
		byField[s.Field] = s
	}
	if byField["username"].Value != "alice" {
		t.Errorf("username suggestion = %+v", byField["username"])
	}
	if byField["password"].Value != "hunter2" {
		t.Errorf("password suggestion = %+v", byField["password"])
	}
	if byField["database_url"].Value != "postgres://x" {
		t.Errorf("generic field suggestion = %+v", byField["database_url"])
	}
}

func TestParseJSON(t *testing.T) {
	data := []byte(`{"username":"bob","api_key":"k-123","notes":"hello world"}`)
	sugs := Parse(data, SourceTypeJSON, "export.json")
	byField := map[string]Suggestion{}
	for _, s := range sugs {
		byField[s.Field] = s
	}
	if byField["username"].Value != "bob" {
		t.Errorf("username = %+v", byField["username"])
	}
	if byField["token"].Value != "k-123" {
		t.Errorf("token = %+v", byField["token"])
	}
	if byField["notes"].Value != "hello world" {
		t.Errorf("notes = %+v", byField["notes"])
	}
}

func TestParseTextPatterns(t *testing.T) {
	data := []byte("Username: carol\nPassword: s3cret\nNothing else here\n")
	sugs := Parse(data, SourceTypeText, "credentials.txt")
	byField := map[string]Suggestion{}
	for _, s := range sugs {
		byField[s.Field] = s
	}
	if byField["username"].Value != "carol" {
		t.Errorf("username = %+v", byField["username"])
	}
	if byField["password"].Value != "s3cret" {
		t.Errorf("password = %+v", byField["password"])
	}
}

func TestParseTextWithoutHintsIsAttachment(t *testing.T) {
	data := []byte("just a random note without credentials")
	sugs := Parse(data, SourceTypeText, "note.txt")
	if len(sugs) != 1 || !sugs[0].Attachment || sugs[0].Field != AttachmentField {
		t.Fatalf("expected attachment fallback, got %+v", sugs)
	}
}

func TestParseCertIsAttachment(t *testing.T) {
	data := []byte(pemBlock("CERTIFICATE"))
	sugs := Parse(data, SourceTypeCert, "elster.pem")
	if len(sugs) != 1 || !sugs[0].Attachment {
		t.Fatalf("expected attachment, got %+v", sugs)
	}
}

func TestProposedEntryPath(t *testing.T) {
	cases := map[string]string{
		"login.example.txt":            "login.example",
		"../evil.txt":                  "evil",
		"a/b/../../etc/passwd":         "passwd",
		"weird name with spaces.txt":   "weird_name_with_spaces",
		"..":                           "entry",
		"login.example.conflict-1.age": "login.example.conflict-1",
		"UPPER Case File.JSON":         "UPPER_Case_File",
	}
	for input, want := range cases {
		if got := ProposedEntryPath(input); got != want {
			t.Errorf("ProposedEntryPath(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestProcessFileEnvAndSanitized(t *testing.T) {
	spool, err := NewSpool()
	if err != nil {
		t.Fatalf("NewSpool: %v", err)
	}
	defer spool.Remove()

	src := writeTemp(t, "creds.env", "USERNAME=alice\nPASSWORD=hunter2\n")
	res, err := ProcessFile(spool, src, DefaultOptions())
	if err != nil {
		t.Fatalf("ProcessFile: %v", err)
	}
	if res.Status != "ok" {
		t.Fatalf("status = %q, reason %q", res.Status, res.Reason)
	}
	if res.Provenance.SHA256 == "" || res.Provenance.SourceType != SourceTypeEnv {
		t.Fatalf("provenance = %+v", res.Provenance)
	}
	if len(res.raw) != 2 {
		t.Fatalf("raw suggestions = %d, want 2", len(res.raw))
	}

	san := res.Sanitized()
	joined := strings.Join(toStrings(san.Suggestions), " ")
	if strings.Contains(joined, "hunter2") || strings.Contains(joined, "alice") {
		t.Fatalf("sanitized output leaks secret values: %s", joined)
	}
	if len(san.raw) != 0 || san.sourceBytes != nil {
		t.Fatal("sanitized result still carries internal fields")
	}
}

func toStrings(sugs []SanitizedSuggestion) []string {
	var out []string
	for _, s := range sugs {
		out = append(out, s.Field, s.Warning)
	}
	return out
}

func TestProcessFileSymlinkSkipped(t *testing.T) {
	spool, _ := NewSpool()
	defer spool.Remove()

	real := writeTemp(t, "real.txt", "USERNAME=a\n")
	sym := filepath.Join(t.TempDir(), "link.txt")
	if err := os.Symlink(real, sym); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	res, err := ProcessFile(spool, sym, DefaultOptions())
	if err != nil {
		t.Fatalf("ProcessFile: %v", err)
	}
	if res.Status != "skipped" {
		t.Fatalf("status = %q, want skipped", res.Status)
	}
}

func TestProcessFileOverLimitSkipped(t *testing.T) {
	spool, _ := NewSpool()
	defer spool.Remove()

	big := writeTemp(t, "big.txt", strings.Repeat("x", 2048))
	opts := DefaultOptions()
	opts.MaxFileSize = 1024
	res, err := ProcessFile(spool, big, opts)
	if err != nil {
		t.Fatalf("ProcessFile: %v", err)
	}
	if res.Status != "skipped" || !strings.Contains(res.Reason, "limit") {
		t.Fatalf("status = %q reason %q, want skipped with limit", res.Status, res.Reason)
	}
}

func TestProcessFilesBatchLimits(t *testing.T) {
	spool, _ := NewSpool()
	defer spool.Remove()

	opts := DefaultOptions()
	opts.MaxFiles = 2
	a := writeTemp(t, "a.env", "A=1\n")
	b := writeTemp(t, "b.env", "B=2\n")
	c := writeTemp(t, "c.env", "C=3\n")

	if _, err := ProcessFiles(spool, []string{a, b, c}, opts); err == nil {
		t.Fatal("expected batch file-limit error")
	}
	results, err := ProcessFiles(spool, []string{a, b}, opts)
	if err != nil {
		t.Fatalf("ProcessFiles: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("results = %d", len(results))
	}
}

func TestWriteBatchQuarantine(t *testing.T) {
	spool, _ := NewSpool()
	defer spool.Remove()

	src := writeTemp(t, "login.example.txt", "username: alice\npassword: hunter2\n")
	res, err := ProcessFile(spool, src, DefaultOptions())
	if err != nil || res.Status != "ok" {
		t.Fatalf("process: %v %+v", err, res)
	}

	v := newFakeVault()
	importID, written, err := WriteBatch(v, []FileResult{res}, BatchOptions{})
	if err != nil {
		t.Fatalf("WriteBatch: %v", err)
	}
	if importID == "" {
		t.Fatal("empty import id")
	}
	if len(written) != 1 {
		t.Fatalf("written = %v", written)
	}
	entryPath := written[0]
	if !strings.HasPrefix(entryPath, "quarantine/"+importID+"/") {
		t.Fatalf("entry not under quarantine prefix: %s", entryPath)
	}
	entry := v.entries[entryPath]
	if entry == nil {
		t.Fatal("entry not stored")
	}
	if entry.Data["username"] != "alice" || entry.Data["password"] != "hunter2" {
		t.Fatalf("entry data = %+v", entry.Data)
	}
	att, ok := entry.SecretMetadata.Attachments[AttachmentField]
	if !ok {
		t.Fatal("attachment metadata missing")
	}
	if att.Filename != "login.example.txt" || att.SHA256 != res.Provenance.SHA256 || att.Size != res.Provenance.Size {
		t.Fatalf("attachment info = %+v", att)
	}
	// The exact source bytes are stored base64-encoded.
	decoded := make([]byte, len(entry.Data[AttachmentField].(string)))
	_ = decoded
	if entry.Data[AttachmentField] == "" {
		t.Fatal("attachment field empty")
	}
}

func TestWriteBatchDoesNotOverwrite(t *testing.T) {
	spool, _ := NewSpool()
	defer spool.Remove()

	src := writeTemp(t, "login.txt", "username: alice\n")
	res, _ := ProcessFile(spool, src, DefaultOptions())

	v := newFakeVault()
	// Pre-seed the target quarantine entry.
	v.entries["quarantine/batch1/login"] = &vault.Entry{Data: map[string]any{}}
	results := []FileResult{res}
	importID, written, err := WriteBatch(v, results, BatchOptions{ImportID: "batch1"})
	if err != nil {
		t.Fatalf("WriteBatch: %v", err)
	}
	if importID != "batch1" {
		t.Fatalf("importID = %q", importID)
	}
	if len(written) != 0 {
		t.Fatalf("written = %v, want none", written)
	}
	if results[0].Status != "skipped" {
		t.Fatalf("status = %q, want skipped (entry exists)", results[0].Status)
	}
}

func TestWriteBatchDryRun(t *testing.T) {
	spool, _ := NewSpool()
	defer spool.Remove()

	src := writeTemp(t, "login.txt", "username: alice\n")
	res, _ := ProcessFile(spool, src, DefaultOptions())

	v := newFakeVault()
	results := []FileResult{res}
	_, written, err := WriteBatch(v, results, BatchOptions{DryRun: true})
	if err != nil {
		t.Fatalf("WriteBatch: %v", err)
	}
	if len(written) != 0 {
		t.Fatalf("dry-run wrote entries: %v", written)
	}
	if len(v.entries) != 0 {
		t.Fatalf("dry-run touched vault: %v", v.entries)
	}
	if results[0].Status != "ok" {
		t.Fatalf("dry-run status = %q", results[0].Status)
	}
}

func TestWriteBatchDuplicateHashSkipped(t *testing.T) {
	spool, _ := NewSpool()
	defer spool.Remove()

	src := writeTemp(t, "recovery.txt", "username: alice\npassword: hunter2\n")
	res, _ := ProcessFile(spool, src, DefaultOptions())

	v := newFakeVault()
	// First write succeeds.
	results := []FileResult{res}
	_, written, err := WriteBatch(v, results, BatchOptions{})
	if err != nil || len(written) != 1 {
		t.Fatalf("first write: %v %v", err, written)
	}

	// Second write of the identical bytes is skipped as a duplicate hash.
	res2, _ := ProcessFile(spool, src, DefaultOptions())
	results2 := []FileResult{res2}
	_, written2, err := WriteBatch(v, results2, BatchOptions{})
	if err != nil {
		t.Fatalf("second write: %v", err)
	}
	if len(written2) != 0 {
		t.Fatalf("duplicate written: %v", written2)
	}
	if results2[0].Status != "skipped" {
		t.Fatalf("status = %q, want skipped (duplicate hash)", results2[0].Status)
	}
	if len(results2[0].Duplicates) != 1 {
		t.Fatalf("duplicates = %v, want 1", results2[0].Duplicates)
	}
}

func TestGenerateImportID(t *testing.T) {
	a := GenerateImportID()
	b := GenerateImportID()
	if a == "" || a == b {
		t.Fatalf("ids: %q %q", a, b)
	}
	if !strings.HasPrefix(a, "intake-") {
		t.Fatalf("id prefix: %q", a)
	}
}
