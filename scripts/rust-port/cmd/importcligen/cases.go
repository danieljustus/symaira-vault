package main

import (
	"archive/zip"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// --- source builders -------------------------------------------------------

func txt(name, text string) fileSpec { return fileSpec{Name: name, Text: text} }

func bin(name string, data []byte) fileSpec {
	return fileSpec{Name: name, Base64: base64.StdEncoding.EncodeToString(data)}
}

func mustBytes(data []byte, err error) []byte {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	return data
}

type zipMember struct {
	name    string
	payload []byte
}

// zipOf builds a stored (uncompressed), zero-timestamp archive so the bytes are
// reproducible and depend on no compressor.
func zipOf(members ...zipMember) []byte {
	var out bytes.Buffer
	writer := zip.NewWriter(&out)
	for _, member := range members {
		header := &zip.FileHeader{Name: member.name, Method: zip.Store}
		file, err := writer.CreateHeader(header)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		if _, err = file.Write(member.payload); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}
	if err := writer.Close(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	return out.Bytes()
}

func asJSON(value any) []byte { return mustBytes(json.Marshal(value)) }

const (
	genericCSV = "title,username,password,url,notes\nsite one,alice,pw-one-1234,https://a.example,note one\nsite/two,bob,pw-two-5678,,\n"
	appleCSV   = "Title,URL,Username,Password,Notes,OTPAuth\n" +
		"GitHub,https://github.com,octo,pw-apple-1,apple note,otpauth://totp/GitHub:octo?secret=JBSWY3DPEHPK3PXP&issuer=GitHub\n" +
		"No OTP,https://x.example,u2,pw-apple-2,,\n"
	chromeCSV = "name,url,username,password,note\n" +
		"Chrome One,https://c1.example/login,cu,cpw-1,chrome note\n" +
		",https://nameless.example/path,cu2,cpw-2,\n"
	firefoxCSV = "url,username,password,httpRealm,formActionOrigin,guid,timeCreated,timeLastUsed,timePasswordChanged\n" +
		"https://ff.example/login,fu,fpw-1,,https://ff.example,{guid-1},1,2,3\n" +
		"https://ff.example/other,fu2,fpw-2,,,{guid-2},1,2,3\n"
	customCSV = "name,login,secret,site,memo\nCustom One,carol,s3cret-One,https://c.example,custom memo\nCustom Two,dave,s3cret-Two,,\n"
)

var bitwardenSource = asJSON(map[string]any{
	"folders": []map[string]any{{"id": "f1", "name": "Work"}},
	"items": []map[string]any{
		{"type": 1, "name": "BW Login", "folderId": "f1", "notes": "bw notes",
			"login": map[string]any{"username": "bwuser", "password": "bw-pass-123", "totp": "JBSWY3DPEHPK3PXP",
				"uris": []map[string]any{{"uri": "https://bw.example"}, {"uri": "https://bw2.example"}}},
			"fields": []map[string]any{{"name": "Pin", "value": "4321"}}},
		{"type": 2, "name": "BW Card", "card": map[string]any{
			"cardholderName": "Jane Doe", "brand": "Visa", "number": "4111111111111111",
			"expMonth": "08", "expYear": "2030", "code": "123"}},
		{"type": 3, "name": "BW Identity ignored"},
		{"type": 1, "name": "No Folder", "login": map[string]any{"username": "nf", "password": "nf-pass-123"}},
	},
})

var onePuxPayload = []byte(`{"accounts":[{"vaults":[{"items":[
{"categoryUuid":"001","title":"Work Login","details":{"loginFields":[
{"designation":"username","value":"op-user"},{"designation":"password","value":"op-pass-123"}],
"notesPlain":"op notes","sections":[{"fields":[{"n":"totp","v":"JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"}]}]},
"overview":{"urls":[{"url":"https://op.example"}],"tags":["work"]}},
{"categoryUuid":"001","title":"Trash","trashed":true},
{"categoryUuid":"webforms.generic","title":"Ignored"}
]}]}]}`)

var onePuxArchive = zipOf(zipMember{"export.json", onePuxPayload})

func fld(value string) map[string]any { return map[string]any{"value": value} }

var cxfSource = zipOf(zipMember{"payload.json", asJSON(map[string]any{
	"version": map[string]any{"major": 1, "minor": 0},
	"accounts": []map[string]any{{
		"id": "acct", "username": "u", "email": "e@example.test",
		"collections": []map[string]any{{
			"id": "col", "title": "Main",
			"items": []map[string]any{{"item": "login"}, {"item": "ssh"}},
		}},
		"items": []map[string]any{
			{"id": "login", "title": "CXF Login", "scope": map[string]any{"urls": []string{"https://cxf.example"}},
				"credentials": []any{
					map[string]any{"type": "basic-auth", "username": fld("cxf-user"), "password": fld("cxf-pass-123")},
					map[string]any{"type": "totp", "secret": "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"},
				}},
			{"id": "ssh", "title": "CXF SSH", "credentials": []any{
				map[string]any{"type": "cryptographic-key", "privateKey": "dGVzdC1rZXktbWF0ZXJpYWw"}}},
			{"id": "card", "title": "CXF Card", "credentials": []any{
				map[string]any{"type": "credit-card", "number": fld("4111111111111111"), "fullName": fld("Fixture User"),
					"verificationNumber": fld("123"), "expiryDate": fld("2027-08"), "cardType": fld("visa")}}},
		},
	}},
})})

// passStore is a pass(1) directory tree plus a synthetic gpg that "decrypts"
// by printing the file (the same fake credential adapter import1passgen uses).
func passStore(prefix string) []fileSpec {
	return []fileSpec{
		txt(prefix+"/work/example.gpg", "example-secret\nusername:  example-user\nurl: https://example.test\ncomment line\n"),
		txt(prefix+"/work/invalid.gpg", "invalid-secret\notpauth://totp/example?secret=bad\n"),
		txt(prefix+"/plain.gpg", "plain-pass-123\n"),
		txt(prefix+"/ignored.txt", "not a gpg file\n"),
		{Name: "bin/gpg", Text: "#!/bin/sh\ncat \"$4\"\n", Mode: "0755"},
	}
}

func manyRows(count int) string {
	var out strings.Builder
	out.WriteString("title,username,password\n")
	for i := 0; i < count; i++ {
		fmt.Fprintf(&out, "entry-%02d,user%02d,pw-many-%08d\n", count-i, i, i*7919)
	}
	return out.String()
}

// --- case helpers ----------------------------------------------------------

var initSeed = [][]string{{"init"}}

func seedOf(more ...[]string) [][]string {
	return append(append([][]string{}, initSeed...), more...)
}

func setField(path, field, value string) []string {
	return []string{"set", path + "." + field, "--value", value}
}

func existingEntry(path string) [][]string {
	return [][]string{
		setField(path, "password", "Old-Password-1234"),
		setField(path, "username", "old-user"),
		setField(path, "extra", "old-extra-field"),
	}
}

func imp(args ...string) []string { return append([]string{"import"}, args...) }

func c(id, desc string, files []fileSpec, seed [][]string, argv ...string) caseInput {
	return caseInput{id: id, desc: desc, files: files, seed: seed, argv: argv}
}

func one(f fileSpec) []fileSpec { return []fileSpec{f} }

func noPost(in caseInput) caseInput { in.noPost = true; return in }

func unix(in caseInput) caseInput { in.platform = "unix"; return in }

func withPost(in caseInput, post ...[]string) caseInput { in.extraPost = post; return in }

// allCases is the full corpus. Order is the fixture order.
func allCases() []caseInput {
	csvFile := one(txt("a.csv", genericCSV))
	var cs []caseInput
	add := func(in ...caseInput) { cs = append(cs, in...) }

	// 1. Format auto-detection from the source extension.
	add(
		c("detect-csv-ext", "a .csv source selects the generic CSV importer", csvFile, seedOf(), imp("a.csv")...),
		c("detect-csv-upper-ext", "extension matching is case-insensitive: .CSV", one(txt("A.CSV", genericCSV)), seedOf(), imp("A.CSV")...),
		c("detect-csv-mixed-ext", "extension matching is case-insensitive: .CsV", one(txt("a.CsV", genericCSV)), seedOf(), imp("a.CsV")...),
		c("detect-zip-ext", "a .zip source selects the CXF importer", one(bin("export.zip", cxfSource)), seedOf(), imp("export.zip")...),
		c("detect-zip-upper-ext", "a .ZIP source selects the CXF importer", one(bin("export.ZIP", cxfSource)), seedOf(), imp("export.ZIP")...),
		c("detect-zip-double-ext", "only the last extension counts: .tar.zip", one(bin("export.tar.zip", cxfSource)), seedOf(), imp("export.tar.zip")...),
		c("detect-json-ext", ".json maps to a format name the command does not support", one(bin("bw.json", bitwardenSource)), seedOf(), imp("bw.json")...),
		c("detect-json-upper-ext", ".JSON maps to the same unsupported name", one(bin("bw.JSON", bitwardenSource)), seedOf(), imp("bw.JSON")...),
		c("detect-yaml-ext", ".yaml maps to an unsupported format name", one(txt("x.yaml", "a: b\n")), seedOf(), imp("x.yaml")...),
		c("detect-yml-ext", ".yml maps to an unsupported format name", one(txt("x.yml", "a: b\n")), seedOf(), imp("x.yml")...),
		c("detect-no-ext", "a source without an extension cannot be detected", one(txt("data", genericCSV)), seedOf(), imp("data")...),
		c("detect-unknown-ext", "an unknown extension cannot be detected", one(txt("data.txt", genericCSV)), seedOf(), imp("data.txt")...),
		c("detect-trailing-dot", "a trailing dot yields the extension \".\"", one(txt("data.", genericCSV)), seedOf(), imp("data.")...),
		c("detect-dotfile-csv", "a dotfile named .csv has the extension .csv (Go filepath.Ext)", one(txt(".csv", genericCSV)), seedOf(), imp(".csv")...),
		c("detect-dotfile-other", "a dotfile named .bashrc has the extension .bashrc", one(txt(".bashrc", genericCSV)), seedOf(), imp(".bashrc")...),
		c("detect-backup-ext", "a .csv.bak source ends in .bak", one(txt("a.csv.bak", genericCSV)), seedOf(), imp("a.csv.bak")...),
		c("detect-dotted-dir", "the extension is that of the last path element, not of a parent directory", []fileSpec{txt("dir.csv/inner", genericCSV)}, seedOf(), imp("dir.csv/inner")...),
		c("detect-1pux-ext", ".1pux is not auto-detected", one(bin("export.1pux", onePuxArchive)), seedOf(), imp("export.1pux")...),
		c("detect-missing-csv", "a missing .csv source passes detection and fails to open", nil, seedOf(), imp("missing.csv")...),
		c("detect-missing-json", "a missing .json source fails on the format before it is opened", nil, seedOf(), imp("missing.json")...),
		c("detect-absolute-path", "an absolute source path works and appears in nothing but diagnostics", one(txt("abs.csv", genericCSV)), seedOf(), imp("@WORK/abs.csv")...),
		c("detect-space-in-name", "a source path with spaces", one(txt("my file.csv", genericCSV)), seedOf(), imp("my file.csv")...),
		c("detect-nested-path", "a nested relative source path", one(txt("sub/dir/n.csv", genericCSV)), seedOf(), imp("sub/dir/n.csv")...),
	)

	// 2. Explicit --format.
	add(
		c("format-csv", "--format csv on an extensionless source", one(txt("data", genericCSV)), seedOf(), imp("data", "--format", "csv")...),
		c("format-csv-upper", "--format is lower-cased: CSV", one(txt("data", genericCSV)), seedOf(), imp("data", "--format", "CSV")...),
		c("format-csv-spaced", "--format is trimmed: ' csv '", one(txt("data", genericCSV)), seedOf(), imp("data", "--format", " csv ")...),
		c("format-bitwarden", "--format bitwarden on a .json source", one(bin("bw.json", bitwardenSource)), seedOf(), imp("bw.json", "--format", "bitwarden")...),
		c("format-bitwarden-mixed", "--format Bitwarden is lower-cased", one(bin("bw.json", bitwardenSource)), seedOf(), imp("bw.json", "--format", "Bitwarden")...),
		c("format-1password", "--format 1password on a .1pux source", one(bin("export.1pux", onePuxArchive)), seedOf(), imp("export.1pux", "--format", "1password")...),
		c("format-1pux-alias", "--format 1pux is not an accepted name", one(bin("export.1pux", onePuxArchive)), seedOf(), imp("export.1pux", "--format", "1pux")...),
		c("format-cxf", "--format cxf on a .zip source", one(bin("export.zip", cxfSource)), seedOf(), imp("export.zip", "--format", "cxf")...),
		c("format-cxf-extensionless", "--format cxf on an extensionless archive", one(bin("archive", cxfSource)), seedOf(), imp("archive", "--format", "cxf")...),
		c("format-apple", "--format apple", one(txt("p.csv", appleCSV)), seedOf(), imp("p.csv", "--format", "apple")...),
		c("format-chrome", "--format chrome", one(txt("p.csv", chromeCSV)), seedOf(), imp("p.csv", "--format", "chrome")...),
		c("format-firefox", "--format firefox", one(txt("p.csv", firefoxCSV)), seedOf(), imp("p.csv", "--format", "firefox")...),
		c("format-pass-store", "--format pass on a directory with a synthetic gpg", passStore("store"), seedOf(), imp("store", "--format", "pass")...),
		c("format-pass-empty-store", "--format pass on a directory without .gpg files", []fileSpec{{Name: "empty", Dir: true}}, seedOf(), imp("empty", "--format", "pass")...),
		c("format-pass-file", "--format pass on a regular file", one(txt("store.txt", "x")), seedOf(), imp("store.txt", "--format", "pass")...),
		c("format-pass-missing", "--format pass on a missing path", nil, seedOf(), imp("nostore", "--format", "pass")...),
		c("format-json", "--format json is unsupported", one(bin("bw.json", bitwardenSource)), seedOf(), imp("bw.json", "--format", "json")...),
		c("format-yaml", "--format yaml is unsupported", one(txt("x.yaml", "a: b\n")), seedOf(), imp("x.yaml", "--format", "yaml")...),
		c("format-unknown", "an unknown --format name", csvFile, seedOf(), imp("a.csv", "--format", "excel")...),
		c("format-unknown-upper", "an unknown --format name is reported lower-cased", csvFile, seedOf(), imp("a.csv", "--format", "EXCEL")...),
		c("format-whitespace-only", "a whitespace-only --format is not empty, so it is unsupported", csvFile, seedOf(), imp("a.csv", "--format", " ")...),
		c("format-empty-value", "--format= (empty) falls back to auto-detection", csvFile, seedOf(), imp("a.csv", "--format=")...),
		c("format-equals-form", "--format=csv", csvFile, seedOf(), imp("a.csv", "--format=csv")...),
		c("format-before-source", "--format before the source", csvFile, seedOf(), imp("--format", "csv", "a.csv")...),
		c("format-last-wins", "a repeated --format: the last value wins", csvFile, seedOf(), imp("a.csv", "--format", "excel", "--format", "csv")...),
		c("format-unsupported-before-open", "an unsupported format is reported before the source is opened", nil, seedOf(), imp("missing.csv", "--format", "nope")...),
		c("format-overrides-ext-bitwarden-on-csv", "explicit bitwarden overrides the .csv extension and fails to parse", csvFile, seedOf(), imp("a.csv", "--format", "bitwarden")...),
		c("format-overrides-ext-csv-on-json", "explicit csv overrides .json: the JSON text is read as CSV", one(bin("bw.json", bitwardenSource)), seedOf(), imp("bw.json", "--format", "csv")...),
		c("format-profile-mismatch", "an apple-profile export read with --format chrome", one(txt("p.csv", appleCSV)), seedOf(), imp("p.csv", "--format", "chrome")...),
		c("format-explicit-disables-sniffing", "--format csv on a Chrome export: no header sniffing, generic mapping", one(txt("p.csv", chromeCSV)), seedOf(), imp("p.csv", "--format", "csv")...),
	)

	// 3. CSV header sniffing.
	add(
		c("sniff-apple", "an Apple Passwords header is detected", one(txt("p.csv", appleCSV)), seedOf(), imp("p.csv")...),
		c("sniff-chrome", "a Chrome header is detected", one(txt("p.csv", chromeCSV)), seedOf(), imp("p.csv")...),
		c("sniff-firefox", "a Firefox header is detected", one(txt("p.csv", firefoxCSV)), seedOf(), imp("p.csv")...),
		c("sniff-generic", "a generic header keeps the generic mapping and prints no detection line", csvFile, seedOf(), imp("a.csv")...),
		c("sniff-case-insensitive", "header columns are matched case-insensitively", one(txt("p.csv", "TITLE,URL,USERNAME,PASSWORD,OTPAUTH\nX,https://x.example,u,p-1234567,\n")), seedOf(), imp("p.csv")...),
		c("sniff-dry-run-apple", "--dry-run reports the sniffed Apple profile and its mapping", one(txt("p.csv", appleCSV)), seedOf(), imp("p.csv", "--dry-run")...),
		c("sniff-dry-run-chrome", "--dry-run reports the sniffed Chrome profile and its mapping", one(txt("p.csv", chromeCSV)), seedOf(), imp("p.csv", "--dry-run")...),
		c("sniff-dry-run-firefox", "--dry-run reports the sniffed Firefox profile and its mapping", one(txt("p.csv", firefoxCSV)), seedOf(), imp("p.csv", "--dry-run")...),
		c("sniff-with-mapping", "a user mapping replaces the sniffed profile mapping (detection line stays)", one(txt("p.csv", chromeCSV)), seedOf(), imp("p.csv", "--mapping", "title=url,password=password", "--dry-run")...),
		c("sniff-empty-file", "an empty .csv has no header to sniff and imports nothing", one(txt("empty.csv", "")), seedOf(), imp("empty.csv")...),
		c("sniff-header-only", "a header-only .csv", one(txt("h.csv", "name,url,username,password,note\n")), seedOf(), imp("h.csv")...),
		c("sniff-bom-header", "a UTF-8 BOM before the header", one(txt("bom.csv", "\ufefftitle,password\nbomsite,pw-bom-12345\n")), seedOf(), imp("bom.csv")...),
		c("sniff-explicit-csv-dry-run", "--format csv on a Chrome export prints no detection line and the generic mapping", one(txt("p.csv", chromeCSV)), seedOf(), imp("p.csv", "--format", "csv", "--dry-run")...),
		c("sniff-quiet", "--quiet suppresses the detection line", one(txt("p.csv", chromeCSV)), seedOf(), imp("p.csv", "--quiet")...),
		c("sniff-chrome-nameless-row", "a Chrome row without a name takes the URL host as its path", one(txt("p.csv", chromeCSV)), seedOf(), imp("p.csv", "--dry-run", "--prefix", "chrome")...),
	)

	// 4. --dry-run.
	add(
		c("dryrun-csv", "--dry-run on generic CSV prints the format, the effective mapping and the plan", csvFile, seedOf(), imp("a.csv", "--dry-run")...),
		c("dryrun-bitwarden", "--dry-run on Bitwarden prints no mapping line", one(bin("bw.json", bitwardenSource)), seedOf(), imp("bw.json", "--format", "bitwarden", "--dry-run")...),
		c("dryrun-1password", "--dry-run on 1Password", one(bin("export.1pux", onePuxArchive)), seedOf(), imp("export.1pux", "--format", "1password", "--dry-run")...),
		c("dryrun-cxf", "--dry-run on CXF", one(bin("export.zip", cxfSource)), seedOf(), imp("export.zip", "--dry-run")...),
		c("dryrun-pass", "--dry-run on a pass store", passStore("store"), seedOf(), imp("store", "--format", "pass", "--dry-run")...),
		c("dryrun-apple-explicit", "--dry-run with --format apple", one(txt("p.csv", appleCSV)), seedOf(), imp("p.csv", "--format", "apple", "--dry-run")...),
		c("dryrun-prefix", "--dry-run with --prefix lists the prefixed paths", csvFile, seedOf(), imp("a.csv", "--dry-run", "--prefix", "team")...),
		c("dryrun-quiet", "--dry-run --quiet prints no report", csvFile, seedOf(), imp("a.csv", "--dry-run", "--quiet")...),
		c("dryrun-existing", "--dry-run over an existing entry still plans the import", csvFile, seedOf(setField("site-one", "password", "Old-Password-1234")), imp("a.csv", "--dry-run")...),
		c("dryrun-skip-existing", "--dry-run --skip-existing reports the skipped entry", csvFile, seedOf(setField("site-one", "password", "Old-Password-1234")), imp("a.csv", "--dry-run", "--skip-existing")...),
		c("dryrun-overwrite", "--dry-run --overwrite plans without deleting", csvFile, seedOf(existingEntry("site-one")...), imp("a.csv", "--dry-run", "--overwrite")...),
		c("dryrun-explicit-false", "--dry-run=false imports", csvFile, seedOf(), imp("a.csv", "--dry-run=false")...),
		c("dryrun-explicit-true", "--dry-run=true does not import", csvFile, seedOf(), imp("a.csv", "--dry-run=true")...),
		c("dryrun-empty-csv", "--dry-run on an empty CSV", one(txt("empty.csv", "")), seedOf(), imp("empty.csv", "--dry-run")...),
		c("dryrun-quarantine", "--dry-run --quarantine prints the ID and plans quarantine paths", csvFile, seedOf(), imp("a.csv", "--dry-run", "--quarantine")...),
		c("dryrun-malformed", "--dry-run still fails on a malformed source", one(txt("bad.csv", "title,password\n\"unterminated,pw\n")), seedOf(), imp("bad.csv", "--dry-run")...),
		c("dryrun-missing", "--dry-run on a missing source prints the format line before the open error", nil, seedOf(), imp("missing.csv", "--dry-run")...),
		c("dryrun-unsupported-format", "--dry-run with an unsupported format fails before any report", csvFile, seedOf(), imp("a.csv", "--dry-run", "--format", "excel")...),
	)

	// 5. --mapping.
	add(
		c("mapping-custom", "a full custom mapping", one(txt("m.csv", customCSV)), seedOf(), imp("m.csv", "--mapping", "title=name,username=login,password=secret,url=site,notes=memo")...),
		c("mapping-custom-dry-run", "the dry-run report shows the user mapping, sorted", one(txt("m.csv", customCSV)), seedOf(), imp("m.csv", "--mapping", "title=name,username=login,password=secret,url=site,notes=memo", "--dry-run")...),
		c("mapping-partial", "a partial mapping drops the unmapped default fields", one(txt("m.csv", customCSV)), seedOf(), imp("m.csv", "--mapping", "title=name,password=secret")...),
		c("mapping-partial-dry-run", "the dry-run report of a partial mapping", one(txt("m.csv", customCSV)), seedOf(), imp("m.csv", "--mapping", "title=name,password=secret", "--dry-run")...),
		c("mapping-extra-field", "a mapping to a field outside the defaults", one(txt("m.csv", customCSV)), seedOf(), imp("m.csv", "--mapping", "title=name,password=secret,pin=memo")...),
		c("mapping-missing-column", "a mapping that names a column the file lacks", one(txt("m.csv", customCSV)), seedOf(), imp("m.csv", "--mapping", "title=name,password=nothere")...),
		c("mapping-spaces", "spaces around keys and values are trimmed", one(txt("m.csv", customCSV)), seedOf(), imp("m.csv", "--mapping", " title = name , password = secret ")...),
		c("mapping-trailing-comma", "an empty pair between commas is skipped", one(txt("m.csv", customCSV)), seedOf(), imp("m.csv", "--mapping", "title=name,,password=secret,")...),
		c("mapping-value-with-equals", "only the first = splits a pair", one(txt("m.csv", "n,s=x\nOne,pw-equals-12345\n")), seedOf(), imp("m.csv", "--mapping", "title=n,password=s=x")...),
		c("mapping-invalid-pair", "a pair without =", one(txt("m.csv", customCSV)), seedOf(), imp("m.csv", "--mapping", "title")...),
		c("mapping-empty-field", "an empty field name", one(txt("m.csv", customCSV)), seedOf(), imp("m.csv", "--mapping", "=name")...),
		c("mapping-empty-column", "an empty column name", one(txt("m.csv", customCSV)), seedOf(), imp("m.csv", "--mapping", "title=")...),
		c("mapping-invalid-dry-run", "an invalid mapping on --dry-run fails after the format line", one(txt("m.csv", customCSV)), seedOf(), imp("m.csv", "--mapping", "title", "--dry-run")...),
		c("mapping-invalid-missing-file", "the mapping is validated before the source is opened", nil, seedOf(), imp("missing.csv", "--mapping", "bad")...),
		c("mapping-empty-value", "--mapping= is the same as no mapping", csvFile, seedOf(), imp("a.csv", "--mapping=")...),
		c("mapping-with-bitwarden", "a valid --mapping on a non-CSV format is ignored", one(bin("bw.json", bitwardenSource)), seedOf(), imp("bw.json", "--format", "bitwarden", "--mapping", "title=name")...),
		c("mapping-with-bitwarden-dry-run", "--mapping on a non-CSV dry-run prints no mapping line", one(bin("bw.json", bitwardenSource)), seedOf(), imp("bw.json", "--format", "bitwarden", "--mapping", "title=name", "--dry-run")...),
		c("mapping-invalid-with-bitwarden", "an invalid --mapping is rejected even for a non-CSV format", one(bin("bw.json", bitwardenSource)), seedOf(), imp("bw.json", "--format", "bitwarden", "--mapping", "bad")...),
		c("mapping-with-cxf", "a valid --mapping with cxf is ignored", one(bin("export.zip", cxfSource)), seedOf(), imp("export.zip", "--mapping", "title=name")...),
		c("mapping-invalid-with-cxf", "an invalid --mapping with cxf", one(bin("export.zip", cxfSource)), seedOf(), imp("export.zip", "--mapping", "bad")...),
		c("mapping-with-profile", "a user mapping overrides the chrome profile mapping", one(txt("p.csv", chromeCSV)), seedOf(), imp("p.csv", "--format", "chrome", "--mapping", "title=url,password=password")...),
		c("mapping-with-profile-dry-run", "dry-run with a chrome profile and a user mapping", one(txt("p.csv", chromeCSV)), seedOf(), imp("p.csv", "--format", "chrome", "--mapping", "title=url,password=password", "--dry-run")...),
		c("mapping-with-pass", "a valid --mapping with a pass store is ignored", passStore("store"), seedOf(), imp("store", "--format", "pass", "--mapping", "a=b")...),
		c("mapping-only-commas", "--mapping \",\" is a non-empty mapping with no pairs: nothing is mapped", csvFile, seedOf(), imp("a.csv", "--mapping", ",")...),
		c("mapping-only-commas-dry-run", "the dry-run report of an empty-pair mapping", csvFile, seedOf(), imp("a.csv", "--mapping", ",", "--dry-run")...),
		c("mapping-only-space", "--mapping \" \" is a non-empty mapping with no pairs", csvFile, seedOf(), imp("a.csv", "--mapping", " ")...),
		c("mapping-duplicate-key", "a repeated mapping key: the last pair wins", one(txt("m.csv", customCSV)), seedOf(), imp("m.csv", "--mapping", "title=memo,title=name,password=secret", "--dry-run")...),
		c("mapping-unicode-invalid-pair", "an invalid pair is quoted with Go %q (non-ASCII kept, control bytes escaped)", one(txt("m.csv", customCSV)), seedOf(), imp("m.csv", "--mapping", "tïtle\t")...),
		c("mapping-last-wins", "a repeated --mapping: the last value wins", one(txt("m.csv", customCSV)), seedOf(), imp("m.csv", "--mapping", "title=memo", "--mapping", "title=name,password=secret", "--dry-run")...),
		c("mapping-with-1password", "a valid --mapping with 1password is ignored", one(bin("export.1pux", onePuxArchive)), seedOf(), imp("export.1pux", "--format", "1password", "--mapping", "a=b")...),
	)

	// 6. Flag conflicts and check order.
	add(
		c("conflict-skip-overwrite", "--skip-existing with --overwrite", csvFile, seedOf(), imp("a.csv", "--skip-existing", "--overwrite")...),
		c("conflict-skip-overwrite-dry-run", "with --dry-run the format and mapping report precede the conflict error", csvFile, seedOf(), imp("a.csv", "--skip-existing", "--overwrite", "--dry-run")...),
		c("conflict-skip-overwrite-missing-file", "the conflict is reported before the source is opened", nil, seedOf(), imp("missing.csv", "--skip-existing", "--overwrite")...),
		c("conflict-skip-overwrite-unsupported", "an unsupported format wins over the conflict", csvFile, seedOf(), imp("a.csv", "--skip-existing", "--overwrite", "--format", "nope")...),
		c("conflict-skip-overwrite-undetectable", "an undetectable extension wins over the conflict", one(txt("data", genericCSV)), seedOf(), imp("data", "--skip-existing", "--overwrite")...),
		c("conflict-skip-overwrite-invalid-mapping", "the conflict wins over an invalid mapping", csvFile, seedOf(), imp("a.csv", "--skip-existing", "--overwrite", "--mapping", "bad")...),
		c("conflict-skip-overwrite-false", "--overwrite=false removes the conflict", csvFile, seedOf(), imp("a.csv", "--skip-existing", "--overwrite=false")...),
		c("conflict-quarantine-prefix", "--quarantine with --prefix", csvFile, seedOf(), imp("a.csv", "--quarantine", "--prefix", "work")...),
		c("conflict-quarantine-prefix-slash", "a prefix of only / still conflicts (the raw flag is compared)", csvFile, seedOf(), imp("a.csv", "--quarantine", "--prefix", "/")...),
		c("conflict-quarantine-prefix-dry-run", "the conflict with --dry-run prints the report first", csvFile, seedOf(), imp("a.csv", "--quarantine", "--prefix", "work", "--dry-run")...),
		c("conflict-quarantine-prefix-empty", "--prefix= is not a prefix, so --quarantine works", csvFile, seedOf(), imp("a.csv", "--quarantine", "--prefix=")...),
		c("conflict-both-pairs", "both conflicts: the skip/overwrite error wins", csvFile, seedOf(), imp("a.csv", "--skip-existing", "--overwrite", "--quarantine", "--prefix", "w")...),
		c("conflict-quarantine-invalid-mapping", "the quarantine ID is printed before an invalid mapping is rejected", csvFile, seedOf(), imp("a.csv", "--quarantine", "--mapping", "bad")...),
		c("conflict-quarantine-missing-file", "the quarantine ID is printed before the open error", nil, seedOf(), imp("missing.csv", "--quarantine")...),
		c("conflict-quarantine-malformed", "the quarantine ID is printed before a parse error", one(txt("bad.csv", "title,password\n\"x,y\n")), seedOf(), imp("bad.csv", "--quarantine")...),
		c("conflict-quarantine-quiet-malformed", "--quiet hides the quarantine ID, not the error", one(txt("bad.csv", "title,password\n\"x,y\n")), seedOf(), imp("bad.csv", "--quarantine", "--quiet")...),
	)

	// 7. Existing-entry collisions.
	oldSite := existingEntry("site-one")
	add(
		c("collide-default-merges", "without flags an existing entry is merged field by field", csvFile, seedOf(oldSite...), imp("a.csv")...),
		c("collide-skip-existing", "--skip-existing keeps the stored entry", csvFile, seedOf(oldSite...), imp("a.csv", "--skip-existing")...),
		c("collide-overwrite", "--overwrite replaces the stored entry (the extra field disappears)", csvFile, seedOf(oldSite...), imp("a.csv", "--overwrite")...),
		c("collide-overwrite-quiet", "--overwrite --quiet prints nothing", csvFile, seedOf(oldSite...), imp("a.csv", "--overwrite", "--quiet")...),
		c("collide-skip-all-existing", "every entry already exists and is skipped", csvFile, seedOf(append(append([][]string{}, oldSite...), existingEntry("site/two")...)...), imp("a.csv", "--skip-existing")...),
		c("collide-skip-prefix", "collision is decided on the prefixed path", csvFile, seedOf(existingEntry("work/site-one")...), imp("a.csv", "--prefix", "work", "--skip-existing")...),
		c("collide-overwrite-prefix", "--overwrite on the prefixed path", csvFile, seedOf(existingEntry("work/site-one")...), imp("a.csv", "--prefix", "work", "--overwrite")...),
		c("collide-prefix-no-collision", "the same entry under another prefix does not collide", csvFile, seedOf(oldSite...), imp("a.csv", "--prefix", "other", "--skip-existing")...),
		c("collide-duplicate-rows", "two rows with one path: the second merges into the first", one(txt("d.csv", "title,password,url\nsame,pw-first-1234,https://one.example\nsame,pw-second-1234,\n")), seedOf(), imp("d.csv")...),
		c("collide-duplicate-rows-skip", "two rows with one path under --skip-existing: the second is skipped", one(txt("d.csv", "title,password\nsame,pw-first-1234\nsame,pw-second-1234\n")), seedOf(), imp("d.csv", "--skip-existing")...),
		c("collide-duplicate-rows-overwrite", "two rows with one path under --overwrite: the second replaces the first", one(txt("d.csv", "title,password,url\nsame,pw-first-1234,https://one.example\nsame,pw-second-1234,\n")), seedOf(), imp("d.csv", "--overwrite")...),
		c("collide-duplicate-rows-dry-run", "duplicate rows are both planned on --dry-run", one(txt("d.csv", "title,password\nsame,pw-first-1234\nsame,pw-second-1234\n")), seedOf(), imp("d.csv", "--dry-run")...),
		c("collide-twice-same-import", "importing the same file twice without flags", csvFile, seedOf(imp("a.csv")), imp("a.csv")...),
		c("collide-twice-skip", "the second import with --skip-existing skips everything", csvFile, seedOf(imp("a.csv")), imp("a.csv", "--skip-existing")...),
		c("collide-twice-overwrite", "the second import with --overwrite replaces everything", csvFile, seedOf(imp("a.csv")), imp("a.csv", "--overwrite")...),
		c("collide-metadata-overwrite", "overwriting a payment entry with a plain one clears nothing it did not set", one(bin("bw.json", bitwardenSource)), seedOf(imp("bw.json", "--format", "bitwarden")), imp("bw.json", "--format", "bitwarden", "--overwrite")...),
		c("collide-metadata-default", "re-importing a payment entry without flags", one(bin("bw.json", bitwardenSource)), seedOf(imp("bw.json", "--format", "bitwarden")), imp("bw.json", "--format", "bitwarden")...),
		c("collide-metadata-skip", "re-importing a payment entry with --skip-existing", one(bin("bw.json", bitwardenSource)), seedOf(imp("bw.json", "--format", "bitwarden")), imp("bw.json", "--format", "bitwarden", "--skip-existing")...),
	)

	card := one(bin("bw.json", bitwardenSource))
	cardCSV := one(txt("c.csv", "title,password,url\nBW-Card,pw-new-12345,https://card.example\n"))
	add(
		c("collide-overwrite-clears-metadata", "overwriting a payment entry with a plain CSV row drops its secret type", append(append([]fileSpec{}, card...), cardCSV...), seedOf(imp("bw.json", "--format", "bitwarden")), imp("c.csv", "--overwrite")...),
		c("collide-default-keeps-metadata", "merging into a payment entry keeps its secret type and old fields", append(append([]fileSpec{}, card...), cardCSV...), seedOf(imp("bw.json", "--format", "bitwarden")), imp("c.csv")...),
		c("collide-skip-keeps-metadata", "skipping a payment entry leaves it untouched", append(append([]fileSpec{}, card...), cardCSV...), seedOf(imp("bw.json", "--format", "bitwarden")), imp("c.csv", "--skip-existing")...),
	)

	// 8. Prefix joining and empty paths.
	emptyPathCSV := one(txt("e.csv", "title,password\n,pw-empty-1234\nsame,pw-same-12345\n  ,pw-blank-1234\n"))
	add(
		c("prefix-plain", "--prefix work", csvFile, seedOf(), imp("a.csv", "--prefix", "work")...),
		c("prefix-edge-slashes", "leading and trailing slashes are trimmed", csvFile, seedOf(), imp("a.csv", "--prefix", "/work/")...),
		c("prefix-multi-slash-edges", "several edge slashes are trimmed", csvFile, seedOf(), imp("a.csv", "--prefix", "//a//b//")...),
		c("prefix-only-slash", "a prefix of / becomes empty", csvFile, seedOf(), imp("a.csv", "--prefix", "/")...),
		c("prefix-equals-form", "--prefix=work", csvFile, seedOf(), imp("a.csv", "--prefix=work")...),
		c("prefix-nested", "a nested prefix", csvFile, seedOf(), imp("a.csv", "--prefix", "a/b/c")...),
		c("prefix-dotdot", "path.Join cleans a/../b to b", csvFile, seedOf(), imp("a.csv", "--prefix", "a/../b")...),
		c("prefix-leading-dotdot", "a prefix of .. is cleaned against the entry path", csvFile, seedOf(), imp("a.csv", "--prefix", "..")...),
		c("prefix-dot", "a prefix of . joins away", csvFile, seedOf(), imp("a.csv", "--prefix", ".")...),
		c("prefix-inner-double-slash", "path.Join collapses an inner //", csvFile, seedOf(), imp("a.csv", "--prefix", "a//b")...),
		c("prefix-spaces", "spaces inside the prefix are kept by the command (not by ApplyPrefix)", csvFile, seedOf(), imp("a.csv", "--prefix", "my team")...),
		c("prefix-edge-spaces", "edge spaces are not trimmed", csvFile, seedOf(), imp("a.csv", "--prefix", " team ")...),
		c("prefix-backslash", "a backslash in the prefix is kept (entry paths drop it, prefixes do not)", csvFile, seedOf(), imp("a.csv", "--prefix", "a\\b")...),
		c("prefix-tab", "a control character in the prefix is an invalid path", csvFile, seedOf(), imp("a.csv", "--prefix", "a\tb")...),
		c("prefix-trailing-dot-segment", "path.Join cleans a/. to a", csvFile, seedOf(), imp("a.csv", "--prefix", "a/.")...),
		c("prefix-dotdot-escapes-then-recovers", "a/b/../../c cleans to c", csvFile, seedOf(), imp("a.csv", "--prefix", "a/b/../../c")...),
		c("prefix-unicode", "a non-ASCII prefix", csvFile, seedOf(), imp("a.csv", "--prefix", "Ünï/çode")...),
		c("prefix-last-wins", "a repeated --prefix: the last value wins", csvFile, seedOf(), imp("a.csv", "--prefix", "one", "--prefix", "two")...),
		c("prefix-empty-then-set", "--prefix= then --prefix work", csvFile, seedOf(), imp("a.csv", "--prefix=", "--prefix", "work")...),
		c("prefix-empty-paths-none", "rows with an empty title are skipped without a prefix", emptyPathCSV, seedOf(), imp("e.csv")...),
		c("prefix-empty-paths-prefixed", "with a prefix an empty path becomes the prefix itself", emptyPathCSV, seedOf(), imp("e.csv", "--prefix", "pre")...),
		c("prefix-empty-paths-dry-run", "empty paths on --dry-run", emptyPathCSV, seedOf(), imp("e.csv", "--dry-run")...),
		c("prefix-empty-paths-quarantine", "with --quarantine an empty path becomes the quarantine root", emptyPathCSV, seedOf(), imp("e.csv", "--quarantine")...),
		c("prefix-chrome-host-path", "a prefix over host-derived paths", one(txt("p.csv", chromeCSV)), seedOf(), imp("p.csv", "--prefix", "browser")...),
		c("prefix-firefox-host-path", "a prefix over Firefox host-derived paths", one(txt("p.csv", firefoxCSV)), seedOf(), imp("p.csv", "--prefix", "browser")...),
	)

	// 9. --quarantine.
	add(
		withPost(c("quarantine-basic", "--quarantine imports under quarantine/<id>/ and prints the ID", csvFile, seedOf(), imp("a.csv", "--quarantine")...), []string{"import", "review", "list"}),
		c("quarantine-quiet", "--quarantine --quiet prints neither the ID nor the summary", csvFile, seedOf(), imp("a.csv", "--quarantine", "--quiet")...),
		c("quarantine-skip-existing", "--quarantine with --skip-existing: a fresh ID never collides", csvFile, seedOf(), imp("a.csv", "--quarantine", "--skip-existing")...),
		c("quarantine-overwrite", "--quarantine with --overwrite", csvFile, seedOf(), imp("a.csv", "--quarantine", "--overwrite")...),
		c("quarantine-bitwarden", "--quarantine over Bitwarden with secret metadata", one(bin("bw.json", bitwardenSource)), seedOf(), imp("bw.json", "--format", "bitwarden", "--quarantine")...),
		c("quarantine-cxf", "--quarantine over CXF", one(bin("export.zip", cxfSource)), seedOf(), imp("export.zip", "--quarantine")...),
		c("quarantine-profile", "--quarantine over a sniffed profile", one(txt("p.csv", chromeCSV)), seedOf(), imp("p.csv", "--quarantine")...),
		c("quarantine-empty-source", "--quarantine over an empty source prints the ID and an empty summary", one(txt("empty.csv", "")), seedOf(), imp("empty.csv", "--quarantine")...),
		c("quarantine-explicit-false", "--quarantine=false imports normally", csvFile, seedOf(), imp("a.csv", "--quarantine=false")...),
		c("quarantine-existing-normal-untouched", "a quarantine import leaves a same-named normal entry alone", csvFile, seedOf(existingEntry("site-one")...), imp("a.csv", "--quarantine")...),
	)

	// 10. Per-format end-to-end imports (state included).
	add(
		withPost(c("e2e-csv-generic", "generic CSV with a search-index probe", csvFile, seedOf(), imp("a.csv")...), []string{"find", "alice"}),
		c("e2e-csv-quoted-multiline", "quoted fields, embedded commas, newlines and unicode", one(txt("q.csv", "title,username,password,notes\n\"Quoted, Title\",\"user\"\"x\",pw-quoted-1234,\"line one\nline two é\"\n")), seedOf(), imp("q.csv")...),
		c("e2e-csv-otp-column", "an otp column is normalized into the totp field", one(txt("o.csv", "title,password,otp\nWithOTP,pw-otp-12345,JBSWY3DPEHPK3PXP\nBadOTP,pw-bad-12345,not-valid!!\nUriOTP,pw-uri-12345,otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&digits=8\n")), seedOf(), imp("o.csv")...),
		c("e2e-csv-crlf", "CRLF line endings", one(txt("crlf.csv", "title,password\r\nwin one,pw-crlf-12345\r\nwin two,pw-crlf-67890\r\n")), seedOf(), imp("crlf.csv")...),
		c("e2e-csv-ragged-rows", "rows shorter and longer than the header", one(txt("r.csv", "title,username,password\nshort,onlyuser\nlong,u,pw-long-12345,extra,cells\n")), seedOf(), imp("r.csv")...),
		c("e2e-csv-path-normalization", "titles with spaces, colons, double dots and edge slashes", one(txt("n.csv", "title,password\n/slash edge/,pw-aaaaaaaa1\nwith: colon?,pw-bbbbbbbb2\na..b,pw-cccccccc3\nTab\there,pw-dddddddd4\n")), seedOf(), imp("n.csv")...),
		c("e2e-csv-field-too-long", "a field above the 4096-character limit fails mid-import", one(txt("long.csv", "title,password\nok-first,pw-first-12345\ntoo-long,"+strings.Repeat("x", 5000)+"\nnever-reached,pw-third-12345\n")), seedOf(), imp("long.csv")...),
		c("e2e-csv-path-too-long", "a very long entry path", one(txt("longpath.csv", "title,password\n"+strings.Repeat("a", 300)+",pw-long-12345\n")), seedOf(), imp("longpath.csv")...),
		c("e2e-csv-many-rows", "forty rows keep their source order", one(txt("many.csv", manyRows(40))), seedOf(), imp("many.csv")...),
		c("e2e-csv-c1-and-nbsp", "C1 control and no-break space characters in titles are accepted", one(txt("c1.csv", "title,password\na\u0085b,pw-c1-1234567\nc\u00a0d,pw-nb-1234567\n")), seedOf(), imp("c1.csv")...),
		c("e2e-csv-dot-title", "a title of . is an invalid path segment", one(txt("dot.csv", "title,password\n.,pw-dot-1234567\n")), seedOf(), imp("dot.csv")...),
		c("e2e-csv-inner-dot-segment", "a ./ segment inside a title is invalid", one(txt("dot.csv", "title,password\na/./b,pw-dot-1234567\n")), seedOf(), imp("dot.csv")...),
		c("e2e-csv-double-slash-title", "an inner // in a title is an empty segment", one(txt("dbl.csv", "title,password\na//b,pw-dbl-1234567\n")), seedOf(), imp("dbl.csv")...),
		c("e2e-csv-path-at-depth-limit", "a 64-segment path is accepted", one(txt("deep.csv", "title,password\n"+strings.TrimSuffix(strings.Repeat("d/", 64), "/")+",pw-deep-123456\n")), seedOf(), imp("deep.csv")...),
		c("e2e-csv-path-over-depth-limit", "a 65-segment path exceeds the vault resource limit", one(txt("deep.csv", "title,password\n"+strings.TrimSuffix(strings.Repeat("d/", 65), "/")+",pw-deep-123456\n")), seedOf(), imp("deep.csv")...),
		c("e2e-apple", "an Apple export with otpauth", one(txt("p.csv", appleCSV)), seedOf(), imp("p.csv")...),
		c("e2e-chrome", "a Chrome export", one(txt("p.csv", chromeCSV)), seedOf(), imp("p.csv")...),
		c("e2e-firefox", "a Firefox export", one(txt("p.csv", firefoxCSV)), seedOf(), imp("p.csv")...),
		c("e2e-firefox-same-host", "two Firefox logins on one host get distinct paths", one(txt("p.csv", "url,username,password,httpRealm\nhttps://same.example/a,u1,pw-same-1234,\nhttps://same.example/b,u2,pw-same-5678,\n")), seedOf(), imp("p.csv")...),
		c("e2e-bitwarden", "Bitwarden login, card (payment metadata), folder and skipped identity", one(bin("bw.json", bitwardenSource)), seedOf(), imp("bw.json", "--format", "bitwarden")...),
		c("e2e-bitwarden-empty-items", "a Bitwarden export without items", one(txt("bw.json", `{"folders":[],"items":[]}`)), seedOf(), imp("bw.json", "--format", "bitwarden")...),
		c("e2e-1password", "a 1PUX archive", one(bin("export.1pux", onePuxArchive)), seedOf(), imp("export.1pux", "--format", "1password")...),
		c("e2e-cxf", "a CXF archive with login, ssh key and payment card", one(bin("export.zip", cxfSource)), seedOf(), imp("export.zip")...),
		c("e2e-pass", "a pass store: password line, url/username lines, notes and an invalid otp", passStore("store"), seedOf(), imp("store", "--format", "pass")...),
		c("e2e-pass-prefix", "a pass store under a prefix", passStore("store"), seedOf(), imp("store", "--format", "pass", "--prefix", "pw")...),
		c("e2e-pass-quarantine", "a pass store in quarantine", passStore("store"), seedOf(), imp("store", "--format", "pass", "--quarantine")...),
	)

	// 11. Quiet and global-flag placement.
	add(
		c("quiet-import", "--quiet suppresses the progress lines and the summary", csvFile, seedOf(), imp("a.csv", "--quiet")...),
		c("quiet-before-command", "--quiet before the command word", csvFile, seedOf(), "--quiet", "import", "a.csv"),
		c("quiet-dry-run", "--quiet --dry-run prints nothing", csvFile, seedOf(), imp("a.csv", "--dry-run", "--quiet")...),
		c("quiet-error-still-printed", "--quiet does not hide an error", nil, seedOf(), imp("missing.csv", "--quiet")...),
		c("quiet-skip-existing", "--quiet hides the skipped-entry lines", csvFile, seedOf(oldSite...), imp("a.csv", "--quiet", "--skip-existing")...),
	)

	// 12. Argument arity and argv shapes.
	add(
		noPost(c("argv-no-source", "no source argument", nil, seedOf(), imp()...)),
		noPost(c("argv-two-sources", "two positional sources", csvFile, seedOf(), imp("a.csv", "b.csv")...)),
		noPost(c("argv-three-sources", "three positional sources", csvFile, seedOf(), imp("a.csv", "b.csv", "c.csv")...)),
		noPost(c("argv-format-as-positional", "the help example `import bitwarden bw-export.json` is two positionals", one(bin("bw-export.json", bitwardenSource)), seedOf(), imp("bitwarden", "bw-export.json")...)),
		noPost(c("argv-flags-only", "flags but no source", nil, seedOf(), imp("--dry-run")...)),
		c("argv-double-dash-source", "a source after -- (named like a flag)", one(txt("--odd.csv", genericCSV)), seedOf(), imp("--", "--odd.csv")...),
		noPost(c("argv-double-dash-two", "two sources after --", csvFile, seedOf(), imp("--", "a.csv", "b.csv")...)),
		c("argv-flags-before-source", "every flag before the source", csvFile, seedOf(), imp("--dry-run", "--prefix", "p", "--format", "csv", "a.csv")...),
		c("argv-flags-after-source", "every flag after the source", csvFile, seedOf(), imp("a.csv", "--skip-existing=false", "--prefix=p", "--format=csv", "--mapping=")...),
		c("argv-empty-source", "an empty-string source", nil, seedOf(), "import", ""),
		c("argv-empty-source-format", "an empty-string source with --format csv", nil, seedOf(), "import", "", "--format", "csv"),
		c("argv-source-dot", "a source of . (the working directory)", nil, seedOf(), imp(".", "--format", "csv")...),
		noPost(c("argv-prefix-needs-argument", "--prefix without its value", csvFile, seedOf(), imp("a.csv", "--prefix")...)),
		noPost(c("argv-format-needs-argument", "--format without its value", csvFile, seedOf(), imp("a.csv", "--format")...)),
		noPost(c("argv-mapping-needs-argument", "--mapping without its value", csvFile, seedOf(), imp("a.csv", "--mapping")...)),
		noPost(c("argv-unknown-flag", "an unknown flag", csvFile, seedOf(), imp("a.csv", "--bogus")...)),
		noPost(c("argv-invalid-bool", "an invalid boolean flag value", csvFile, seedOf(), imp("a.csv", "--dry-run=maybe")...)),
		noPost(c("argv-bool-with-separate-value", "a boolean flag does not take a separate value: false becomes a second positional", csvFile, seedOf(), imp("a.csv", "--dry-run", "false")...)),
		noPost(c("argv-unknown-shorthand", "an unknown shorthand flag", csvFile, seedOf(), imp("a.csv", "-z")...)),
		c("argv-review-word-as-source", "a source file literally named review is not a subcommand when it is the second word", csvFile, seedOf(), imp("a.csv", "review")...),
	)

	// 13. Source error paths.
	badCSV := one(txt("bad.csv", "title,password\n\"unterminated,pw\n"))
	add(
		c("error-missing-source", "a missing source file", nil, seedOf(), imp("missing.csv", "--format", "csv")...),
		c("error-directory-source", "a directory as a CSV source", []fileSpec{{Name: "dir.csv", Dir: true}}, seedOf(), imp("dir.csv")...),
		unix(c("error-unreadable-source", "a source without read permission", []fileSpec{{Name: "locked.csv", Text: genericCSV, Mode: "0000"}}, seedOf(), imp("locked.csv")...)),
		c("error-oversized-source", "a sparse source above the 100 MiB cap", []fileSpec{{Name: "huge.csv", SparseSize: 100*1024*1024 + 1}}, seedOf(), imp("huge.csv")...),
		c("error-oversized-source-dry-run", "the cap also applies under --dry-run", []fileSpec{{Name: "huge.csv", SparseSize: 100*1024*1024 + 1}}, seedOf(), imp("huge.csv", "--dry-run")...),
		c("error-oversized-source-quarantine", "the quarantine ID is printed before the cap error", []fileSpec{{Name: "huge.csv", SparseSize: 100*1024*1024 + 1}}, seedOf(), imp("huge.csv", "--quarantine")...),
		c("error-directory-bitwarden", "a directory as a Bitwarden source", []fileSpec{{Name: "d.json", Dir: true}}, seedOf(), imp("d.json", "--format", "bitwarden")...),
		c("error-directory-1password", "a directory as a 1PUX source", []fileSpec{{Name: "d.1pux", Dir: true}}, seedOf(), imp("d.1pux", "--format", "1password")...),
		c("error-directory-cxf", "a directory as a CXF source", []fileSpec{{Name: "d.zip", Dir: true}}, seedOf(), imp("d.zip")...),
		c("error-directory-apple", "a directory as an Apple-profile source", []fileSpec{{Name: "d.csv", Dir: true}}, seedOf(), imp("d.csv", "--format", "apple")...),
		c("error-csv-malformed-second-record", "an unterminated quote after a valid row names the row", one(txt("bad.csv", "title,password\nok,pw-12345678\n\"unterminated,pw\n")), seedOf(), imp("bad.csv")...),
		c("error-csv-malformed-multiline-quote", "a quote opened on one line and never closed reports the record start", one(txt("bad.csv", "title,notes\nsite,\"line one\nline two\nline three\n")), seedOf(), imp("bad.csv")...),
		c("error-csv-header-malformed", "a malformed header record", one(txt("bad.csv", "ti\"tle,password\nx,y\n")), seedOf(), imp("bad.csv")...),
		c("error-csv-quote-then-text", "text after a closing quote", one(txt("bad.csv", "title,password\n\"ab\"c,pw\n")), seedOf(), imp("bad.csv")...),
		c("error-csv-bare-quote-later-field", "a bare quote in the third field", one(txt("bad.csv", "title,password,url\nx,y,a\"b\n")), seedOf(), imp("bad.csv")...),
		c("error-csv-crlf-malformed", "CRLF input with an unterminated quote", one(txt("bad.csv", "title,password\r\nx,\"y\r\n")), seedOf(), imp("bad.csv")...),
		c("error-csv-unicode-before-error", "multi-byte characters before the error shift the byte column", one(txt("bad.csv", "title,password\nüñí,\"y\n")), seedOf(), imp("bad.csv")...),
		c("error-csv-blank-lines-before-error", "blank lines are skipped but still counted in the line number", one(txt("bad.csv", "title,password\n\n\nx,\"y\n")), seedOf(), imp("bad.csv")...),
		c("limit-exact-cxf", "an archive source of exactly 100 MiB fills Go's limit reader and is rejected by the importer", []fileSpec{{Name: "exact.zip", SparseSize: 100 * 1024 * 1024}}, seedOf(), imp("exact.zip")...),
		c("limit-exact-1password", "a 1PUX source of exactly 100 MiB is rejected by the importer", []fileSpec{{Name: "exact.1pux", SparseSize: 100 * 1024 * 1024}}, seedOf(), imp("exact.1pux", "--format", "1password")...),
		c("limit-under-cxf", "a CXF source one byte under the limit is read and fails as an invalid archive", []fileSpec{{Name: "under.zip", SparseSize: 100*1024*1024 - 1}}, seedOf(), imp("under.zip")...),
		c("limit-over-1password", "a 1PUX source one byte over the limit is rejected by the command", []fileSpec{{Name: "over.1pux", SparseSize: 100*1024*1024 + 1}}, seedOf(), imp("over.1pux", "--format", "1password")...),
		c("error-csv-malformed", "an unterminated quote", badCSV, seedOf(), imp("bad.csv")...),
		c("error-csv-bare-quote", "a bare quote inside an unquoted field", one(txt("bare.csv", "title,password\nab\"c,pw\n")), seedOf(), imp("bare.csv")...),
		c("error-csv-malformed-keeps-vault", "a parse error leaves the stored entries untouched", badCSV, seedOf(oldSite...), imp("bad.csv")...),
		c("error-csv-invalid-utf8", "invalid UTF-8 bytes in a field that is never echoed", one(bin("u.csv", []byte("title,password\nutf8-site,pw-\xff\xfe-12345\n"))), seedOf(), imp("u.csv")...),
		c("error-csv-nul-byte", "a NUL byte in a field", one(bin("nul.csv", []byte("title,password\nna\x00me,pw-nul-123456\n"))), seedOf(), imp("nul.csv")...),
		c("error-bitwarden-malformed", "malformed Bitwarden JSON", one(txt("bw.json", "{not json")), seedOf(), imp("bw.json", "--format", "bitwarden")...),
		c("error-bitwarden-empty-file", "an empty Bitwarden file", one(txt("bw.json", "")), seedOf(), imp("bw.json", "--format", "bitwarden")...),
		c("error-bitwarden-array", "Bitwarden JSON of the wrong shape", one(txt("bw.json", "[1,2]")), seedOf(), imp("bw.json", "--format", "bitwarden")...),
		c("error-bitwarden-wrong-type", "a Bitwarden field of the wrong type", one(txt("bw.json", `{"items":"x"}`)), seedOf(), imp("bw.json", "--format", "bitwarden")...),
		c("error-bitwarden-trailing", "Bitwarden JSON followed by trailing text (the decoder stops after the first value)", one(txt("bw.json", `{"folders":[],"items":[]} trailing`)), seedOf(), imp("bw.json", "--format", "bitwarden")...),
		c("error-bitwarden-null", "Bitwarden JSON null", one(txt("bw.json", "null")), seedOf(), imp("bw.json", "--format", "bitwarden")...),
		c("error-1password-not-zip", "a 1PUX source that is not a zip", one(txt("export.1pux", "not a zip")), seedOf(), imp("export.1pux", "--format", "1password")...),
		c("error-1password-missing-export", "a 1PUX archive without export.json", one(bin("export.1pux", zipOf(zipMember{"other.json", []byte("{}")}))), seedOf(), imp("export.1pux", "--format", "1password")...),
		c("error-1password-bad-json", "a 1PUX archive with invalid export.json", one(bin("export.1pux", zipOf(zipMember{"export.json", []byte("{nope")}))), seedOf(), imp("export.1pux", "--format", "1password")...),
		c("error-1password-empty-file", "an empty 1PUX file", one(txt("export.1pux", "")), seedOf(), imp("export.1pux", "--format", "1password")...),
		c("error-cxf-not-zip", "a CXF source that is not a zip", one(txt("export.zip", "not a zip archive")), seedOf(), imp("export.zip")...),
		c("error-cxf-no-json", "a CXF archive without a JSON document", one(bin("export.zip", zipOf(zipMember{"readme.txt", []byte("x")}))), seedOf(), imp("export.zip")...),
		c("error-cxf-bad-json", "a CXF archive with invalid JSON", one(bin("export.zip", zipOf(zipMember{"manifest.json", []byte("{not-json")}))), seedOf(), imp("export.zip")...),
		c("error-cxf-empty-file", "an empty CXF file", one(txt("export.zip", "")), seedOf(), imp("export.zip")...),
		c("error-apple-empty-file", "an empty Apple-profile file", one(txt("p.csv", "")), seedOf(), imp("p.csv", "--format", "apple")...),
		c("error-profile-missing-columns", "a Firefox profile over a file without the profile columns", csvFile, seedOf(), imp("a.csv", "--format", "firefox")...),
		c("error-pass-gpg-missing", "a pass store when no gpg is on PATH", []fileSpec{txt("store/a.gpg", "x\n")}, seedOf(), imp("store", "--format", "pass")...),
	)

	// 14. Vault preconditions: parse errors precede the vault check.
	valid := csvFile
	add(
		noPost(c("vault-not-initialized", "a valid source and no vault", valid, nil, imp("a.csv")...)),
		noPost(c("vault-not-initialized-dry-run", "--dry-run still needs the vault", valid, nil, imp("a.csv", "--dry-run")...)),
		noPost(c("vault-not-initialized-quarantine", "the quarantine ID is printed before the vault check", valid, nil, imp("a.csv", "--quarantine")...)),
		noPost(c("vault-not-initialized-malformed", "a malformed source fails before the vault check", badCSV, nil, imp("bad.csv")...)),
		noPost(c("vault-not-initialized-missing", "a missing source fails before the vault check", nil, nil, imp("missing.csv")...)),
		noPost(c("vault-not-initialized-conflict", "a flag conflict fails before the vault check", valid, nil, imp("a.csv", "--skip-existing", "--overwrite")...)),
		noPost(c("vault-not-initialized-unsupported", "an unsupported format fails before the vault check", valid, nil, imp("a.csv", "--format", "nope")...)),
		noPost(c("vault-not-initialized-bad-mapping", "an invalid mapping fails before the vault check", valid, nil, imp("a.csv", "--mapping", "bad")...)),
		noPost(c("vault-not-initialized-empty-csv", "an empty source still needs the vault", one(txt("empty.csv", "")), nil, imp("empty.csv")...)),
		noPost(c("vault-not-initialized-oversized", "the size cap fails before the vault check", []fileSpec{{Name: "huge.csv", SparseSize: 100*1024*1024 + 1}}, nil, imp("huge.csv")...)),
	)

	return cs
}
