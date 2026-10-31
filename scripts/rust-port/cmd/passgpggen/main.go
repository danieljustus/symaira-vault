// Command passgpggen freezes the production pass importer against REAL gpg
// (IO-001 "real GPG cryptographic compatibility" residual).
//
// The older onepass.json case drives the importer through a synthetic gpg shim
// that merely `cat`s its input. This generator instead:
//
//  1. creates a test-only keypair (empty passphrase) in a disposable
//     GNUPGHOME, and a second "foreign" keypair in another one;
//  2. encrypts a corpus of pass entries with the real gpg binary: single-line
//     passwords, key: value fields, otpauth URIs, Unicode, CRLF/CR, empty and
//     newline-only content, binary / invalid UTF-8 plaintext, ASCII-armored
//     entries, an entry encrypted to a key that is NOT in the keyring, a
//     symmetric entry, corrupted / truncated ciphertext, plain text in a .gpg
//     file, nested directories, symlinks and non-.gpg files;
//  3. imports ONLY the first secret key (armored) into a third disposable
//     GNUPGHOME and runs the REAL Go importer (importer.New(FormatPass)) over
//     every store, recording entries, warnings and the complete error text.
//
// The ciphertexts and the armored secret key are stored in the fixture, so the
// Rust replay (crates/symvault-sync/tests/pass_gpg_contract.rs) decrypts
// identical bytes with the same keyring state and needs no key generation, and
// --check never re-encrypts (gpg encryption is randomized): it decrypts the
// stored ciphertexts and re-runs the Go importer.
//
// Environment pinned for Go and Rust alike (Go forwards LC_ALL and GNUPGHOME
// from its process environment to gpg, so gpg's wording is locale dependent):
// LC_ALL=C, GNUPGHOME=<disposable>, HOME=<disposable>, and a gpg-agent.conf
// whose pinentry-program is /usr/bin/false so a passphrase prompt can never
// open a GUI.
//
// What of gpg's stderr reaches Go: on success nothing (stderr is discarded);
// on failure the whole trimmed stderr is appended to
// "decrypt pass entry <path>: ". That text carries the store path, key ids and
// key creation dates (all fixed by the stored ciphertext/key) and wording that
// differs between gpg versions. Two narrow comparison rules, shared by this
// generator's --check and the Rust replay and recorded in the fixture's
// "normalization" block, deal with this; no field is ever dropped:
//
//	N1 (store root): every occurrence of the store root as Go prints it
//	   (filepath.Clean of the argument; nothing when that is ".") is replaced
//	   by "@STORE". An un-cleaned spelling is NOT rewritten, so a port that
//	   prints "./store" or "a//b" still differs.
//	N2 (gpg version drift): only for a case flagged version_variant and only
//	   when the replaying gpg version line differs from the recorded one: lines
//	   equal to an entry of optional_stderr_lines are removed and consecutive
//	   identical lines are collapsed, on both sides. With an identical gpg
//	   version string the raw text must be byte-identical.
package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strings"

	"github.com/danieljustus/symaira-vault/internal/importer"
	"github.com/danieljustus/symaira-vault/scripts/rust-port/internal/provenance"
)

const (
	pinnedOracleCommit = "fca3f89401833b5e14ec4ec74ef736b0f63bca74"
	defaultOutput      = "testdata/port/sync/pass-gpg.json"
	storeMarker        = "@STORE"
	storeDirName       = "pass-store.d"
	agentConf          = "pinentry-program /usr/bin/false\n"
	symPassphrase      = "symmetric-test-passphrase"
	keyUID             = "Symvault Pass Test <pass-test@example.invalid>"
	foreignUID         = "Symvault Foreign Test <foreign@example.invalid>"
)

var gpgArgs = []string{"--decrypt", "--batch", "--yes"}

type entry struct {
	Path     string         `json:"path"`
	Data     map[string]any `json:"data"`
	Warnings []string       `json:"warnings"`
}

type fileSpec struct {
	Path string `json:"path"`
	// Kind: encrypted | raw | symlink | dir | locked_dir.
	Kind string `json:"kind"`
	// Mode (encrypted only): main | armor | foreign | symmetric | corrupted |
	// truncated | armor_truncated.
	Mode string `json:"mode,omitempty"`
	// ContentBase64 is what is written to disk (the ciphertext for encrypted).
	ContentBase64 string `json:"content_base64,omitempty"`
	// PlaintextBase64 is what gpg was given (encrypted only).
	PlaintextBase64 string `json:"plaintext_base64,omitempty"`
	// Decrypts says the keyring can decrypt ContentBase64 to PlaintextBase64.
	Decrypts bool `json:"decrypts,omitempty"`
	// Target is a symlink target (verbatim).
	Target string `json:"target,omitempty"`
}

type testCase struct {
	ID                  string     `json:"id"`
	StoreForm           string     `json:"store_form"`
	Files               []fileSpec `json:"files"`
	Expected            []entry    `json:"expected"`
	Failed              bool       `json:"failed"`
	Error               string     `json:"error,omitempty"`
	VersionVariant      bool       `json:"version_variant,omitempty"`
	OptionalStderrLines []string   `json:"optional_stderr_lines,omitempty"`
}

type oracle struct {
	Commit          string   `json:"commit"`
	Sources         []string `json:"sources"`
	SourceDigest    string   `json:"source_digest"`
	GeneratorDigest string   `json:"generator_digest"`
	GoVersion       string   `json:"go_version"`
	GOOS            string   `json:"goos"`
	GPGVersion      string   `json:"gpg_version"`
	GPGArgs         []string `json:"gpg_args"`
}

type keyring struct {
	Fingerprint    string `json:"fingerprint"`
	SecretKeyArmor string `json:"secret_key_armor"`
	AgentConf      string `json:"agent_conf"`
	Note           string `json:"note"`
}

type normalization struct {
	Environment string `json:"environment"`
	N1          string `json:"n1_store_root"`
	N2          string `json:"n2_gpg_version_drift"`
	Stderr      string `json:"gpg_stderr_reaching_go"`
	StoreForms  string `json:"store_forms"`
	TwoRun      string `json:"two_run_check"`
}

type fixture struct {
	SchemaVersion int           `json:"schema_version"`
	Oracle        oracle        `json:"oracle"`
	Keyring       keyring       `json:"keyring"`
	Normalization normalization `json:"normalization"`
	Cases         []testCase    `json:"cases"`
}

func documentedNormalization() normalization {
	return normalization{
		Environment: "LC_ALL=C, GNUPGHOME and HOME point to disposable directories, gpg-agent.conf is keyring.agent_conf, the keyring holds only the imported secret key; PATH is inherited (gpg is resolved there). Go forwards these because secrets.PrepareCmd allowlists LC_ALL, GNUPGHOME and HOME.",
		N1:          "occurrences of filepath.Clean(store argument) in the error text are replaced by " + storeMarker + "; nothing is replaced when the cleaned argument is \".\" (Go then prints bare relative names); an un-cleaned spelling is not rewritten",
		N2:          "only for version_variant cases and only when the replaying `gpg --version` first line differs from oracle.gpg_version: lines equal to an optional_stderr_lines entry are removed and consecutive identical lines collapsed, on both sides; otherwise the error text is compared byte for byte",
		Stderr:      "success: gpg stderr is discarded; failure: error = \"decrypt pass entry <path>: \" + strings.TrimSpace(stderr) (or err.Error() when stderr is empty)",
		StoreForms:  "the store argument is spelled plain, with a trailing slash, a doubled slash, a ./ segment, a parent segment, relative, ./relative or as \".\" (cwd inside the store) so Go's path.Join cleaning of printed paths is pinned",
		TwoRun:      "every case is evaluated twice against the real Go importer and any difference fails generation",
	}
}

type genFile struct {
	path     string
	kind     string
	mode     string
	plain    []byte
	target   string
	decrypts bool
}

type genCase struct {
	id             string
	form           string
	files          []genFile
	versionVariant bool
	optional       []string
}

func enc(path, mode string, plain []byte) genFile {
	return genFile{path: path, kind: "encrypted", mode: mode, plain: plain, decrypts: mode == "main" || mode == "armor"}
}

func e(path string, plain string) genFile { return enc(path, "main", []byte(plain)) }

func raw(path, content string) genFile {
	return genFile{path: path, kind: "raw", plain: []byte(content)}
}

func bigNote() string {
	var b strings.Builder
	b.WriteString("big-password\n")
	for i := 0; i < 1250; i++ {
		fmt.Fprintf(&b, "line %05d: the quick brown fox jumps over the lazy dog\n", i)
	}
	return b.String()
}

// totpURLFiles pins the net/url, ParseQuery and strconv behavior that ParseTOTP
// exposes through otpauth:// lines. Each line is its own entry so a rejection
// is recorded as that entry's warning, not as an aborted import.
func totpURLFiles() []genFile {
	const sec = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"
	var files []genFile
	add := func(name, line string) {
		files = append(files, e("url/"+name+".gpg", "pw\n"+line+"\n"))
	}
	pre := "otpauth://totp/x?secret=" + sec
	add("ok", pre)
	add("upper-scheme-and-type", "OTPAUTH://TOTP/x?secret="+sec)
	add("mixed-scheme", "OtpAuth://ToTp/x?secret="+sec)
	add("no-slash-after-host", "otpauth://totp?secret="+sec)
	add("empty-host", "otpauth:///x?secret="+sec)
	add("empty-host-and-path", "otpauth://?secret="+sec)
	add("type-with-port", "otpauth://totp:80/x?secret="+sec)
	add("type-with-bad-port", "otpauth://totp:x/y?secret="+sec)
	add("type-with-empty-port", "otpauth://totp:/y?secret="+sec)
	add("two-colons-host", "otpauth://totp:1:2/y?secret="+sec)
	add("userinfo", "otpauth://user@totp/x?secret="+sec)
	add("userinfo-password", "otpauth://user:pa%20ss@totp/x?secret="+sec)
	add("userinfo-at-sign", "otpauth://us@er@totp/x?secret="+sec)
	add("userinfo-bad-char", "otpauth://us<er@totp/x?secret="+sec)
	add("userinfo-bad-escape", "otpauth://us%zzer@totp/x?secret="+sec)
	add("userinfo-unicode", "otpauth://üser@totp/x?secret="+sec)
	add("fragment", pre+"#frag")
	add("fragment-bad-escape", pre+"#%zz")
	add("fragment-trailing-percent", pre+"#a%")
	add("empty-fragment", pre+"#")
	add("space-in-path", "otpauth://totp/x y?secret="+sec)
	add("path-bad-escape", "otpauth://totp/%zz?secret="+sec)
	add("path-short-escape", "otpauth://totp/%a?secret="+sec)
	add("path-trailing-percent", "otpauth://totp/x%")
	add("path-escape-before-query", "otpauth://totp/%7e?secret="+sec)
	add("host-escape-low", "otpauth://to%74p/x?secret="+sec)
	add("host-escape-high", "otpauth://tot%C3%A9/x?secret="+sec)
	add("host-bad-char", "otpauth://to^tp/x?secret="+sec)
	add("host-space", "otpauth://to tp/x?secret="+sec)
	add("host-angle-quote", "otpauth://to<t>\"p/x?secret="+sec)
	add("host-unicode", "otpauth://tötp/x?secret="+sec)
	add("ipv6-literal", "otpauth://[::1]/x?secret="+sec)
	add("ipv6-literal-port", "otpauth://[::1]:80/x?secret="+sec)
	add("ipv6-bad-port", "otpauth://[::1]:x/x?secret="+sec)
	add("ipv6-zone", "otpauth://[fe80::1%25en0]/x?secret="+sec)
	add("ipv6-zone-bad-escape", "otpauth://[fe80::1%25%zz]/x?secret="+sec)
	add("ipv6-zone-empty", "otpauth://[fe80::1%25]/x?secret="+sec)
	add("ipv6-host-escape", "otpauth://[%3a%3a1]/x?secret="+sec)
	add("ipv6-missing-bracket", "otpauth://[::1/x?secret="+sec)
	add("ipv6-prefix-before-bracket", "otpauth://a[::1]/x?secret="+sec)
	add("ipv6-ipv4", "otpauth://[1.2.3.4]/x?secret="+sec)
	add("ipv6-ipv4-mapped", "otpauth://[::ffff:1.2.3.4]/x?secret="+sec)
	add("ipv6-garbage", "otpauth://[zz]/x?secret="+sec)
	add("ipv6-empty", "otpauth://[]/x?secret="+sec)
	add("ipv6-too-many-digits", "otpauth://[12345::1]/x?secret="+sec)
	add("ipv6-double-ellipsis", "otpauth://[1::2::3]/x?secret="+sec)
	add("ipv6-too-short", "otpauth://[1:2:3]/x?secret="+sec)
	add("ipv6-too-long", "otpauth://[1:2:3:4:5:6:7:8:9]/x?secret="+sec)
	add("ipv6-trailing-garbage", "otpauth://[::1g]/x?secret="+sec)
	add("ipv6-trailing-colon", "otpauth://[1:]/x?secret="+sec)
	add("ipv6-want-colon", "otpauth://[1x2::]/x?secret="+sec)
	add("ipv6-ellipsis-full", "otpauth://[1:2:3:4:5:6:7::8]/x?secret="+sec)
	add("ipv6-embedded-v4", "otpauth://[::1.2.3.4]/x?secret="+sec)
	add("ipv6-embedded-v4-bad", "otpauth://[::1.2.3]/x?secret="+sec)
	add("ipv6-embedded-v4-misplaced", "otpauth://[1:2.3.4.5::]/x?secret="+sec)
	add("ipv6-embedded-v4-leading-zero", "otpauth://[::01.2.3.4]/x?secret="+sec)
	add("ipv6-embedded-v4-range", "otpauth://[::1.2.3.256]/x?secret="+sec)
	add("ipv6-embedded-v4-dots", "otpauth://[::1..3.4]/x?secret="+sec)
	add("ipv6-embedded-v4-long", "otpauth://[::1.2.3.4.5]/x?secret="+sec)
	add("ipv6-embedded-v4-char", "otpauth://[::1.2.x.4]/x?secret="+sec)
	add("ipv4-literal", "otpauth://1.2.3.4/x?secret="+sec)
	add("ctl-in-path", "otpauth://totp/a\x01b?secret="+sec)
	add("del-in-query", "otpauth://totp/x?secret="+sec+"\x7f")
	add("tab-inside", "otpauth://totp/a\tb?secret="+sec)
	add("invalid-bytes-and-bad-escape", "otpauth://totp/\xff%zz?secret="+sec)
	add("invalid-bytes-in-host", "otpauth://tot\xffp/x?secret="+sec)
	add("invalid-bytes-bad-port", "otpauth://totp:\xff/x?secret="+sec)
	add("unicode-quote", "otpauth://totp/日本\u00a0語%zz?secret="+sec)
	add("long-escape-tail", "otpauth://totp/x%zzzz?secret="+sec)
	add("trailing-spaces", "otpauth://totp/x?secret="+sec+"  \t")
	add("trailing-unicode-space", "otpauth://totp/x?secret="+sec+"\u2003\u0085")
	add("duplicate-secret-first-wins", pre+"&secret=short")
	add("empty-first-secret", "otpauth://totp/x?secret=&secret="+sec)
	add("bad-escape-first-secret", "otpauth://totp/x?secret=%zz&secret="+sec)
	add("semicolon-pair-dropped", "otpauth://totp/x?secret="+sec+"&issuer=a;b")
	add("semicolon-in-secret-pair", "otpauth://totp/x?secret=a;b&secret="+sec)
	add("upper-key-ignored", "otpauth://totp/x?SECRET="+sec)
	add("escaped-key", "otpauth://totp/x?%73ecret="+sec)
	add("escaped-secret-value", "otpauth://totp/x?secret=%4A%42SWY3DPEHPK3PXPJBSWY3DPEHPK3PXP")
	add("plus-is-space", "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP+JBSWY3DPEHPK3PXP")
	add("empty-pairs", "otpauth://totp/x?&&secret="+sec+"&&")
	add("key-without-equals", "otpauth://totp/x?secret&secret="+sec)
	add("missing-secret", "otpauth://totp/x?issuer=Example")
	add("empty-query", "otpauth://totp/x?")
	add("force-query-only", "otpauth://totp/x??secret="+sec)
	add("secret-is-invalid-utf8", "otpauth://totp/x?secret=%FF%FE")
	add("secret-too-long", "otpauth://totp/x?secret="+strings.Repeat("A", 300))
	add("secret-weak-identical", "otpauth://totp/x?secret=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	add("digits-8", pre+"&digits=8")
	add("digits-text", pre+"&digits=abc")
	add("digits-plus", pre+"&digits=%2B8")
	add("digits-leading-zero", pre+"&digits=08")
	add("digits-negative", pre+"&digits=-6")
	add("digits-overflow", pre+"&digits=99999999999999999999")
	add("digits-negative-overflow", pre+"&digits=-99999999999999999999")
	add("digits-invalid-utf8", pre+"&digits=%FF")
	add("digits-unicode", pre+"&digits=%E2%82%AC")
	add("digits-space", pre+"&digits=%206")
	add("digits-seven", pre+"&digits=7")
	add("digits-quote-chars", pre+"&digits=%22%5C%01")
	add("period-float", pre+"&period=1e3")
	add("period-zero", pre+"&period=0")
	add("period-max", pre+"&period=3600")
	add("period-over", pre+"&period=3601")
	add("period-underscore", pre+"&period=1_0")
	add("period-invalid-utf8", pre+"&period=%C3")
	add("period-overflow", pre+"&period=9223372036854775808")
	add("period-int64-max", pre+"&period=9223372036854775807")
	add("algorithm-lower", pre+"&algorithm=sha256")
	add("algorithm-sha512", pre+"&algorithm=SHA512")
	add("algorithm-unknown", pre+"&algorithm=SHA3")
	add("algorithm-sharp-s", pre+"&algorithm=%C3%9F")
	add("algorithm-long-s", pre+"&algorithm=%C5%BFha1")
	add("algorithm-control", pre+"&algorithm=%01x")
	add("algorithm-nbsp", pre+"&algorithm=%C2%A0")
	add("algorithm-invalid-utf8", pre+"&algorithm=%FF")
	add("algorithm-unicode-lower", pre+"&algorithm=%D0%B0%D0%B1")
	add("algorithm-quote", pre+"&algorithm=%22%5C")
	add("algorithm-empty", pre+"&algorithm=")
	add("many-params-at-limit", pre+strings.Repeat("&a", 9999))
	add("many-params-over-limit", pre+strings.Repeat("&a", 10000))
	return files
}

func corpus() []genCase {
	otp := "otpauth://totp/Example:alice@example.com?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP&issuer=Example"
	cases := []genCase{
		{id: "store_totp_urls", form: "plain", files: totpURLFiles()},
		{id: "store_basic_formats", form: "plain", files: []genFile{
			e("password-only.gpg", "hunter2\n"),
			e("no-trailing-newline.gpg", "hunter2"),
			e("double-trailing-newline.gpg", "pw\n\n"),
			e("only-newline.gpg", "\n"),
			e("empty-content.gpg", ""),
			e("multi-field.gpg", "s3cret\nusername: alice\nurl: https://example.test/login\nsecurity question: blue\nanother: field\n"),
			e("blank-lines.gpg", "pw\n\n\nnote after blanks\n\n"),
			e("leading-blank-line.gpg", "\nsecond line is a note\n"),
			e("prefix-edges.gpg", "pw\nurl:no-space\nURL: UPPER\nusername:\nusername: \nurl: \n  indented: note\n\tuser: tab\n"),
			e("duplicate-keys.gpg", "pw\nurl: a\nurl: b\nusername: x\nusername: y\n"),
			e("field-looking-first-line.gpg", "url: not-a-field\nusername: u\n"),
			e("trim-url-and-username.gpg", "pw\nurl:   https://trim.test \t \nusername: \t padded user  \n"),
		}},
		{id: "store_totp", form: "plain", files: []genFile{
			e("totp-valid.gpg", "pw\n"+otp+"\n"),
			e("totp-params.gpg", "pw\notpauth://totp/Acme:bob?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP&digits=8&period=60&algorithm=SHA256&issuer=Acme\n"),
			e("totp-invalid-secret.gpg", "pw\notpauth://totp/x?secret=bad\nafter\n"),
			e("totp-hotp.gpg", "pw\notpauth://hotp/x?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP&counter=1\n"),
			e("totp-two-lines.gpg", "pw\n"+otp+"\notpauth://totp/second?secret=bad\n"+otp+"\n"),
			e("totp-first-line.gpg", otp+"\nusername: u\n"),
			e("totp-crlf.gpg", "pw\r\n"+otp+"\r\nnote\r\n"),
			e("totp-invalid-bytes.gpg", "pw\notpauth://totp/\xff\xfe?secret=bad\n"),
			e("totp-percent-bad.gpg", "pw\notpauth://totp/%zz?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP\n"),
			e("totp-spaced-lowercase.gpg", "pw\notpauth://totp/Lower?secret=jbswy3dp ehpk3pxp jbswy3dp ehpk3pxp\n"),
			e("totp-unusual-params.gpg", "pw\notpauth://totp/x?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP&digits=7&period=0&algorithm=MD5\n"),
			e("totp-empty-secret.gpg", "pw\notpauth://totp/x?secret=\n"),
		}},
		{id: "store_text_encodings", form: "plain", files: []genFile{
			e("unicode.gpg", "pässwörd-日本語-🔑\nusername: ユーザー\nurl: https://ünï.test/ä\nnote: ☃ snow\n"),
			e("unicode-spaces-trim.gpg", "pw\nurl: \u00a0https://nbsp.test\u00a0\u2003\nusername: \u3000wide\u0085\n"),
			e("nfd-combining.gpg", "pa\u0301ss\nusername: e\u0301\n"),
			e("bom.gpg", "\ufeffpw-with-bom\nusername: u\n"),
			e("crlf.gpg", "pw\r\nusername: bob\r\nurl: https://crlf.test\r\nnote one\r\nnote two\r\n"),
			e("cr-only.gpg", "pw\rusername: x\rnote\r"),
			e("mixed-line-endings.gpg", "pw\nusername: m\r\nnote a\rnote b\n\r\n"),
			e("tabs-and-controls.gpg", "pw\twith\ttabs\nnote\x01\x02\x1b[0m\n"),
			e("nul-byte.gpg", "pw\x00after-nul\nnote\x00\n"),
			e("binary-invalid-utf8.gpg", "\xe2\x82\n\xff\n"),
			e("invalid-utf8-fields.gpg", "pw\xff\nurl: \xff\xfe \nusername: \xc3\nnote \xc0\xaf \xed\xa0\x80 \xf4\x90\x80\x80 \xf0\x9f\n"),
			e("long-line.gpg", strings.Repeat("0123456789abcdef", 4096)+"\nusername: long\n"),
		}},
		{id: "store_layout", form: "plain", files: []genFile{
			e("top.gpg", "top\n"),
			e("Sp ace/entry with space.gpg", "spaced\n"),
			e("work/example.gpg", "example-secret\nusername:  example-user\nurl: https://example.test\ncomment line\n"),
			e("work/deep/er/nested/entry.gpg", "nested\n"),
			e("work/sub.dir/x.gpg", "dotted dir\n"),
			e(".hidden.gpg", "hidden file\n"),
			e(".hidden-dir/inside.gpg", "hidden dir\n"),
			e("日本/ключ.gpg", "unicode names\n"),
			e("slash\\name.gpg", "backslash\n"),
			e("a.gpg.gpg", "double suffix\n"),
			e("dir.gpg/inside.gpg", "dir named like an entry\n"),
			e("..dots...gpg", "dots\n"),
			e("trailing-space .gpg", "name with trailing space\n"),
			e("UPPERCASE.GPG", "ignored: suffix is case sensitive\n"),
			raw(".gpg-id", "pass-test@example.invalid\n"),
			raw("README.md", "# not an entry\n"),
			raw("notes.txt", "plain\n"),
			raw("entry.gpg.bak", "not matched\n"),
			raw("entry.asc", "-----BEGIN PGP MESSAGE-----\n"),
			raw(".git/config", "[core]\n"),
			raw(".git/objects/x.gpg.orig", "x\n"),
			{path: "empty-dir", kind: "dir"},
			{path: "empty.gpg.d", kind: "dir"},
		}},
		{id: "store_large_entry", form: "plain", files: []genFile{
			e("big.gpg", bigNote()),
			e("small.gpg", "small\n"),
		}},
		{id: "store_armored_and_links", form: "plain", files: []genFile{
			enc("armored.gpg", "armor", []byte("armored-secret\nusername: arm\nurl: https://armor.test\n")),
			enc("armored-unicode.gpg", "armor", []byte("ärmored-日本\n")),
			e("real/target.gpg", "link target\n"),
			{path: "link-to-entry.gpg", kind: "symlink", target: "real/target.gpg"},
			{path: "link-to-dir", kind: "symlink", target: "real"},
		}},
	}
	// Path spellings of the store argument. Each store has one good entry and
	// a foreign-key entry so the error text carries the printed path.
	for _, form := range []string{"plain", "trailing_slash", "double_slash", "dot_segment", "parent_segment", "relative", "relative_dot", "cwd_dot", "symlink_root", "symlink_root_slash", "symlink_root_gpg"} {
		cases = append(cases, genCase{id: "path_form_" + form, form: form, files: []genFile{
			e("a-good.gpg", "good\n"),
			enc("sub/b-foreign.gpg", "foreign", []byte("not decryptable here\n")),
		}})
	}
	// Failure cases: one store each, since the first failure aborts the import.
	good := e("a-good.gpg", "good\nusername: u\n")
	cases = append(cases,
		genCase{id: "error_foreign_key", form: "plain", files: []genFile{good, enc("b-foreign.gpg", "foreign", []byte("secret for someone else\n"))}},
		genCase{id: "error_symmetric_no_pinentry", form: "plain", files: []genFile{good, enc("b-symmetric.gpg", "symmetric", []byte("symmetric secret\n"))}},
		genCase{id: "error_corrupted_ciphertext", form: "plain", files: []genFile{good, enc("b-corrupted.gpg", "corrupted", []byte("will be corrupted\n"))},
			versionVariant: true, optional: []string{"gpg: WARNING: encrypted message has been manipulated!"}},
		genCase{id: "error_truncated_ciphertext", form: "plain", files: []genFile{good, enc("b-truncated.gpg", "truncated", []byte("will be truncated\n"))},
			versionVariant: true},
		genCase{id: "error_armor_truncated", form: "plain", files: []genFile{good, enc("b-armor-truncated.gpg", "armor_truncated", []byte("armor will be cut\n"))},
			versionVariant: true, optional: []string{"gpg: no valid OpenPGP data found."}},
		genCase{id: "error_plain_text_in_gpg_file", form: "plain", files: []genFile{good, {path: "b-plain.gpg", kind: "raw", plain: []byte("just plain text\n")}}},
		genCase{id: "error_empty_gpg_file", form: "plain", files: []genFile{good, {path: "b-empty.gpg", kind: "raw", plain: []byte{}}}},
		genCase{id: "error_bare_gpg_name", form: "plain", files: []genFile{{path: ".gpg", kind: "raw", plain: []byte("not encrypted\n")}}},
		genCase{id: "error_dangling_symlink", form: "plain", files: []genFile{good, {path: "b-dangling.gpg", kind: "symlink", target: "nowhere.gpg"}}},
		genCase{id: "error_directory_symlink_named_gpg", form: "plain", files: []genFile{good, e("real/t.gpg", "t\n"), {path: "b-dir-link.gpg", kind: "symlink", target: "real"}}},
		genCase{id: "error_first_failure_wins", form: "plain", files: []genFile{
			good,
			enc("b-first-foreign.gpg", "foreign", []byte("first\n")),
			{path: "c-second-plain.gpg", kind: "raw", plain: []byte("plain\n")},
		}},
		genCase{id: "error_in_nested_directory_after_good_entries", form: "plain", files: []genFile{
			good, e("m/ok.gpg", "ok\n"), enc("m/z/bad-foreign.gpg", "foreign", []byte("bad\n")), e("z-after.gpg", "after\n"),
		}},
		genCase{id: "error_unreadable_directory", form: "plain", files: []genFile{good, e("locked/inside.gpg", "hidden\n"), {path: "locked", kind: "locked_dir"}}},
		genCase{id: "error_decrypt_failure_precedes_unreadable_directory", form: "plain", files: []genFile{
			enc("a-foreign.gpg", "foreign", []byte("foreign\n")), e("z-locked/inside.gpg", "hidden\n"), {path: "z-locked", kind: "locked_dir"},
		}},
		genCase{id: "error_unreadable_directory_precedes_decrypt_failure", form: "plain", files: []genFile{
			e("a-locked/inside.gpg", "hidden\n"), {path: "a-locked", kind: "locked_dir"}, enc("z-foreign.gpg", "foreign", []byte("foreign\n")),
		}},
		genCase{id: "error_unreadable_store_root", form: "plain", files: []genFile{good, {path: ".", kind: "locked_dir"}}},
		genCase{id: "error_store_missing", form: "missing"},
		genCase{id: "error_store_is_file", form: "file"},
	)
	return cases
}

// ---- gpg helpers ----------------------------------------------------------

type gpgEnv struct {
	root string // short disposable parent of every home
	n    int
}

func newGPGEnv() (*gpgEnv, error) {
	// gpg-agent sockets live under GNUPGHOME and sockaddr_un is ~104 bytes.
	base := os.TempDir()
	if len(base) > 40 {
		base = "/tmp"
	}
	dir, err := os.MkdirTemp(base, "pgg-")
	if err != nil {
		return nil, err
	}
	return &gpgEnv{root: dir}, nil
}

func (g *gpgEnv) newHome(label string) (string, error) {
	g.n++
	home := filepath.Join(g.root, fmt.Sprintf("%s%d", label, g.n))
	if err := os.MkdirAll(home, 0o700); err != nil {
		return "", err
	}
	if err := os.WriteFile(filepath.Join(home, "gpg-agent.conf"), []byte(agentConf), 0o600); err != nil {
		return "", err
	}
	return home, nil
}

func homeEnv(home string) []string {
	return []string{"PATH=" + os.Getenv("PATH"), "GNUPGHOME=" + home, "LC_ALL=C", "HOME=" + home}
}

func gpg(home string, stdin []byte, args ...string) ([]byte, []byte, error) {
	cmd := exec.Command("gpg", args...)
	cmd.Env = homeEnv(home)
	cmd.Stdin = bytes.NewReader(stdin)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	err := cmd.Run()
	return out.Bytes(), errb.Bytes(), err
}

func mustGPG(home string, stdin []byte, args ...string) []byte {
	out, stderr, err := gpg(home, stdin, args...)
	if err != nil {
		must(fmt.Errorf("gpg %s: %w: %s", strings.Join(args, " "), err, stderr))
	}
	return out
}

func killAgent(home string) {
	cmd := exec.Command("gpgconf", "--kill", "all")
	cmd.Env = homeEnv(home)
	_ = cmd.Run()
}

func (g *gpgEnv) close() {
	entries, _ := os.ReadDir(g.root)
	for _, ent := range entries {
		killAgent(filepath.Join(g.root, ent.Name()))
	}
	_ = os.RemoveAll(g.root)
}

func gpgVersion() (string, error) {
	out, err := exec.Command("gpg", "--version").Output()
	if err != nil {
		return "", fmt.Errorf("gpg is required (fail closed): %w", err)
	}
	return strings.TrimSpace(strings.SplitN(string(out), "\n", 2)[0]), nil
}

func fingerprint(home, uid string) string {
	out := mustGPG(home, nil, "--batch", "--with-colons", "--list-secret-keys", uid)
	for _, line := range strings.Split(string(out), "\n") {
		if f := strings.Split(line, ":"); f[0] == "fpr" {
			return f[9]
		}
	}
	must(fmt.Errorf("no fingerprint for %s", uid))
	return ""
}

func genKey(home, uid string) string {
	mustGPG(home, nil, "--batch", "--pinentry-mode", "loopback", "--passphrase", "", "--quick-gen-key", uid, "default", "default", "never")
	return fingerprint(home, uid)
}

// encryptAll fills in the ciphertext of every encrypted spec.
func encryptAll(env *gpgEnv, cases []genCase) ([]testCase, string, error) {
	mainHome, err := env.newHome("m")
	if err != nil {
		return nil, "", err
	}
	foreignHome, err := env.newHome("f")
	if err != nil {
		return nil, "", err
	}
	mainFPR := genKey(mainHome, keyUID)
	foreignFPR := genKey(foreignHome, foreignUID)
	armor := string(mustGPG(mainHome, nil, "--batch", "--pinentry-mode", "loopback", "--passphrase", "", "--armor", "--export-secret-keys", mainFPR))

	encrypt := func(file genFile) []byte {
		base := []string{"--batch", "--yes", "--trust-model", "always"}
		switch file.mode {
		case "main":
			return mustGPG(mainHome, file.plain, append(base, "-r", mainFPR, "--encrypt", "--output", "-")...)
		case "armor", "armor_truncated":
			out := mustGPG(mainHome, file.plain, append(base, "--armor", "-r", mainFPR, "--encrypt", "--output", "-")...)
			if file.mode == "armor_truncated" {
				return out[:len(out)*2/3]
			}
			return out
		case "foreign":
			return mustGPG(foreignHome, file.plain, append(base, "-r", foreignFPR, "--encrypt", "--output", "-")...)
		case "symmetric":
			return mustGPG(mainHome, file.plain, "--batch", "--yes", "--pinentry-mode", "loopback", "--passphrase", symPassphrase, "--symmetric", "--output", "-")
		case "corrupted":
			out := mustGPG(mainHome, file.plain, append(base, "-r", mainFPR, "--encrypt", "--output", "-")...)
			out[len(out)-5] ^= 0xff
			return out
		case "truncated":
			out := mustGPG(mainHome, file.plain, append(base, "-r", mainFPR, "--encrypt", "--output", "-")...)
			return out[:100]
		}
		must(fmt.Errorf("unknown encryption mode %q", file.mode))
		return nil
	}

	out := make([]testCase, 0, len(cases))
	for _, c := range cases {
		tc := testCase{ID: c.id, StoreForm: c.form, Files: []fileSpec{}, VersionVariant: c.versionVariant, OptionalStderrLines: c.optional}
		for _, f := range c.files {
			spec := fileSpec{Path: f.path, Kind: f.kind, Mode: f.mode, Target: f.target, Decrypts: f.decrypts}
			switch f.kind {
			case "encrypted":
				spec.PlaintextBase64 = base64.StdEncoding.EncodeToString(f.plain)
				spec.ContentBase64 = base64.StdEncoding.EncodeToString(encrypt(f))
			case "raw":
				spec.ContentBase64 = base64.StdEncoding.EncodeToString(f.plain)
			}
			tc.Files = append(tc.Files, spec)
		}
		out = append(out, tc)
	}
	return out, armor, nil
}

// ---- evaluation (shared by generate and --check) --------------------------

type result struct {
	Entries []entry
	Failed  bool
	Error   string
}

func clean(arg string) string { return filepath.Clean(arg) }

func normalizeStore(text, arg string) string {
	root := clean(arg)
	if root == "." {
		return text
	}
	return strings.ReplaceAll(text, root, storeMarker)
}

func normalizeVariant(text string, optional []string) string {
	skip := map[string]bool{}
	for _, l := range optional {
		skip[l] = true
	}
	var kept []string
	for _, l := range strings.Split(text, "\n") {
		if skip[l] {
			continue
		}
		if len(kept) > 0 && kept[len(kept)-1] == l {
			continue
		}
		kept = append(kept, l)
	}
	return strings.Join(kept, "\n")
}

func errorsMatch(recorded, got string, c testCase, recordedVersion, gotVersion string) bool {
	if recordedVersion == gotVersion || !c.VersionVariant {
		return recorded == got
	}
	return normalizeVariant(recorded, c.OptionalStderrLines) == normalizeVariant(got, c.OptionalStderrLines)
}

func materialize(storeDir string, files []fileSpec) (locked []string, err error) {
	if err = os.MkdirAll(storeDir, 0o700); err != nil {
		return nil, err
	}
	for _, f := range files {
		p := filepath.Join(storeDir, filepath.FromSlash(f.Path))
		switch f.Kind {
		case "encrypted", "raw":
			content, derr := base64.StdEncoding.DecodeString(f.ContentBase64)
			if derr != nil {
				return locked, derr
			}
			if err = os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
				return locked, err
			}
			if err = os.WriteFile(p, content, 0o600); err != nil {
				return locked, err
			}
		case "symlink":
			if err = os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
				return locked, err
			}
			if err = os.Symlink(f.Target, p); err != nil {
				return locked, err
			}
		case "dir", "locked_dir":
			if err = os.MkdirAll(p, 0o700); err != nil {
				return locked, err
			}
			if f.Kind == "locked_dir" {
				locked = append(locked, p)
			}
		default:
			return locked, fmt.Errorf("unknown file kind %q", f.Kind)
		}
	}
	return locked, nil
}

// storeArgument returns the argument handed to the importer and the directory
// to chdir into first ("" for none).
func storeArgument(base, form string) (string, string) {
	store := filepath.Join(base, storeDirName)
	switch form {
	case "plain":
		return store, ""
	case "trailing_slash":
		return store + "/", ""
	case "double_slash":
		return base + "//" + storeDirName, ""
	case "dot_segment":
		return base + "/./" + storeDirName, ""
	case "parent_segment":
		return base + "/other/../" + storeDirName, ""
	case "relative":
		return storeDirName, base
	case "relative_dot":
		return "./" + storeDirName, base
	case "cwd_dot":
		return ".", store
	case "symlink_root":
		return filepath.Join(base, "store-link"), ""
	case "symlink_root_slash":
		return filepath.Join(base, "store-link") + "/", ""
	case "symlink_root_gpg":
		return filepath.Join(base, "store-link.gpg"), ""
	case "missing":
		return filepath.Join(base, "no-such-store"), ""
	case "file":
		return filepath.Join(base, "afile"), ""
	}
	must(fmt.Errorf("unknown store form %q", form))
	return "", ""
}

func convert(entries []importer.ImportedEntry) []entry {
	out := make([]entry, 0, len(entries))
	for _, item := range entries {
		out = append(out, entry{Path: item.Path, Data: item.Data, Warnings: item.Warnings})
	}
	return out
}

// jsonRoundTrip makes the recorded entries independent of Go-only types.
func jsonRoundTrip(entries []entry) ([]entry, error) {
	raw, err := json.Marshal(entries)
	if err != nil {
		return nil, err
	}
	var out []entry
	if err = json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	if out == nil {
		out = []entry{}
	}
	return out, nil
}

func runStore(c testCase) (res result, err error) {
	base, err := os.MkdirTemp(os.TempDir(), "pgg-store-")
	if err != nil {
		return res, err
	}
	// The store sits in a realpath-stable directory so printed paths are
	// reproducible within one run (macOS TMPDIR is a symlinked /var).
	if resolved, rerr := filepath.EvalSymlinks(base); rerr == nil {
		base = resolved
	}
	var locked []string
	defer func() {
		for _, p := range locked {
			_ = os.Chmod(p, 0o700)
		}
		_ = os.RemoveAll(base)
	}()
	storeDir := filepath.Join(base, storeDirName)
	switch c.StoreForm {
	case "missing":
	case "file":
		err = os.WriteFile(filepath.Join(base, "afile"), []byte("x"), 0o600)
	default:
		if err = os.MkdirAll(filepath.Join(base, "other"), 0o700); err == nil {
			locked, err = materialize(storeDir, c.Files)
		}
		if err == nil {
			switch c.StoreForm {
			case "symlink_root", "symlink_root_slash":
				err = os.Symlink(storeDirName, filepath.Join(base, "store-link"))
			case "symlink_root_gpg":
				err = os.Symlink(storeDirName, filepath.Join(base, "store-link.gpg"))
			}
		}
	}
	if err != nil {
		return res, err
	}
	for _, p := range locked {
		if err = os.Chmod(p, 0); err != nil {
			return res, err
		}
	}
	arg, chdir := storeArgument(base, c.StoreForm)
	if chdir != "" {
		old, werr := os.Getwd()
		if werr != nil {
			return res, werr
		}
		if err = os.Chdir(chdir); err != nil {
			return res, err
		}
		defer func() {
			if cerr := os.Chdir(old); cerr != nil && err == nil {
				err = cerr
			}
		}()
	}

	var entries []importer.ImportedEntry
	var perr error
	if c.StoreForm == "missing" || c.StoreForm == "file" {
		// The CLI opens the source before parsing; for these the library's own
		// stat/IsDir diagnostics are what is pinned.
		entries, perr = importer.NewPassImporter(arg).Parse(nil)
	} else {
		parser, nerr := importer.New(importer.FormatPass)
		if nerr != nil {
			return res, nerr
		}
		// The CLI opens the source and hands the *os.File over; Parse reads the
		// directory from file.Name(), i.e. the argument verbatim. An unreadable
		// root cannot be opened, so it takes the equivalent direct path.
		if f, oerr := os.Open(arg); oerr == nil { // #nosec G304 -- disposable test store
			defer func() { _ = f.Close() }()
			entries, perr = parser.Parse(f)
		} else {
			entries, perr = importer.NewPassImporter(arg).Parse(nil)
		}
	}
	if perr != nil {
		return result{Entries: []entry{}, Failed: true, Error: normalizeStore(perr.Error(), arg)}, nil
	}
	rt, err := jsonRoundTrip(convert(entries))
	if err != nil {
		return res, err
	}
	return result{Entries: rt}, nil
}

type session struct {
	env   *gpgEnv
	home  string
	saved map[string]*string
}

func openSession(env *gpgEnv, armor string) (*session, error) {
	home, err := env.newHome("d")
	if err != nil {
		return nil, err
	}
	mustGPG(home, []byte(armor), "--batch", "--import")
	s := &session{env: env, home: home, saved: map[string]*string{}}
	cleanups = append(cleanups, func() { killAgent(home) })
	for _, kv := range [][2]string{{"GNUPGHOME", home}, {"LC_ALL", "C"}, {"HOME", home}} {
		if old, ok := os.LookupEnv(kv[0]); ok {
			v := old
			s.saved[kv[0]] = &v
		} else {
			s.saved[kv[0]] = nil
		}
		must(os.Setenv(kv[0], kv[1]))
	}
	return s, nil
}

func (s *session) close() {
	for k, v := range s.saved {
		if v == nil {
			_ = os.Unsetenv(k)
		} else {
			_ = os.Setenv(k, *v)
		}
	}
	killAgent(s.home)
}

// verifyPlaintexts decrypts every stored ciphertext that the keyring is meant
// to read and compares the bytes with the recorded plaintext.
func (s *session) verifyPlaintexts(c testCase) error {
	for _, f := range c.Files {
		if f.Kind != "encrypted" || !f.Decrypts {
			continue
		}
		ct, err := base64.StdEncoding.DecodeString(f.ContentBase64)
		if err != nil {
			return err
		}
		want, err := base64.StdEncoding.DecodeString(f.PlaintextBase64)
		if err != nil {
			return err
		}
		got, stderr, err := gpg(s.home, ct, "--decrypt", "--batch", "--yes")
		if err != nil {
			return fmt.Errorf("%s/%s: gpg decrypt: %w: %s", c.ID, f.Path, err, stderr)
		}
		if !bytes.Equal(got, want) {
			return fmt.Errorf("%s/%s: decrypted bytes differ from recorded plaintext", c.ID, f.Path)
		}
	}
	return nil
}

func evaluate(env *gpgEnv, armor string, cases []testCase) ([]result, error) {
	s, err := openSession(env, armor)
	if err != nil {
		return nil, err
	}
	defer s.close()
	out := make([]result, 0, len(cases))
	for _, c := range cases {
		if err = s.verifyPlaintexts(c); err != nil {
			return nil, err
		}
		r, rerr := runStore(c)
		if rerr != nil {
			return nil, fmt.Errorf("%s: %w", c.ID, rerr)
		}
		out = append(out, r)
	}
	return out, nil
}

// ---- main -----------------------------------------------------------------

func sourceList() []string {
	return []string{
		"internal/crypto/totp.go",
		"internal/importer/importer.go",
		"internal/importer/pass.go",
		"internal/importer/totp.go",
		"internal/secrets/filter.go",
	}
}

func repoRoot() string {
	out, err := exec.Command("git", "rev-parse", "--show-toplevel").Output()
	must(err)
	return strings.TrimSpace(string(out))
}

func main() {
	check := flag.Bool("check", false, "re-verify the stored fixture (decrypts stored ciphertexts; never re-encrypts)")
	output := flag.String("output", defaultOutput, "fixture path")
	flag.Parse()
	root := repoRoot()
	sources := sourceList()
	_, err := provenance.Verify(root, pinnedOracleCommit, sources)
	must(err)
	sourceDigest, err := provenance.Digest(root, sources)
	must(err)
	generatorDigest, err := provenance.Digest(root, []string{"scripts/rust-port/cmd/passgpggen/main.go"})
	must(err)
	version, err := gpgVersion()
	must(err)
	env, err := newGPGEnv()
	must(err)
	cleanups = append(cleanups, env.close)

	if *check {
		must(runCheck(env, *output, version, sourceDigest, generatorDigest))
	} else {
		must(runGenerate(env, *output, version, sourceDigest, generatorDigest))
	}
	runCleanups()
}

func runGenerate(env *gpgEnv, output, version, sourceDigest, generatorDigest string) error {
	cases, armor, err := encryptAll(env, corpus())
	if err != nil {
		return err
	}
	first, err := evaluate(env, armor, cases)
	if err != nil {
		return err
	}
	second, err := evaluate(env, armor, cases)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(first, second) {
		return errors.New("pass importer is not deterministic across two evaluations")
	}
	failures := 0
	for i := range cases {
		cases[i].Expected = first[i].Entries
		cases[i].Failed = first[i].Failed
		cases[i].Error = first[i].Error
		if first[i].Failed {
			failures++
		}
	}
	fpr := armorFingerprint(env, armor)
	fix := fixture{
		SchemaVersion: 1,
		Oracle: oracle{
			Commit: pinnedOracleCommit, Sources: sourceList(), SourceDigest: sourceDigest,
			GeneratorDigest: generatorDigest, GoVersion: runtime.Version(), GOOS: runtime.GOOS,
			GPGVersion: version, GPGArgs: gpgArgs,
		},
		Keyring: keyring{
			Fingerprint: fpr, SecretKeyArmor: armor, AgentConf: agentConf,
			Note: "test-only key pair generated in a disposable GNUPGHOME with an empty passphrase; it protects nothing",
		},
		Normalization: documentedNormalization(),
		Cases:         cases,
	}
	content, err := json.MarshalIndent(fix, "", "  ")
	if err != nil {
		return err
	}
	content = append(content, '\n')
	if err = os.WriteFile(output, content, 0o600); err != nil { // #nosec G306 -- fixture file
		return err
	}
	fmt.Printf("PASS pass/gpg oracle generated (%d cases, %d failing stores, %s)\n", len(cases), failures, version)
	return nil
}

func armorFingerprint(env *gpgEnv, armor string) string {
	home, err := env.newHome("i")
	must(err)
	out := mustGPG(home, []byte(armor), "--batch", "--import-options", "show-only", "--import", "--with-colons")
	for _, line := range strings.Split(string(out), "\n") {
		if f := strings.Split(line, ":"); f[0] == "fpr" {
			return f[9]
		}
	}
	must(errors.New("no fingerprint in armored key"))
	return ""
}

func runCheck(env *gpgEnv, path, version, sourceDigest, generatorDigest string) error {
	content, err := os.ReadFile(path) // #nosec G304 -- fixture path flag
	if err != nil {
		return err
	}
	var fix fixture
	if err = json.Unmarshal(content, &fix); err != nil {
		return err
	}
	var problems []string
	if fix.Oracle.Commit != pinnedOracleCommit {
		problems = append(problems, "oracle commit differs from the pinned commit")
	}
	if !reflect.DeepEqual(fix.Oracle.Sources, sourceList()) {
		problems = append(problems, "oracle source list differs")
	}
	if fix.Oracle.SourceDigest != sourceDigest {
		problems = append(problems, "source digest differs: production sources changed")
	}
	if fix.Oracle.GeneratorDigest != generatorDigest {
		problems = append(problems, "generator digest differs: regenerate deliberately")
	}
	if !reflect.DeepEqual(fix.Normalization, documentedNormalization()) {
		problems = append(problems, "normalization documentation differs")
	}
	if fix.Keyring.AgentConf != agentConf {
		problems = append(problems, "agent_conf differs")
	}
	if got := armorFingerprint(env, fix.Keyring.SecretKeyArmor); got != fix.Keyring.Fingerprint {
		problems = append(problems, "recorded fingerprint does not match the armored key")
	}
	results, err := evaluate(env, fix.Keyring.SecretKeyArmor, fix.Cases)
	if err != nil {
		return err
	}
	for i, c := range fix.Cases {
		r := results[i]
		if r.Failed != c.Failed {
			problems = append(problems, fmt.Sprintf("%s: failed=%v, recorded %v", c.ID, r.Failed, c.Failed))
			continue
		}
		if c.Failed {
			if !errorsMatch(c.Error, r.Error, c, fix.Oracle.GPGVersion, version) {
				problems = append(problems, fmt.Sprintf("%s: error differs\n  recorded: %q\n  now:      %q", c.ID, c.Error, r.Error))
			}
			continue
		}
		want, werr := json.Marshal(c.Expected)
		got, gerr := json.Marshal(r.Entries)
		if err = errors.Join(werr, gerr); err != nil {
			return fmt.Errorf("%s: marshal entries: %w", c.ID, err)
		}
		if !bytes.Equal(want, got) {
			problems = append(problems, fmt.Sprintf("%s: entries differ\n  recorded: %s\n  now:      %s", c.ID, want, got))
		}
	}
	// The recorded corpus must match the generator's case list (ids and file
	// layout), so a silently shortened fixture cannot pass.
	expectedIDs := []string{}
	for _, g := range corpus() {
		expectedIDs = append(expectedIDs, g.id)
	}
	gotIDs := []string{}
	for _, c := range fix.Cases {
		gotIDs = append(gotIDs, c.ID)
	}
	if !reflect.DeepEqual(expectedIDs, gotIDs) {
		sort.Strings(expectedIDs)
		sort.Strings(gotIDs)
		problems = append(problems, fmt.Sprintf("case ids differ from the generator corpus: want %v got %v", expectedIDs, gotIDs))
	}
	if len(problems) > 0 {
		return fmt.Errorf("pass/gpg fixture check failed (recorded on %s with %q, verified on %s with %q):\n%s",
			fix.Oracle.GOOS, fix.Oracle.GPGVersion, runtime.GOOS, version, strings.Join(problems, "\n"))
	}
	fmt.Printf("PASS pass/gpg fixture (%d cases; recorded on %s with %q, verified on %s with %q)\n",
		len(fix.Cases), fix.Oracle.GOOS, fix.Oracle.GPGVersion, runtime.GOOS, version)
	return nil
}

// cleanups run before every exit, so a failing run never leaves a gpg-agent
// behind (os.Exit skips deferred calls).
var cleanups []func()

func must(err error) {
	if err != nil {
		runCleanups()
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func runCleanups() {
	for len(cleanups) > 0 {
		last := cleanups[len(cleanups)-1]
		cleanups = cleanups[:len(cleanups)-1]
		last()
	}
}
