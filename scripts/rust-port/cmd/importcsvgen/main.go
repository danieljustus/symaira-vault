// Command importcsvgen freezes production CSV import and path behavior.
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/danieljustus/symaira-vault/internal/importer"
	"github.com/danieljustus/symaira-vault/scripts/rust-port/internal/provenance"
)

const pinnedOracleCommit = "fca3f89401833b5e14ec4ec74ef736b0f63bca74"

type entry struct {
	Path     string         `json:"path"`
	Data     map[string]any `json:"data"`
	Warnings []string       `json:"warnings"`
}
type csvCase struct {
	Name    string          `json:"name"`
	Format  importer.Format `json:"format"`
	Input   string          `json:"input"`
	Entries []entry         `json:"entries"`
	Failed  bool            `json:"failed"`
}

type totpCase struct {
	Input string         `json:"input"`
	Value map[string]any `json:"value"`
	Error string         `json:"error"`
}

func main() {
	check := flag.Bool("check", false, "check fixture freshness")
	flag.Parse()
	rootBytes, err := exec.Command("git", "rev-parse", "--show-toplevel").Output()
	must(err)
	root := strings.TrimSpace(string(rootBytes))
	sources := []string{"internal/crypto/totp.go", "internal/importer/csv.go", "internal/importer/csv_profiles.go", "internal/importer/importer.go", "internal/importer/totp.go"}
	_, err = provenance.Verify(root, pinnedOracleCommit, sources)
	must(err)
	digest, err := provenance.Digest(root, sources)
	must(err)
	generatorDigest, err := provenance.Digest(root, []string{"scripts/rust-port/cmd/importcsvgen/main.go"})
	must(err)
	cases := []csvCase{
		{Name: "csv_invalid_totp", Format: "csv", Input: "title,password,otp\nA,p,bad\n"},
		{Name: "apple_totp", Format: "apple", Input: "Title,Password,OTPAuth\nA,p,otpauth://totp/x?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP&algorithm=sha256&digits=8&period=45\n"},
		{Name: "empty", Format: "csv", Input: ""},
		{Name: "empty_fields", Format: "csv", Input: "title,username,password,url,notes\nA,,p,,\n"},
		{Name: "no_title_no_invented_path", Format: "csv", Input: "url,password\nhttps://example.test,p\n"},
		{Name: "duplicate_header_last", Format: "csv", Input: "title,password,password\nA,old,new\n"},
		{Name: "short_row", Format: "csv", Input: "title,password,url\nA,p\n"},
		{Name: "blank_rows", Format: "csv", Input: "title,password\n , \nA,p\n"},
		{Name: "embedded_newline", Format: "csv", Input: "title,password\nA,\"line1\nline2\"\n"},
		{Name: "escaped_quote", Format: "csv", Input: "title,password\nA,\"a\"\"b\"\n"},
		{Name: "bare_quote", Format: "csv", Input: "title,password\nA,a\"b\n"},
		{Name: "closed_quote_suffix", Format: "csv", Input: "title,password\nA,\"a\"b\n"},
		{Name: "bare_cr", Format: "csv", Input: "title,password\nA,a\rb\n"},
		{Name: "trailing_cr", Format: "csv", Input: "title,password\nA,p\r"},
		{Name: "crlf", Format: "csv", Input: "title,password\r\nA,\"a\r\nb\"\r\n"},
		{Name: "malformed", Format: "csv", Input: "title,password\nA,\"unterminated"},
		{Name: "chrome_hosts_collisions", Format: "chrome", Input: "name,url,username,password,note\n,https://USER:PASS@EXAMPLE.test:8080/a,u,p,n\n,https://example.test/b,u2,p2,\nexample.test-2,https://other.test,u3,p3,\n"},
		{Name: "firefox_ipv6", Format: "firefox", Input: "url,username,password,httpRealm\nhttps://[::1]:8000/a,u,p,\n"},
		{Name: "apple_empty_title", Format: "apple", Input: "Title,URL,Username,Password,Notes,OTPAuth\n,https://example.test,u,p,,\n"},
		{Name: "profile_case_headers", Format: "chrome", Input: " NAME ,URL,UserName,PASSWORD,NOTE\nTitle,https://example.test,u,p,n\n"},
	}
	for i := range cases {
		parser, err := importer.New(cases[i].Format)
		must(err)
		entries, err := parser.Parse(strings.NewReader(cases[i].Input))
		cases[i].Failed = err != nil
		cases[i].Entries = []entry{}
		for _, e := range entries {
			cases[i].Entries = append(cases[i].Entries, entry{e.Path, e.Data, e.Warnings})
		}
	}
	secret := "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"
	totps := []totpCase{}
	inputs := []string{"", "bad", "JBSWY3DPEHPK3PXP", secret, "  " + strings.ToLower(secret) + "  ",
		"otpauth://totp/Example?secret=" + secret,
		"otpauth://totp/Example?secret=" + secret + "&algorithm=sha512&digits=8&period=45",
		"otpauth://hotp/Example?secret=" + secret, "otpauth:///Example?secret=" + secret,
		"otpauth://totp/Example", "otpauth://totp/x?secret=%ZZ", "otpauth://totp/x?secret=" + secret + ";bad=x",
		"otpauth://totp/x?secret=&secret=" + secret, "OTPAUTH://TOTP/x?secret=" + secret,
		"otpauth://totp/x?secret=" + secret + "&algorithm=MD5",
		"otpauth://totp/x?secret=" + secret + "&digits=7", "otpauth://totp/x?secret=" + secret + "&digits=no",
		"otpauth://totp/x?secret=" + secret + "&period=0", "otpauth://totp/x?secret=" + secret + "&period=3601",
		"otpauth://totp/x?secret=" + secret + "&period=9223372036854775808",
	}
	for _, input := range inputs {
		v, err := importer.ParseTOTP(input)
		message := ""
		if err != nil {
			message = err.Error()
		}
		totps = append(totps, totpCase{input, v, message})
	}
	paths := []string{" .... ", "////a///", "../a..b", " a b ", "a:b\\c", "......"}
	normalized := map[string]string{}
	for _, p := range paths {
		normalized[p] = importer.NormalizePath(p)
	}
	prefixes := [][2]string{{" / x y / ", "a:b"}, {"", "../a"}, {"p", ""}}
	prefixResults := []string{}
	for _, p := range prefixes {
		prefixResults = append(prefixResults, importer.ApplyPrefix(p[0], p[1]))
	}
	fixture := struct {
		Commit          string            `json:"commit"`
		Sources         []string          `json:"sources"`
		SourceDigest    string            `json:"source_digest"`
		GeneratorDigest string            `json:"generator_digest"`
		Cases           []csvCase         `json:"cases"`
		Paths           map[string]string `json:"paths"`
		Prefixes        [][2]string       `json:"prefixes"`
		PrefixResults   []string          `json:"prefix_results"`
		Totps           []totpCase        `json:"totps"`
	}{pinnedOracleCommit, sources, digest, generatorDigest, cases, normalized, prefixes, prefixResults, totps}
	content, err := json.MarshalIndent(fixture, "", "  ")
	must(err)
	content = append(content, '\n')
	path := "testdata/port/sync/csv.json"
	if *check {
		old, err := os.ReadFile(path)
		must(err)
		if !bytes.Equal(old, content) {
			must(fmt.Errorf("CSV fixture stale"))
		}
	} else {
		must(os.WriteFile(path, content, 0600))
	}
	fmt.Printf("PASS CSV oracle (%d cases)\n", len(cases))
}
func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
