package main

import (
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/danieljustus/symaira-vault/pkg/mobilebind"
)

// Public test keys that already appear in the repository's crypto tests. They
// are fixture inputs; nothing about them is a secret.
const (
	id1 = "AGE-SECRET-KEY-1HS3YTK69EJH0ZYM8ANNNDWQMPT7ZMLPYGTMC47F5T4EDJ5N7EYMQ4L5CDL"
	id2 = "AGE-SECRET-KEY-18HD87KNMWKY3RW97YR2PYU6HGWDZXAGW6JF74LNNHUA6A8K5ZF9QTWUTK3"

	vaultPass = "correct horse battery staple"
	x25519Hdr = "age-encryption.org/v1\n-> X25519 "
	scryptHdr = "age-encryption.org/v1\n-> scrypt "
)

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

// seedData is the random material the oracle produced once. It is stored in the
// fixture and fed back verbatim by --check, so a re-run is deterministic.
type seedData struct {
	X25519 map[string]string `json:"x25519_ciphertexts_b64"`
	Scrypt map[string]string `json:"scrypt_ciphertexts_b64"`
	Vault  seedVault         `json:"vault"`
}

type seedVault struct {
	Passphrase string      `json:"passphrase"`
	Identity   string      `json:"identity"`
	Recipient  string      `json:"recipient"`
	Files      []vaultFile `json:"files"`
	Entries    []string    `json:"entries"`
}

// seedEntries are written through the real WriteEntryJSON while seeding.
var seedEntries = []struct{ Path, JSON string }{
	{"work/github", `{"data":{"username":"octo","token":"s3cr3t-<>&"},"meta":{"tags":["code","work"]}}`},
	{"work/aws", `{"data":{"access_key":"AKIAEXAMPLE","region":"eu-central-1","port":8443,"ratio":1.5}}`},
	{"personal/email", `{"data":{"user":"me@example.org","password":"pässwörd ✓","nested":{"a":[1,"two",null,true]}}}`},
	{"notes/é-ü", `{"data":{"text":"unicode path"}}`},
	{"top", `{"data":{"k":"v"}}`},
}

func makeSeed(tmp string) (seedData, error) {
	var s seedData
	s.X25519, s.Scrypt = map[string]string{}, map[string]string{}
	rec1, err := mobilebind.IdentityPublicKey(id1)
	if err != nil {
		return s, err
	}
	for name, pt := range map[string][]byte{
		"hello":  []byte("hello, symvault\n"),
		"binary": allBytes(),
		"chunk+": pattern(65537),
	} {
		ct, err := mobilebind.EncryptWithPublicKey(rec1, pt)
		if err != nil {
			return s, err
		}
		s.X25519[name] = b64(ct)
	}
	ct, err := mobilebind.EncryptWithPassphrase(vaultPass, []byte("hello, symvault\n"))
	if err != nil {
		return s, err
	}
	s.Scrypt["hello"] = b64(ct)

	dir := filepath.Join(tmp, "vault")
	if err := mobilebind.InitVault(dir, vaultPass); err != nil {
		return s, err
	}
	id, err := mobilebind.OpenVaultWithPassphrase(dir, vaultPass)
	if err != nil {
		return s, err
	}
	for _, e := range seedEntries {
		if err := mobilebind.WriteEntryJSON(dir, e.Path, e.JSON, id); err != nil {
			return s, err
		}
		s.Vault.Entries = append(s.Vault.Entries, e.Path)
	}
	rec, err := mobilebind.IdentityPublicKey(id)
	if err != nil {
		return s, err
	}
	s.Vault.Passphrase, s.Vault.Identity, s.Vault.Recipient = vaultPass, id, rec
	// A pre-"entries/" top-level entry: random ciphertext, so it lives in the seed.
	legacy, err := mobilebind.EncryptWithPublicKey(rec, []byte(`{"data":{"legacy":"yes"},"meta":{"created":"2020-01-02T03:04:05Z","updated":"2020-01-02T03:04:05Z","version":1},"secret_meta":{}}`))
	if err != nil {
		return s, err
	}
	s.X25519["legacy-entry"] = b64(legacy)
	// Snapshot the durable files only; lock and cache files are implementation detail.
	err = filepath.WalkDir(dir, func(p string, d os.DirEntry, werr error) error {
		if werr != nil {
			return werr
		}
		rel, _ := filepath.Rel(dir, p)
		if rel == "." || rel == ".lock" || rel == ".search-index" || rel == ".symvault-migrated" {
			return nil
		}
		info, _ := d.Info()
		f := vaultFile{Path: filepath.ToSlash(rel), Mode: uint32(info.Mode().Perm())}
		if d.IsDir() {
			f.Dir = true
		} else {
			data, rerr := os.ReadFile(p)
			if rerr != nil {
				return rerr
			}
			// Machine-bound: Go records the creation directory in config.yaml.
			data = []byte(strings.ReplaceAll(string(data), dir, "$ROOT/vault"))
			f.B64 = b64(data)
		}
		s.Vault.Files = append(s.Vault.Files, f)
		return nil
	})
	sort.Slice(s.Vault.Files, func(i, j int) bool { return s.Vault.Files[i].Path < s.Vault.Files[j].Path })
	if err != nil {
		return s, err
	}
	return s, addDerivedSeed(&s)
}

// storedMinusZero is an entry document as a Go-written vault can hold it: Go
// marshals a float64 -0 as the integer literal "-0" and reads it back as -0.
const storedMinusZero = `{"data":{"neg":-0,"negfloat":-0.0,"zero":0,"mixed":[-0,0.5]},"meta":{"created":"2020-01-02T03:04:05Z","updated":"2020-01-02T03:04:05Z","version":1},"secret_meta":{}}`

// addDerivedSeed adds seed ciphertexts that are encrypted to the seed vault's
// recipient. It only creates what is missing, so --keep-seed leaves every
// existing byte of the seed alone.
func addDerivedSeed(s *seedData) error {
	if _, ok := s.X25519["stored-minus-zero"]; ok {
		return nil
	}
	ct, err := mobilebind.EncryptWithPublicKey(s.Vault.Recipient, []byte(storedMinusZero))
	if err != nil {
		return err
	}
	s.X25519["stored-minus-zero"] = b64(ct)
	return nil
}

// seedFileB64 returns the bytes of a file of the frozen seed vault.
func seedFileB64(sd seedData, path string) string {
	for _, f := range sd.Vault.Files {
		if f.Path == path {
			return f.B64
		}
	}
	panic("seed vault has no file " + path)
}

func allBytes() []byte {
	out := make([]byte, 256)
	for i := range out {
		out[i] = byte(i)
	}
	return out
}

// caseSpec is one scenario: optional seed vault, mutations, then ordered calls.
type caseSpec struct {
	ID        string     `json:"id"`
	Group     string     `json:"group"`
	Vault     bool       `json:"vault,omitempty"`
	Mutations []mutation `json:"mutations,omitempty"`
	Steps     []stepSpec `json:"steps"`
	After     *afterSpec `json:"after,omitempty"`

	// Generation-only requests; the recorded result is After.
	afterPaths []string
	afterTree  bool
	afterText  map[string]bool
	// randomized[i] marks step i as a shape-verified step.
	randomized map[int]*shape
}

func args(a callArgs) callArgs { return a }

func fixed(fn string, a callArgs, normalize ...string) stepSpec {
	return stepSpec{Function: fn, Args: a, Normalize: normalize}
}

var vaultArg = "$ROOT/vault"

// flipAt returns s with the byte at i replaced by a different bech32 character.
func flipAt(s string, i int) string {
	b := []byte(s)
	if b[i] == 'Q' {
		b[i] = 'P'
	} else {
		b[i] = 'Q'
	}
	return string(b)
}

// identityMutations are malformed identity strings derived from a valid key.
func identityMutations(valid string) []struct{ Name, Value string } {
	out := []struct{ Name, Value string }{
		{"empty", ""}, {"spaces", "   "}, {"tabs-newlines", "\t\n\r "},
		{"prefix-only", "AGE-SECRET-KEY-"}, {"prefix-and-1", "AGE-SECRET-KEY-1"},
		{"lowercase", strings.ToLower(valid)}, {"mixed-case", "AGE-SECRET-KEY-1" + strings.ToLower(valid[16:20]) + valid[20:]},
		{"wrong-prefix", "AGE-SECRET-KEZ-" + valid[15:]}, {"plugin-prefix", "AGE-PLUGIN-FOO-1QQQQ"},
		{"recipient-as-identity", "age1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq"},
		{"trailing-char", valid + "Q"}, {"nul", valid[:30] + "\x00" + valid[31:]},
		{"invalid-char-b", valid[:40] + "B" + valid[41:]}, {"invalid-char-1", valid[:40] + "1" + valid[41:]},
		{"inner-space", valid[:30] + " " + valid[30:]}, {"long", "AGE-SECRET-KEY-" + strings.Repeat("Q", 4000)},
		{"hrp-only-sep", "AGE-SECRET-KEY-1" + strings.Repeat("Q", 5)},
		{"unicode", "AGE-SECRET-KEY-1ÄÖÜ"},
	}
	for _, i := range []int{16, 17, 30, 50, 73} {
		out = append(out, struct{ Name, Value string }{fmt.Sprintf("flip-%d", i), flipAt(valid, i)})
	}
	for _, n := range []int{17, 20, 40, 60, 73} {
		out = append(out, struct{ Name, Value string }{fmt.Sprintf("truncate-%d", n), valid[:n]})
	}
	return out
}

func recipientMutations(valid string) []struct{ Name, Value string } {
	lower := func(s string) string { return strings.ToLower(s) }
	out := []struct{ Name, Value string }{
		{"empty", ""}, {"spaces", "  \t "}, {"prefix-only", "age1"}, {"ssh", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExample"},
		{"identity-as-recipient", id1}, {"uppercase", strings.ToUpper(valid)},
		{"mixed-case", valid[:10] + strings.ToUpper(valid[10:14]) + valid[14:]},
		{"wrong-prefix", "agf" + valid[3:]}, {"trailing-char", valid + "q"}, {"nul", valid[:20] + "\x00" + valid[21:]},
		{"invalid-char-b", valid[:30] + "b" + valid[31:]}, {"inner-space", valid[:30] + " " + valid[30:]},
		{"long", "age1" + strings.Repeat("q", 4000)}, {"unicode", "age1äöü"},
		{"plugin", "age1tag1qqqqqqqqqqqqqqq"}, {"wrong-hrp", "bech1" + valid[4:]},
	}
	for _, i := range []int{5, 20, 40, 61} {
		b := []byte(lower(valid))
		if b[i] == 'q' {
			b[i] = 'p'
		} else {
			b[i] = 'q'
		}
		out = append(out, struct{ Name, Value string }{fmt.Sprintf("flip-%d", i), string(b)})
	}
	for _, n := range []int{5, 10, 30, 61} {
		out = append(out, struct{ Name, Value string }{fmt.Sprintf("truncate-%d", n), valid[:n]})
	}
	return out
}

// ciphertextMutations derives malformed age envelopes from a valid one.
func ciphertextMutations(ct []byte) []struct {
	Name string
	Data []byte
} {
	type m = struct {
		Name string
		Data []byte
	}
	text := string(ct)
	firstNL := strings.Index(text, "\n")
	secondNL := firstNL + 1 + strings.Index(text[firstNL+1:], "\n")
	thirdNL := secondNL + 1 + strings.Index(text[secondNL+1:], "\n")
	footer := strings.Index(text, "\n--- ") + 1
	footerEnd := footer + strings.Index(text[footer:], "\n") + 1
	out := []m{
		{"junk", []byte("junk")}, {"one-byte", []byte{0}}, {"newline", []byte("\n")},
		{"intro-only", []byte(text[:firstNL+1])}, {"intro-no-newline", []byte(text[:firstNL])},
		{"bad-version", []byte("age-encryption.org/v2" + text[firstNL:])},
		{"intro-long-garbage", []byte(strings.Repeat("x", 300) + "\n")},
		{"secret-key-as-ciphertext", []byte(id1 + "\n")},
		{"plugin-key-as-ciphertext", []byte("AGE-PLUGIN-FOO-1QQ\n")},
		{"binary-garbage", append([]byte{0xff, 0xfe, 0x00, 0x01}, []byte("\n\n")...)},
		{"trunc-after-stanza-line", []byte(text[:secondNL+1])},
		{"trunc-mid-stanza-line", []byte(text[:firstNL+10])},
		{"trunc-after-body", []byte(text[:thirdNL+1])},
		{"trunc-mid-footer", []byte(text[:footer+10])},
		{"trunc-footer-before-newline", []byte(text[:footerEnd-1])},
		{"trunc-no-nonce", []byte(text[:footerEnd])},
		{"trunc-mid-nonce", []byte(text[:footerEnd+7])},
		{"trunc-nonce-only", []byte(text[:footerEnd+16])},
		{"trunc-one-payload-byte", ct[:footerEnd+17]},
		{"drop-last-byte", ct[:len(ct)-1]},
		{"drop-last-17-bytes", ct[:len(ct)-17]},
		{"append-byte", append(append([]byte{}, ct...), 0x00)},
		{"stanza-no-prefix", []byte(text[:firstNL+1] + "XX" + text[firstNL+3:])},
		{"stanza-too-few-args", []byte(text[:firstNL+1] + "->\n" + text[thirdNL+1:])},
		{"footer-bad-prefix", []byte(text[:footer] + "-- " + text[footer+4:])},
		{"footer-short-mac", []byte(text[:footerEnd-6] + "\n" + text[footerEnd:])},
		{"footer-bad-base64", []byte(text[:footerEnd-3] + "*\n" + text[footerEnd:])},
		{"no-stanzas", []byte(text[:firstNL+1] + text[footer:])},
		{"stanza-body-bad-base64", []byte(text[:secondNL+1] + "!!!!\n" + text[thirdNL+1:])},
	}
	flip := func(name string, off int) {
		b := append([]byte{}, ct...)
		b[off] ^= 0x01
		out = append(out, m{name, b})
	}
	flip("flip-stanza-arg", firstNL+14)
	flip("flip-stanza-body", secondNL+3)
	flip("flip-footer-mac", footerEnd-3)
	flip("flip-nonce", footerEnd+2)
	flip("flip-payload-first", footerEnd+16)
	flip("flip-payload-last", len(ct)-1)
	return out
}

// buildCases returns the complete, deterministic case list for a seed.
func buildCases(sd seedData) []caseSpec {
	var cs []caseSpec
	add := func(c caseSpec) { cs = append(cs, c) }
	rec1, _ := mobilebind.IdentityPublicKey(id1)
	rec2, _ := mobilebind.IdentityPublicKey(id2)
	single := func(id, group string, st stepSpec) caseSpec {
		return caseSpec{ID: group + "/" + id, Group: group, Steps: []stepSpec{st}}
	}
	vsingle := func(id, group string, st stepSpec, muts ...mutation) caseSpec {
		return caseSpec{ID: group + "/" + id, Group: group, Vault: true, Mutations: muts, Steps: []stepSpec{st}}
	}
	vid, vpass := sd.Vault.Identity, sd.Vault.Passphrase

	// ---- GenerateIdentity -------------------------------------------------
	{
		c := single("shape", "GenerateIdentity", fixed("GenerateIdentity", args(callArgs{})))
		c.randomized = map[int]*shape{0: {StringPrefix: "AGE-SECRET-KEY-1", StringCharset: "bech32-upper", Length: 74,
			Distinct: true,
			Roundtrip: &stepSpec{Function: "IdentityPublicKey", Args: callArgs{Identity: outToken},
				Want: want{OK: true, Shape: &shape{StringPrefix: "age1", StringCharset: "bech32-lower", Length: 62}}}}}
		add(c)
	}

	// ---- IdentityPublicKey ------------------------------------------------
	for _, v := range []struct{ n, id string }{
		{"valid-1", id1}, {"valid-2", id2},
		{"trim-ascii", " \t\r\n" + id1 + "\n\r\t "}, {"trim-unicode", "\u00a0\u2003" + id1 + "\u3000\u0085"},
		{"trim-vt-ff", "\v\f" + id1 + "\f\v"},
	} {
		add(single(v.n, "IdentityPublicKey", fixed("IdentityPublicKey", args(callArgs{Identity: v.id}))))
	}
	for _, m := range identityMutations(id1) {
		add(single("bad-"+m.Name, "IdentityPublicKey", fixed("IdentityPublicKey", args(callArgs{Identity: m.Value}))))
	}

	// ---- PublicKeyFingerprint ---------------------------------------------
	for _, v := range []struct{ n, k string }{
		{"recipient-1", rec1}, {"recipient-2", rec2}, {"trim", "  \t" + rec1 + "\n"}, {"empty", ""}, {"spaces", "   "},
		{"not-a-key", "not a key"}, {"unicode", "ключ-🔑"}, {"identity-string", id1}, {"long", strings.Repeat("age1", 1000)},
		{"nbsp-not-trimmed-asciionly", "\u00a0" + rec1}, {"inner-newline", rec1 + "\n" + rec1},
	} {
		add(single(v.n, "PublicKeyFingerprint", fixed("PublicKeyFingerprint", args(callArgs{Pubkey: v.k}))))
	}

	// ---- EncryptWithPublicKey ---------------------------------------------
	encCase := func(name string, recipient string, pt []byte, rtID string, hdrLenFrom []byte) {
		a := callArgs{Recipient: recipient, PlaintextB64: b64(pt)}
		if len(pt) > 4096 {
			a = callArgs{Recipient: recipient, PlaintextPattern: len(pt)}
		}
		c := single(name, "EncryptWithPublicKey", fixed("EncryptWithPublicKey", args(a)))
		ct, err := mobilebind.EncryptWithPublicKey(recipient, pt)
		if err != nil {
			panic(err)
		}
		c.randomized = map[int]*shape{0: {BytesPrefixB64: b64([]byte(x25519Hdr)), Length: len(ct), Distinct: true,
			Roundtrip: &stepSpec{Function: "DecryptWithIdentity", Args: callArgs{Identity: rtID, CiphertextB64: outToken},
				Want: wantBytes(pt)}}}
		add(c)
	}
	encCase("short", rec1, []byte("hello, symvault\n"), id1, nil)
	encCase("one-byte", rec1, []byte{0x00}, id1, nil)
	encCase("binary-256", rec1, allBytes(), id1, nil)
	encCase("whitespace-recipient", " \t"+rec1+"\n", []byte("trimmed"), id1, nil)
	encCase("unicode-text", rec2, []byte("pässwörd ✓ 🔑"), id2, nil)
	encCase("exact-chunk-65536", rec1, pattern(65536), id1, nil)
	encCase("chunk-plus-one-65537", rec1, pattern(65537), id1, nil)
	encCase("two-chunks-131072", rec1, pattern(131072), id1, nil)
	for _, m := range recipientMutations(rec1) {
		add(single("bad-recipient-"+m.Name, "EncryptWithPublicKey",
			fixed("EncryptWithPublicKey", args(callArgs{Recipient: m.Value, PlaintextB64: b64([]byte("x"))}))))
	}
	add(single("empty-plaintext", "EncryptWithPublicKey", fixed("EncryptWithPublicKey", args(callArgs{Recipient: rec1}))))
	add(single("empty-plaintext-bad-recipient", "EncryptWithPublicKey", fixed("EncryptWithPublicKey", args(callArgs{Recipient: "nope"}))))

	// ---- DecryptWithIdentity ----------------------------------------------
	helloCT := decodeB64(sd.X25519["hello"])
	for _, name := range []string{"hello", "binary", "chunk+"} {
		add(single("go-ciphertext-"+name, "DecryptWithIdentity",
			fixed("DecryptWithIdentity", args(callArgs{Identity: id1, CiphertextRef: "x25519:" + name}))))
	}
	add(single("trim-identity", "DecryptWithIdentity", fixed("DecryptWithIdentity",
		args(callArgs{Identity: "\n " + id1 + " \t", CiphertextB64: sd.X25519["hello"]}))))
	add(single("wrong-identity", "DecryptWithIdentity", fixed("DecryptWithIdentity", args(callArgs{Identity: id2, CiphertextB64: sd.X25519["hello"]}))))
	add(single("empty-ciphertext", "DecryptWithIdentity", fixed("DecryptWithIdentity", args(callArgs{Identity: id1}))))
	add(single("empty-ciphertext-bad-identity", "DecryptWithIdentity", fixed("DecryptWithIdentity", args(callArgs{Identity: "x"}))))
	add(single("passphrase-ciphertext", "DecryptWithIdentity", fixed("DecryptWithIdentity",
		args(callArgs{Identity: id1, CiphertextB64: sd.Scrypt["hello"]}))))
	for _, m := range identityMutations(id1) {
		add(single("bad-identity-"+m.Name, "DecryptWithIdentity", fixed("DecryptWithIdentity",
			args(callArgs{Identity: m.Value, CiphertextB64: sd.X25519["hello"]}))))
	}
	for _, m := range ciphertextMutations(helloCT) {
		add(single("mut-"+m.Name, "DecryptWithIdentity", fixed("DecryptWithIdentity",
			args(callArgs{Identity: id1, CiphertextB64: b64(m.Data)}))))
	}
	bigCT := decodeB64(sd.X25519["chunk+"])
	for _, edit := range []string{
		fmt.Sprintf("flip:%d", len(bigCT)-1), fmt.Sprintf("flip:%d", 65536+100), fmt.Sprintf("truncate:%d", len(bigCT)/2),
		fmt.Sprintf("truncate:%d", len(bigCT)-1), fmt.Sprintf("truncate:%d", len(bigCT)-17),
	} {
		add(single("mut-large-"+strings.Replace(edit, ":", "-", 1), "DecryptWithIdentity", fixed("DecryptWithIdentity",
			args(callArgs{Identity: id1, CiphertextRef: "x25519:chunk+", CiphertextEdit: edit}))))
	}

	// ---- EncryptWithPassphrase --------------------------------------------
	pwCase := func(name, pass string, pt []byte) {
		a := callArgs{Passphrase: pass, PlaintextB64: b64(pt)}
		if len(pt) > 4096 {
			a = callArgs{Passphrase: pass, PlaintextPattern: len(pt)}
		}
		c := single(name, "EncryptWithPassphrase", fixed("EncryptWithPassphrase", args(a)))
		ct, err := mobilebind.EncryptWithPassphrase(pass, pt)
		if err != nil {
			panic(err)
		}
		c.randomized = map[int]*shape{0: {BytesPrefixB64: b64([]byte(scryptHdr)), Length: len(ct), Distinct: true, ScryptWorkFactor: 18,
			Roundtrip: &stepSpec{Function: "DecryptWithPassphrase", Args: callArgs{Passphrase: pass, CiphertextB64: outToken},
				Want: wantBytes(pt)}}}
		add(c)
	}
	pwCase("short", "correct horse", []byte("hello, symvault\n"))
	pwCase("unicode-passphrase", "pässwörd ✓ 🔑", []byte{1, 2, 3})
	pwCase("binary", "p", allBytes())
	pwCase("long-passphrase", strings.Repeat("long-pass-", 200), []byte("x"))
	pwCase("chunk-plus-one", "pw", pattern(65537))
	add(single("empty-passphrase", "EncryptWithPassphrase", fixed("EncryptWithPassphrase", args(callArgs{PlaintextB64: b64([]byte("x"))}))))
	add(single("empty-plaintext", "EncryptWithPassphrase", fixed("EncryptWithPassphrase", args(callArgs{Passphrase: "pw"}))))
	add(single("both-empty", "EncryptWithPassphrase", fixed("EncryptWithPassphrase", args(callArgs{}))))

	// ---- DecryptWithPassphrase --------------------------------------------
	scryptCT := decodeB64(sd.Scrypt["hello"])
	add(single("go-ciphertext", "DecryptWithPassphrase", fixed("DecryptWithPassphrase", args(callArgs{Passphrase: vaultPass, CiphertextB64: sd.Scrypt["hello"]}))))
	add(single("wrong-passphrase", "DecryptWithPassphrase", fixed("DecryptWithPassphrase", args(callArgs{Passphrase: "wrong", CiphertextB64: sd.Scrypt["hello"]}))))
	add(single("empty-passphrase", "DecryptWithPassphrase", fixed("DecryptWithPassphrase", args(callArgs{CiphertextB64: sd.Scrypt["hello"]}))))
	add(single("empty-ciphertext", "DecryptWithPassphrase", fixed("DecryptWithPassphrase", args(callArgs{Passphrase: "pw"}))))
	add(single("both-empty", "DecryptWithPassphrase", fixed("DecryptWithPassphrase", args(callArgs{}))))
	add(single("x25519-ciphertext", "DecryptWithPassphrase", fixed("DecryptWithPassphrase", args(callArgs{Passphrase: "pw", CiphertextB64: sd.X25519["hello"]}))))
	for _, m := range ciphertextMutations(scryptCT) {
		add(single("mut-"+m.Name, "DecryptWithPassphrase", fixed("DecryptWithPassphrase",
			args(callArgs{Passphrase: vaultPass, CiphertextB64: b64(m.Data)}))))
	}
	// Work-factor policy is part of the error contract (age caps accepted cost).
	wf := strings.Index(string(scryptCT), "\n-> scrypt ")
	if wf >= 0 {
		line := string(scryptCT[wf+1:])
		line = line[:strings.Index(line, "\n")]
		fields := strings.Fields(line)
		if len(fields) == 4 {
			for _, w := range []string{"23", "30", "0", "07", "x", "99999999999999999999"} {
				fields[3] = w
				mut := strings.Replace(string(scryptCT), line, strings.Join(fields, " "), 1)
				add(single("mut-work-factor-"+w, "DecryptWithPassphrase", fixed("DecryptWithPassphrase",
					args(callArgs{Passphrase: vaultPass, CiphertextB64: b64([]byte(mut))}))))
			}
		}
	}

	// ---- InitVault ----------------------------------------------------------
	initAfter := func(c *caseSpec) {
		c.afterTree = true
		c.afterPaths = []string{"config.yaml", "identity.age", "entries"}
		c.afterText = map[string]bool{"config.yaml": true}
	}
	{
		c := caseSpec{ID: "InitVault/fresh-then-open", Group: "InitVault", Steps: []stepSpec{
			fixed("InitVault", args(callArgs{VaultDir: vaultArg, Passphrase: "init pass"})),
			fixed("OpenVaultWithPassphrase", args(callArgs{VaultDir: vaultArg, Passphrase: "init pass"})),
			fixed("OpenVaultWithPassphrase", args(callArgs{VaultDir: vaultArg, Passphrase: "wrong pass"})),
		}}
		c.randomized = map[int]*shape{1: {StringPrefix: "AGE-SECRET-KEY-1", StringCharset: "bech32-upper", Length: 74}}
		add(c)
	}
	{
		c := single("fresh-tree", "InitVault", fixed("InitVault", args(callArgs{VaultDir: vaultArg, Passphrase: "init pass"})))
		initAfter(&c)
		add(c)
	}
	for _, v := range []struct{ n, dir string }{
		{"dir-with-space", "$ROOT/va ult"}, {"dir-yaml-special", "$ROOT/v: #1 'q' \"dq\" [x] {y}"},
		{"dir-unicode", "$ROOT/vault-é-✓"}, {"dir-nested", "$ROOT/a/b/c/vault"}, {"dir-dotdot-clean", "$ROOT/x/../vault"},
		{"dir-trailing-slash", "$ROOT/vault/"}, {"dir-yaml-bool", "$ROOT/true"}, {"dir-leading-dash", "$ROOT/-dash"},
		{"dir-percent-star", "$ROOT/%star*&anchor !tag"}, {"dir-numberlike", "$ROOT/123"},
	} {
		c := single(v.n, "InitVault", fixed("InitVault", args(callArgs{VaultDir: v.dir, Passphrase: "pw"})))
		c.afterPaths, c.afterText = []string{"config.yaml"}, map[string]bool{"config.yaml": true}
		add(c)
	}
	add(single("empty-dir", "InitVault", fixed("InitVault", args(callArgs{Passphrase: "pw"}))))
	add(single("empty-passphrase", "InitVault", fixed("InitVault", args(callArgs{VaultDir: vaultArg}))))
	add(single("both-empty", "InitVault", fixed("InitVault", args(callArgs{}))))
	add(vsingle("reinit-existing-overwrites", "InitVault", fixed("InitVault", args(callArgs{VaultDir: vaultArg, Passphrase: "new pass"}))))
	{
		c := vsingle("reinit-then-old-passphrase-fails", "InitVault", fixed("InitVault", args(callArgs{VaultDir: vaultArg, Passphrase: "new pass"})))
		c.Steps = append(c.Steps, fixed("OpenVaultWithPassphrase", args(callArgs{VaultDir: vaultArg, Passphrase: vpass})),
			fixed("OpenVaultWithPassphrase", args(callArgs{VaultDir: vaultArg, Passphrase: "new pass"})))
		c.randomized = map[int]*shape{2: {StringPrefix: "AGE-SECRET-KEY-1", StringCharset: "bech32-upper", Length: 74}}
		add(c)
	}
	add(vsingle("parent-is-file", "InitVault", fixed("InitVault", args(callArgs{VaultDir: "$ROOT/vault/identity.age/sub", Passphrase: "pw"}))))
	add(vsingle("dir-is-file", "InitVault", fixed("InitVault", args(callArgs{VaultDir: "$ROOT/vault/identity.age", Passphrase: "pw"}))))
	{
		c := single("unicode-passphrase-roundtrip", "InitVault", fixed("InitVault", args(callArgs{VaultDir: vaultArg, Passphrase: "pässwörd ✓ 🔑"})))
		c.Steps = append(c.Steps, fixed("OpenVaultWithPassphrase", args(callArgs{VaultDir: vaultArg, Passphrase: "pässwörd ✓ 🔑"})))
		c.randomized = map[int]*shape{1: {StringPrefix: "AGE-SECRET-KEY-1", StringCharset: "bech32-upper", Length: 74}}
		add(c)
	}

	// ---- OpenVaultWithPassphrase ------------------------------------------
	open := func(pass, dir string) stepSpec {
		return fixed("OpenVaultWithPassphrase", args(callArgs{VaultDir: dir, Passphrase: pass}))
	}
	add(vsingle("seed-vault", "OpenVaultWithPassphrase", open(vpass, vaultArg)))
	add(vsingle("wrong-passphrase", "OpenVaultWithPassphrase", open("wrong", vaultArg)))
	add(vsingle("passphrase-prefix", "OpenVaultWithPassphrase", open(vpass[:10], vaultArg)))
	add(vsingle("passphrase-trailing-space", "OpenVaultWithPassphrase", open(vpass+" ", vaultArg)))
	add(vsingle("empty-passphrase", "OpenVaultWithPassphrase", open("", vaultArg)))
	add(vsingle("empty-dir", "OpenVaultWithPassphrase", open(vpass, "")))
	add(vsingle("both-empty", "OpenVaultWithPassphrase", open("", "")))
	add(vsingle("missing-dir", "OpenVaultWithPassphrase", open(vpass, "$ROOT/missing")))
	add(vsingle("dir-traversal", "OpenVaultWithPassphrase", open(vpass, "$ROOT/vault/../vault")))
	add(vsingle("relative-traversal", "OpenVaultWithPassphrase", open(vpass, "../vault")))
	add(vsingle("parent-is-file", "OpenVaultWithPassphrase", open(vpass, "$ROOT/vault/identity.age/sub")))
	add(vsingle("dir-is-file", "OpenVaultWithPassphrase", open(vpass, "$ROOT/vault/identity.age")))
	add(vsingle("missing-identity-file", "OpenVaultWithPassphrase", open(vpass, vaultArg), mutation{Op: "remove", Path: "identity.age"}))
	add(vsingle("identity-is-directory", "OpenVaultWithPassphrase", open(vpass, vaultArg),
		mutation{Op: "remove", Path: "identity.age"}, mutation{Op: "mkdir", Path: "identity.age"}))
	add(vsingle("identity-empty", "OpenVaultWithPassphrase", open(vpass, vaultArg), mutation{Op: "write", Path: "identity.age", Text: ""}))
	add(vsingle("identity-junk", "OpenVaultWithPassphrase", open(vpass, vaultArg), mutation{Op: "write", Path: "identity.age", Text: "junk"}))
	add(vsingle("identity-truncated", "OpenVaultWithPassphrase", open(vpass, vaultArg), mutation{Op: "truncate", Path: "identity.age", Size: 100}))
	add(vsingle("identity-flipped-payload", "OpenVaultWithPassphrase", open(vpass, vaultArg), mutation{Op: "flip", Path: "identity.age", Offset: 270}))
	add(vsingle("missing-config", "OpenVaultWithPassphrase", open(vpass, vaultArg), mutation{Op: "remove", Path: "config.yaml"}))
	add(vsingle("config-junk", "OpenVaultWithPassphrase", open(vpass, vaultArg), mutation{Op: "write", Path: "config.yaml", Text: "vault: [unclosed\n"}))
	add(vsingle("config-empty", "OpenVaultWithPassphrase", open(vpass, vaultArg), mutation{Op: "write", Path: "config.yaml", Text: ""}))
	add(vsingle("config-type-mismatch", "OpenVaultWithPassphrase", open(vpass, vaultArg), mutation{Op: "write", Path: "config.yaml", Text: "vault: 5\n"}))
	add(vsingle("recipients-valid-wrong-passphrase", "OpenVaultWithPassphrase", open("wrong", vaultArg),
		mutation{Op: "write", Path: "recipients.txt", Text: sd.Vault.Recipient + "\n"}))
	add(vsingle("recipients-invalid-wrong-passphrase", "OpenVaultWithPassphrase", open("wrong", vaultArg),
		mutation{Op: "write", Path: "recipients.txt", Text: "not-a-recipient\n"}))
	add(vsingle("recipients-empty-wrong-passphrase", "OpenVaultWithPassphrase", open("wrong", vaultArg),
		mutation{Op: "write", Path: "recipients.txt", Text: "# only a comment\n"}))
	add(vsingle("manifest-missing-rebuilt", "OpenVaultWithPassphrase", open(vpass, vaultArg), mutation{Op: "remove", Path: "manifest.age"}))
	add(vsingle("entries-dir-missing", "OpenVaultWithPassphrase", open(vpass, vaultArg), mutation{Op: "remove", Path: "entries"}))

	add(vsingle("identity-is-symlink", "OpenVaultWithPassphrase", open(vpass, vaultArg),
		mutation{Op: "rename", Path: "identity.age", Target: "identity-real.age"}, mutation{Op: "symlink", Path: "identity.age", Target: "identity-real.age"}))
	add(vsingle("identity-is-dangling-symlink", "OpenVaultWithPassphrase", open(vpass, vaultArg),
		mutation{Op: "symlink", Path: "identity.age", Target: "nowhere.age"}))
	add(vsingle("identity-is-symlink-outside-root", "OpenVaultWithPassphrase", open(vpass, vaultArg),
		mutation{Op: "rename", Path: "identity.age", Target: "../identity-outside.age"}, mutation{Op: "symlink", Path: "identity.age", Target: "../identity-outside.age"}))
	add(vsingle("config-is-symlink", "OpenVaultWithPassphrase", open(vpass, vaultArg),
		mutation{Op: "rename", Path: "config.yaml", Target: "config-real.yaml"}, mutation{Op: "symlink", Path: "config.yaml", Target: "config-real.yaml"}))
	add(vsingle("manifest-is-symlink", "OpenVaultWithPassphrase", open(vpass, vaultArg),
		mutation{Op: "rename", Path: "manifest.age", Target: "manifest-real.age"}, mutation{Op: "symlink", Path: "manifest.age", Target: "manifest-real.age"}))
	add(vsingle("entries-dir-is-symlink", "OpenVaultWithPassphrase", open(vpass, vaultArg),
		mutation{Op: "rename", Path: "entries", Target: "entries-real"}, mutation{Op: "symlink", Path: "entries", Target: "entries-real"}))
	// Go rewrites config.yaml to the full merged config on every open of a
	// config without legacy_mode; the file, and the tree around it, are state.
	{
		c := caseSpec{ID: "OpenVaultWithPassphrase/fresh-init-config-and-tree-after-open", Group: "OpenVaultWithPassphrase", Steps: []stepSpec{
			fixed("InitVault", args(callArgs{VaultDir: vaultArg, Passphrase: "init pass"})),
			fixed("OpenVaultWithPassphrase", args(callArgs{VaultDir: vaultArg, Passphrase: "init pass"})),
		}}
		c.randomized = map[int]*shape{1: {StringPrefix: "AGE-SECRET-KEY-1", StringCharset: "bech32-upper", Length: 74}}
		c.afterTree = true
		c.afterPaths = []string{"config.yaml", "identity.age", "entries", "manifest.age"}
		c.afterText = map[string]bool{"config.yaml": true}
		add(c)
	}
	for _, r := range []struct {
		id   string
		muts []mutation
	}{
		{"seed-vault-state-after-open", nil},
		{"init-style-config-with-legacy-file", []mutation{
			{Op: "write", Path: "config.yaml", Text: "vault:\n    format_version: 2\nvaultDir: /placeholder/vault\n"},
			{Op: "write", Path: "stray.age", B64: sd.X25519["hello"]}}},
		{"config-without-vault-section", []mutation{{Op: "write", Path: "config.yaml", Text: "vaultDir: /placeholder/vault\n"}}},
		{"config-with-legacy-mode-true", []mutation{{Op: "write", Path: "config.yaml", Text: "vault:\n    legacy_mode: true\n    format_version: 2\nvaultDir: /placeholder/vault\n"}}},
		{"manifest-removed-config-init-style", []mutation{
			{Op: "write", Path: "config.yaml", Text: "vault:\n    format_version: 2\nvaultDir: /placeholder/vault\n"},
			{Op: "remove", Path: "manifest.age"}}},
	} {
		c := vsingle(r.id, "OpenVaultWithPassphrase", open(vpass, vaultArg), r.muts...)
		c.afterTree = true
		c.afterPaths = []string{"config.yaml"}
		c.afterText = map[string]bool{"config.yaml": true}
		add(c)
	}

	// ---- ReadEntryJSON ----------------------------------------------------
	read := func(path, id, dir string, normalize ...string) stepSpec {
		return fixed("ReadEntryJSON", args(callArgs{VaultDir: dir, EntryPath: path, Identity: id}), normalize...)
	}
	for _, e := range sd.Vault.Entries {
		add(vsingle("seed-"+strings.ReplaceAll(e, "/", "-"), "ReadEntryJSON", read(e, vid, vaultArg)))
	}
	add(vsingle("trim-identity", "ReadEntryJSON", read("top", " \n"+vid+"\t", vaultArg)))
	add(vsingle("path-trimmed-spaces", "ReadEntryJSON", read(" top ", vid, vaultArg)))
	add(vsingle("missing-entry", "ReadEntryJSON", read("nope", vid, vaultArg)))
	add(vsingle("missing-nested", "ReadEntryJSON", read("work/nope/deeper", vid, vaultArg)))
	add(vsingle("missing-under-file-parent", "ReadEntryJSON", read("top/child", vid, vaultArg)))
	for _, p := range []struct{ n, p string }{
		{"empty-path", ""}, {"dot", "."}, {"dotdot", ".."}, {"traversal", "../x"}, {"traversal-nested", "work/../../x"},
		{"absolute", "/abs"}, {"dot-segment", "a/./b"}, {"double-slash", "a//b"}, {"trailing-slash", "work/"},
		{"nul", "a\x00b"}, {"backslash", "a\\b"}, {"deep-65", strings.Repeat("a/", 64) + "a"}, {"deep-70", strings.Repeat("a/", 70) + "a"},
		{"windows-drive", "C:\\x"}, {"newline", "a\nb"}, {"only-spaces", "   "}, {"leading-space-traversal", " ../x"},
		{"unicode-dotdot-lookalike", "\u2025/x"},
	} {
		add(vsingle("path-"+p.n, "ReadEntryJSON", read(p.p, vid, vaultArg)))
	}
	add(vsingle("wrong-identity-existing", "ReadEntryJSON", read("top", id2, vaultArg)))
	add(vsingle("wrong-identity-missing", "ReadEntryJSON", read("nope", id2, vaultArg)))
	for _, m := range identityMutations(id1)[:8] {
		add(vsingle("bad-identity-"+m.Name, "ReadEntryJSON", read("top", m.Value, vaultArg)))
	}
	add(vsingle("empty-dir", "ReadEntryJSON", read("top", vid, "")))
	add(vsingle("missing-dir", "ReadEntryJSON", read("top", vid, "$ROOT/missing")))
	add(vsingle("dir-traversal", "ReadEntryJSON", read("top", vid, "$ROOT/vault/../vault")))
	add(vsingle("dir-is-file", "ReadEntryJSON", read("top", vid, "$ROOT/vault/identity.age")))
	add(vsingle("missing-config", "ReadEntryJSON", read("top", vid, vaultArg), mutation{Op: "remove", Path: "config.yaml"}))
	add(vsingle("config-junk", "ReadEntryJSON", read("top", vid, vaultArg), mutation{Op: "write", Path: "config.yaml", Text: "vault: [unclosed\n"}))
	add(vsingle("entry-corrupt-flip", "ReadEntryJSON", read("top", vid, vaultArg), mutation{Op: "flip", Path: "entries/top.age", Offset: 200}))
	add(vsingle("entry-corrupt-truncate", "ReadEntryJSON", read("top", vid, vaultArg), mutation{Op: "truncate", Path: "entries/top.age", Size: 60}))
	add(vsingle("entry-empty-file", "ReadEntryJSON", read("top", vid, vaultArg), mutation{Op: "write", Path: "entries/top.age", Text: ""}))
	add(vsingle("entry-junk", "ReadEntryJSON", read("top", vid, vaultArg), mutation{Op: "write", Path: "entries/top.age", Text: "junk"}))
	add(vsingle("manifest-missing", "ReadEntryJSON", read("top", vid, vaultArg), mutation{Op: "remove", Path: "manifest.age"}))
	add(vsingle("legacy-top-level-entry", "ReadEntryJSON", read("legacy", vid, vaultArg),
		mutation{Op: "write", Path: "legacy.age", B64: sd.X25519["legacy-entry"]}))

	add(vsingle("stored-minus-zero", "ReadEntryJSON", read("negzero", vid, vaultArg),
		mutation{Op: "write", Path: "entries/negzero.age", B64: sd.X25519["stored-minus-zero"]}))
	// config.yaml is rewritten by Go's vault.Open (legacy-mode detection).
	rewrite := func(group, id string, st stepSpec, muts ...mutation) {
		c := vsingle(id, group, st, muts...)
		c.afterTree = true
		c.afterPaths = []string{"config.yaml"}
		c.afterText = map[string]bool{"config.yaml": true}
		add(c)
	}
	initStyle := mutation{Op: "write", Path: "config.yaml", Text: "vault:\n    format_version: 2\nvaultDir: /placeholder/vault\n"}
	rewrite("ReadEntryJSON", "config-rewritten-init-style", read("top", vid, vaultArg), initStyle)
	rewrite("ReadEntryJSON", "config-rewritten-init-style-legacy-file", read("top", vid, vaultArg), initStyle,
		mutation{Op: "write", Path: "stray.age", B64: sd.X25519["hello"]})
	rewrite("ReadEntryJSON", "config-rewritten-no-vault-section", read("top", vid, vaultArg),
		mutation{Op: "write", Path: "config.yaml", Text: "vaultDir: /placeholder/vault\n"})
	rewrite("ReadEntryJSON", "config-untouched-when-legacy-mode-set", read("top", vid, vaultArg))
	// Symlinks (the harness replays them identically in Go, Rust and Swift).
	rename := func(from, to string) mutation { return mutation{Op: "rename", Path: from, Target: to} }
	link := func(path, target string) mutation { return mutation{Op: "symlink", Path: path, Target: target} }
	add(vsingle("entry-is-symlink", "ReadEntryJSON", read("top", vid, vaultArg),
		rename("entries/top.age", "entries/top-real.age"), link("entries/top.age", "top-real.age")))
	add(vsingle("entry-is-symlink-outside-root", "ReadEntryJSON", read("top", vid, vaultArg),
		rename("entries/top.age", "../outside.age"), link("entries/top.age", "../../outside.age")))
	add(vsingle("entry-is-dangling-symlink", "ReadEntryJSON", read("top", vid, vaultArg),
		link("entries/top.age", "nowhere.age")))
	add(vsingle("entries-subdir-is-symlink", "ReadEntryJSON", read("work/github", vid, vaultArg),
		rename("entries/work", "entries/work-real"), link("entries/work", "work-real")))
	add(vsingle("entries-dir-is-symlink", "ReadEntryJSON", read("top", vid, vaultArg),
		rename("entries", "entries-real"), link("entries", "entries-real")))
	add(vsingle("manifest-is-symlink", "ReadEntryJSON", read("top", vid, vaultArg),
		rename("manifest.age", "manifest-real.age"), link("manifest.age", "manifest-real.age")))
	add(vsingle("identity-is-symlink-entry-read", "ReadEntryJSON", read("top", vid, vaultArg),
		rename("identity.age", "identity-real.age"), link("identity.age", "identity-real.age")))

	// ---- WriteEntryJSON (each followed by a normalised read) ----------------
	writeRead := func(id, path, js string, extra ...stepSpec) caseSpec {
		c := caseSpec{ID: "WriteEntryJSON/" + id, Group: "WriteEntryJSON", Vault: true, Steps: []stepSpec{
			fixed("WriteEntryJSON", args(callArgs{VaultDir: vaultArg, EntryPath: path, EntryJSON: js, Identity: vid})),
			fixed("ReadEntryJSON", args(callArgs{VaultDir: vaultArg, EntryPath: path, Identity: vid}), "timestamps"),
		}}
		c.Steps = append(c.Steps, extra...)
		return c
	}
	for _, w := range []struct{ n, p, j string }{
		{"minimal", "new/minimal", `{"data":{"k":"v"}}`},
		{"empty-object", "new/empty", `{}`},
		{"null-document", "new/null", `null`},
		{"numbers", "new/numbers", `{"data":{"i":1,"f":1.5,"big":12345678901234567890,"exp":1e21,"small":1e-7,"neg":-0.0,"half":0.5,"int-as-float":2.0,"huge-int":9007199254740993}}`},
		{"html-and-unicode", "new/html", `{"data":{"h":"<b>&amp;</b>","u":"\u2028\u2029é✓🔑","esc":"\"\\\n\t\u0000\u001f"}}`},
		{"nested", "new/nested", `{"data":{"a":{"b":{"c":[1,[2,[3]],{"d":null}]}},"empty_arr":[],"empty_obj":{}}}`},
		{"meta-tags", "new/tags", `{"data":{"k":"v"},"meta":{"tags":["b","a","<x>"],"version":7,"created":"2001-02-03T04:05:06Z"}}`},
		{"secret-meta", "new/secret", `{"data":{"token":"abc"},"secret_meta":{"type":"api_key","usage_hint":"hint","auto_rotate":true}}`},
		{"classification-canary", "new/class", `{"data":{"k":"v"},"classification":3,"canary":true}`},
		{"explicit-path-field", "new/pathfield", `{"path":"other/path","data":{"k":"v"}}`},
		{"duplicate-keys", "new/dup", `{"data":{"k":"first","k":"second"},"data":{"z":1}}`},
		{"unknown-fields", "new/unknown", `{"data":{"k":"v"},"extra":{"x":1},"Data":{"case":"insensitive"}}`},
		{"overwrite-seed", "top", `{"data":{"k":"changed"}}`},
		{"overwrite-seed-nested", "work/github", `{"data":{"username":"octo2"}}`},
		{"password-like", "new/pw", `{"data":{"password":"correct horse","username":"u"}}`},
		{"totp-field", "new/totp", `{"data":{"totp":"JBSWY3DPEHPK3PXP"}}`},
		{"long-value", "new/long", `{"data":{"v":"` + strings.Repeat("x", 4096) + `"}}`},
		{"unicode-path", "new/é/✓", `{"data":{"k":"v"}}`},
		{"backslash-path", "new\\win", `{"data":{"k":"v"}}`},
		{"spaces-path-trim", " new/spaced ", `{"data":{"k":"v"}}`},
		{"depth-64", strings.Repeat("d/", 63) + "d", `{"data":{"k":"v"}}`},
	} {
		c := writeRead(w.n, w.p, w.j)
		if strings.HasPrefix(w.p, "new\\") || strings.HasPrefix(w.p, " ") {
			c.Steps = append(c.Steps, fixed("ListEntriesJSON", args(callArgs{VaultDir: vaultArg, Identity: vid})))
		}
		add(c)
	}
	for _, w := range []struct{ n, j string }{
		{"empty-string", ""}, {"open-brace", "{"}, {"array", "[]"}, {"string", `"x"`}, {"number", "5"}, {"true", "true"},
		{"data-string", `{"data":"x"}`}, {"data-array", `{"data":[1]}`}, {"data-number", `{"data":5}`},
		{"trailing-garbage", `{"data":{"k":1}} x`}, {"two-docs", `{} {}`}, {"bad-literal", `{"data":tru}`},
		{"bad-key", `{data:{}}`}, {"single-quotes", `{'data':{}}`}, {"trailing-comma", `{"data":{},}`},
		{"missing-colon", `{"data" {}}`}, {"unterminated-string", `{"data":{"k":"v}}`}, {"control-char-in-string", "{\"data\":{\"k\":\"a\tb\"}}"},
		{"bad-escape", `{"data":{"k":"\q"}}`}, {"bad-unicode-escape", `{"data":{"k":"\u12"}}`},
		{"meta-version-string", `{"meta":{"version":"x"}}`}, {"meta-version-float", `{"meta":{"version":1.5}}`},
		{"meta-created-number", `{"meta":{"created":5}}`}, {"meta-created-bad-time", `{"meta":{"created":"yesterday"}}`},
		{"meta-tags-string", `{"meta":{"tags":"a"}}`}, {"meta-tags-number-item", `{"meta":{"tags":[1]}}`},
		{"meta-array", `{"meta":[]}`}, {"secret-meta-string", `{"secret_meta":"x"}`}, {"secret-meta-type-number", `{"secret_meta":{"type":5}}`},
		{"classification-string", `{"classification":"a"}`}, {"classification-float", `{"classification":1.5}`},
		{"canary-number", `{"canary":1}`}, {"path-number", `{"path":5}`}, {"data-null-value", `{"data":null}`},
		{"utf8-bom", "\ufeff{}"}, {"leading-whitespace", " \n\t{\"data\":{}}\n"}, {"huge-number", `{"data":{"n":1e999}}`},
		{"write-history-bad", `{"meta":{"write_history":[{"timestamp":"x","action":"a"}]}}`},
		{"deep-nesting", strings.Repeat(`{"a":`, 40) + "1" + strings.Repeat("}", 40)},
	} {
		c := single("json-"+w.n, "WriteEntryJSON", fixed("WriteEntryJSON", args(callArgs{VaultDir: vaultArg, EntryPath: "bad/json", EntryJSON: w.j, Identity: vid})))
		c.Vault = true
		c.Steps = append(c.Steps, fixed("ListEntriesJSON", args(callArgs{VaultDir: vaultArg, Identity: vid})))
		add(c)
	}
	// ---- nesting, size and budget limits (FFI-001 review F1/F3) -------------
	// Documents are generated from repeated parts so a 10 000-level or
	// megabyte-sized input costs a few bytes in the fixture. "Depth N" is the
	// number of containers below the data object (objects: {"a":{"a":...1}}).
	limitCase := func(id string, readBack bool, parts []jsonPart) {
		c := caseSpec{ID: "WriteEntryJSON/" + id, Group: "WriteEntryJSON", Vault: true, Steps: []stepSpec{
			fixed("WriteEntryJSON", args(callArgs{VaultDir: vaultArg, EntryPath: "deep/x", EntryJSONParts: parts, Identity: vid}))}}
		if readBack {
			c.Steps = append(c.Steps, fixed("ReadEntryJSON", args(callArgs{VaultDir: vaultArg, EntryPath: "deep/x", Identity: vid}), "timestamps"))
		}
		c.Steps = append(c.Steps, fixed("ListEntriesJSON", args(callArgs{VaultDir: vaultArg, Identity: vid})))
		add(c)
	}
	objectsAt := func(n int, leaf, tail string) []jsonPart {
		return []jsonPart{{Text: `{"data":`}, {Text: `{"a":`, Repeat: n}, {Text: leaf}, {Text: `}`, Repeat: n}, {Text: tail}}
	}
	arraysAt := func(n int, leaf string) []jsonPart {
		return []jsonPart{{Text: `{"data":{"k":`}, {Text: `[`, Repeat: n}, {Text: leaf}, {Text: `]`, Repeat: n}, {Text: `}}`}}
	}
	limitCase("json-deep-object-32-accepted", true, objectsAt(32, "1", "}"))
	for _, n := range []int{33, 129, 5000, 9999, 10000, 10001} {
		limitCase(fmt.Sprintf("json-deep-object-%d", n), false, objectsAt(n, "1", "}"))
	}
	limitCase("json-deep-array-31-accepted", true, arraysAt(31, "1"))
	for _, n := range []int{32, 33, 129, 5000, 9998, 9999, 10001} {
		limitCase(fmt.Sprintf("json-deep-array-%d", n), false, arraysAt(n, "1"))
	}
	// A number that does not fit float64 is reported wherever it sits, and a
	// later type error outranks the store's depth limit.
	limitCase("json-deep-object-5000-huge-number", false, objectsAt(5000, "1e999", "}"))
	limitCase("json-deep-object-5000-then-type-error", false, objectsAt(5000, "1", `,"canary":1}`))
	limitCase("json-deep-object-5000-then-syntax-error", false, objectsAt(5000, "1", `,}`))
	limitCase("json-deep-object-unterminated-10001", false, []jsonPart{{Text: `{"data":`}, {Text: `{"a":`, Repeat: 10001}})
	limitCase("json-deep-array-unterminated-5000", false, []jsonPart{{Text: `{"data":{"k":`}, {Text: `[`, Repeat: 5000}})
	// The four store budgets all surface as one text that names neither path
	// nor value.
	limitCase("json-limit-string-1MiB-accepted-boundary-minus", false, []jsonPart{{Text: `{"data":{"v":"`}, {Text: strings.Repeat("x", 1024), Repeat: 1023}, {Text: `"}}`}})
	limitCase("json-limit-string-over-1MiB", false, []jsonPart{{Text: `{"data":{"v":"`}, {Text: strings.Repeat("x", 1024), Repeat: 1024}, {Text: `x"}}`}})
	limitCase("json-limit-array-items-1024-accepted", true, []jsonPart{{Text: `{"data":{"k":[`}, {Text: `0,`, Repeat: 1023}, {Text: `0]}}`}})
	limitCase("json-limit-array-items-1025", false, []jsonPart{{Text: `{"data":{"k":[`}, {Text: `0,`, Repeat: 1024}, {Text: `0]}}`}})
	limitCase("json-limit-key-over-1MiB", false, []jsonPart{{Text: `{"data":{"`}, {Text: strings.Repeat("k", 1024), Repeat: 1024}, {Text: `k":1}}`}})
	manyFields := func(prefix, suffix string, n int) string {
		var b strings.Builder
		b.WriteString(prefix)
		for i := 0; i < n; i++ {
			if i > 0 {
				b.WriteByte(',')
			}
			fmt.Fprintf(&b, `"k%04d":1`, i)
		}
		b.WriteString(suffix)
		return b.String()
	}
	limitCase("json-limit-top-level-fields-1025", false, []jsonPart{{Text: manyFields(`{"data":{`, `}}`, 1025)}})
	limitCase("json-limit-nested-fields-1025", false, []jsonPart{{Text: manyFields(`{"data":{"o":{`, `}}}`, 1025)}})
	// Go stores -0 as the literal "-0" and reads it back as -0.
	for _, w := range []struct{ n, j string }{
		{"numbers-minus-zero-forms", `{"data":{"a":-0,"b":-0.0,"c":-0e0,"d":0,"e":-1e-400,"f":[-0,0.0]}}`},
	} {
		add(writeRead(w.n, "new/negzero", w.j))
	}

	for _, p := range []struct{ n, p string }{
		{"empty", ""}, {"dot", "."}, {"dotdot", ".."}, {"traversal", "../x"}, {"traversal-nested", "work/../../x"}, {"absolute", "/abs"},
		{"dot-segment", "a/./b"}, {"double-slash", "a//b"}, {"trailing-slash", "work/"}, {"nul", "a\x00b"}, {"deep-65", strings.Repeat("a/", 64) + "a"},
		{"deep-70", strings.Repeat("a/", 70) + "a"}, {"newline", "a\nb"}, {"only-spaces", "   "},
		{"file-as-directory", "top/child"}, {"directory-as-file", "work"},
	} {
		c := vsingle("path-"+p.n, "WriteEntryJSON", fixed("WriteEntryJSON", args(callArgs{VaultDir: vaultArg, EntryPath: p.p, EntryJSON: `{"data":{"k":"v"}}`, Identity: vid})))
		c.Steps = append(c.Steps, fixed("ListEntriesJSON", args(callArgs{VaultDir: vaultArg, Identity: vid})))
		add(c)
	}
	for _, m := range identityMutations(id1)[:8] {
		add(vsingle("bad-identity-"+m.Name, "WriteEntryJSON", fixed("WriteEntryJSON", args(callArgs{VaultDir: vaultArg, EntryPath: "x", EntryJSON: `{}`, Identity: m.Value}))))
	}
	{
		c := vsingle("other-identity-writes-unreadable-entry", "WriteEntryJSON", fixed("WriteEntryJSON",
			args(callArgs{VaultDir: vaultArg, EntryPath: "foreign", EntryJSON: `{"data":{"k":"v"}}`, Identity: id2})))
		c.Steps = append(c.Steps,
			fixed("ReadEntryJSON", args(callArgs{VaultDir: vaultArg, EntryPath: "foreign", Identity: vid})),
			fixed("ReadEntryJSON", args(callArgs{VaultDir: vaultArg, EntryPath: "foreign", Identity: id2}), "timestamps"))
		add(c)
	}
	add(vsingle("empty-dir", "WriteEntryJSON", fixed("WriteEntryJSON", args(callArgs{EntryPath: "x", EntryJSON: `{}`, Identity: vid}))))
	add(vsingle("dir-is-file", "WriteEntryJSON", fixed("WriteEntryJSON", args(callArgs{VaultDir: "$ROOT/vault/identity.age", EntryPath: "x", EntryJSON: `{}`, Identity: vid}))))
	add(vsingle("config-junk", "WriteEntryJSON", fixed("WriteEntryJSON", args(callArgs{VaultDir: vaultArg, EntryPath: "x", EntryJSON: `{}`, Identity: vid})),
		mutation{Op: "write", Path: "config.yaml", Text: "vault: [unclosed\n"}))
	add(vsingle("entries-dir-missing", "WriteEntryJSON", fixed("WriteEntryJSON", args(callArgs{VaultDir: vaultArg, EntryPath: "x/y", EntryJSON: `{"data":{"k":"v"}}`, Identity: vid})),
		mutation{Op: "remove", Path: "entries"}))

	// A missing config.yaml means default settings for Write/List/Verify.
	{
		c := vsingle("config-missing", "WriteEntryJSON", fixed("WriteEntryJSON", args(callArgs{VaultDir: vaultArg, EntryPath: "new/entry", EntryJSON: `{"data":{"k":"v"}}`, Identity: vid})),
			mutation{Op: "remove", Path: "config.yaml"})
		c.Steps = append(c.Steps,
			fixed("ListEntriesJSON", args(callArgs{VaultDir: vaultArg, Identity: vid})),
			fixed("VerifyManifestIntegrity", args(callArgs{VaultDir: vaultArg, Identity: vid})),
			fixed("ReadEntryJSON", args(callArgs{VaultDir: vaultArg, EntryPath: "new/entry", Identity: vid}), "timestamps"))
		c.afterTree = true
		c.afterPaths = []string{"entries"}
		add(c)
	}
	add(vsingle("config-empty", "WriteEntryJSON", fixed("WriteEntryJSON", args(callArgs{VaultDir: vaultArg, EntryPath: "new/entry", EntryJSON: `{"data":{"k":"v"}}`, Identity: vid})),
		mutation{Op: "write", Path: "config.yaml", Text: ""}))
	add(vsingle("config-is-directory", "WriteEntryJSON", fixed("WriteEntryJSON", args(callArgs{VaultDir: vaultArg, EntryPath: "new/entry", EntryJSON: `{"data":{"k":"v"}}`, Identity: vid})),
		mutation{Op: "remove", Path: "config.yaml"}, mutation{Op: "mkdir", Path: "config.yaml"}))
	add(vsingle("config-missing-identity-file-missing", "WriteEntryJSON", fixed("WriteEntryJSON", args(callArgs{VaultDir: vaultArg, EntryPath: "new/entry", EntryJSON: `{"data":{"k":"v"}}`, Identity: vid})),
		mutation{Op: "remove", Path: "config.yaml"}, mutation{Op: "remove", Path: "identity.age"}))
	add(vsingle("identity-file-missing", "WriteEntryJSON", fixed("WriteEntryJSON", args(callArgs{VaultDir: vaultArg, EntryPath: "new/entry", EntryJSON: `{"data":{"k":"v"}}`, Identity: vid})),
		mutation{Op: "remove", Path: "identity.age"}))
	add(vsingle("config-missing-dir-missing", "WriteEntryJSON", fixed("WriteEntryJSON", args(callArgs{VaultDir: "$ROOT/missing", EntryPath: "new/entry", EntryJSON: `{"data":{"k":"v"}}`, Identity: vid}))))
	add(vsingle("entry-is-symlink-overwrite", "WriteEntryJSON", fixed("WriteEntryJSON", args(callArgs{VaultDir: vaultArg, EntryPath: "top", EntryJSON: `{"data":{"k":"over"}}`, Identity: vid})),
		mutation{Op: "rename", Path: "entries/top.age", Target: "entries/top-real.age"}, mutation{Op: "symlink", Path: "entries/top.age", Target: "top-real.age"}))
	add(vsingle("entries-subdir-is-symlink", "WriteEntryJSON", fixed("WriteEntryJSON", args(callArgs{VaultDir: vaultArg, EntryPath: "work/new", EntryJSON: `{"data":{"k":"v"}}`, Identity: vid})),
		mutation{Op: "rename", Path: "entries/work", Target: "entries/work-real"}, mutation{Op: "symlink", Path: "entries/work", Target: "work-real"}))
	add(vsingle("entries-dir-is-symlink", "WriteEntryJSON", fixed("WriteEntryJSON", args(callArgs{VaultDir: vaultArg, EntryPath: "x/y", EntryJSON: `{"data":{"k":"v"}}`, Identity: vid})),
		mutation{Op: "rename", Path: "entries", Target: "entries-real"}, mutation{Op: "symlink", Path: "entries", Target: "entries-real"}))

	// ---- ListEntriesJSON --------------------------------------------------
	list := func(prefix, id, dir string) stepSpec {
		return fixed("ListEntriesJSON", args(callArgs{VaultDir: dir, Prefix: prefix, Identity: id}))
	}
	for _, p := range []struct{ n, p string }{
		{"all", ""}, {"work", "work"}, {"work-slash", "work/"}, {"work-slash-g", "work/g"}, {"personal", "personal"}, {"no-match", "zz"},
		{"slash", "/"}, {"dotdot", ".."}, {"dot", "."}, {"unicode", "notes/é"}, {"unicode-partial", "n"}, {"case-sensitive", "WORK"},
		{"entries-prefix", "entries"}, {"with-age-suffix", "top.age"}, {"exact-entry", "top"}, {"deeper-than-entry", "top/x"},
		{"backslash", "work\\"}, {"space", " "}, {"nul", "a\x00b"}, {"long", strings.Repeat("a", 5000)}, {"wildcard", "*"}, {"regex-like", "w.*"},
	} {
		add(vsingle("prefix-"+p.n, "ListEntriesJSON", list(p.p, vid, vaultArg)))
	}
	add(vsingle("wrong-identity", "ListEntriesJSON", list("", id2, vaultArg)))
	add(vsingle("wrong-identity-prefix", "ListEntriesJSON", list("work", id2, vaultArg)))
	for _, m := range identityMutations(id1)[:6] {
		add(vsingle("bad-identity-"+m.Name, "ListEntriesJSON", list("", m.Value, vaultArg)))
	}
	{
		c := single("empty-vault", "ListEntriesJSON", fixed("InitVault", args(callArgs{VaultDir: vaultArg, Passphrase: "pw"})))
		c.Steps = append(c.Steps, list("", vid, vaultArg))
		add(c)
	}
	add(vsingle("missing-dir", "ListEntriesJSON", list("", vid, "$ROOT/missing")))
	add(vsingle("dir-is-file", "ListEntriesJSON", list("", vid, "$ROOT/vault/identity.age")))
	add(vsingle("manifest-missing", "ListEntriesJSON", list("", vid, vaultArg), mutation{Op: "remove", Path: "manifest.age"}))
	add(vsingle("manifest-junk", "ListEntriesJSON", list("", vid, vaultArg), mutation{Op: "write", Path: "manifest.age", Text: "junk"}))
	add(vsingle("config-junk", "ListEntriesJSON", list("", vid, vaultArg), mutation{Op: "write", Path: "config.yaml", Text: "vault: [unclosed\n"}))
	add(vsingle("stray-non-age-file", "ListEntriesJSON", list("", vid, vaultArg), mutation{Op: "write", Path: "entries/stray.txt", Text: "x"},
		mutation{Op: "remove", Path: "manifest.age"}))
	add(vsingle("extra-entry-file-unknown-to-manifest", "ListEntriesJSON", list("", vid, vaultArg),
		mutation{Op: "write", Path: "entries/extra.age", B64: sd.X25519["hello"]}))
	add(vsingle("extra-entry-file-manifest-removed", "ListEntriesJSON", list("", vid, vaultArg),
		mutation{Op: "write", Path: "entries/extra.age", B64: sd.X25519["hello"]}, mutation{Op: "remove", Path: "manifest.age"}))
	add(vsingle("entry-file-removed-manifest-stale", "ListEntriesJSON", list("", vid, vaultArg), mutation{Op: "remove", Path: "entries/top.age"}))

	rmConfig := mutation{Op: "remove", Path: "config.yaml"}
	add(vsingle("config-missing", "ListEntriesJSON", list("", vid, vaultArg), rmConfig))
	add(vsingle("config-missing-prefix", "ListEntriesJSON", list("work/", vid, vaultArg), rmConfig))
	add(vsingle("config-missing-manifest-removed", "ListEntriesJSON", list("", vid, vaultArg), rmConfig, mutation{Op: "remove", Path: "manifest.age"}))
	add(vsingle("config-missing-manifest-junk", "ListEntriesJSON", list("", vid, vaultArg), rmConfig, mutation{Op: "write", Path: "manifest.age", Text: "junk"}))
	add(vsingle("config-missing-legacy-file", "ListEntriesJSON", list("", vid, vaultArg), rmConfig, mutation{Op: "remove", Path: "manifest.age"},
		mutation{Op: "write", Path: "stray.age", B64: sd.X25519["hello"]}))
	add(vsingle("config-missing-wrong-identity", "ListEntriesJSON", list("", id2, vaultArg), rmConfig))
	add(vsingle("config-missing-dir-missing", "ListEntriesJSON", list("", vid, "$ROOT/missing")))
	add(vsingle("config-missing-dir-is-file", "ListEntriesJSON", list("", vid, "$ROOT/vault/identity.age"), rmConfig))
	add(vsingle("config-empty", "ListEntriesJSON", list("", vid, vaultArg), mutation{Op: "write", Path: "config.yaml", Text: ""}))
	add(vsingle("config-is-directory", "ListEntriesJSON", list("", vid, vaultArg), rmConfig, mutation{Op: "mkdir", Path: "config.yaml"}))
	add(vsingle("config-missing-identity-file-missing", "ListEntriesJSON", list("", vid, vaultArg), rmConfig, mutation{Op: "remove", Path: "identity.age"}))
	add(vsingle("identity-file-missing", "ListEntriesJSON", list("", vid, vaultArg), mutation{Op: "remove", Path: "identity.age"}))
	add(vsingle("config-missing-no-entries-dir", "ListEntriesJSON", list("", vid, vaultArg), rmConfig, mutation{Op: "remove", Path: "entries"}, mutation{Op: "remove", Path: "manifest.age"}))
	add(vsingle("entry-is-symlink", "ListEntriesJSON", list("", vid, vaultArg), mutation{Op: "remove", Path: "manifest.age"},
		mutation{Op: "rename", Path: "entries/top.age", Target: "entries/top-real.age"}, mutation{Op: "symlink", Path: "entries/top.age", Target: "top-real.age"}))
	add(vsingle("entries-subdir-is-symlink", "ListEntriesJSON", list("", vid, vaultArg), mutation{Op: "remove", Path: "manifest.age"},
		mutation{Op: "rename", Path: "entries/work", Target: "entries/work-real"}, mutation{Op: "symlink", Path: "entries/work", Target: "work-real"}))
	add(vsingle("entries-subdir-is-symlink-manifest-present", "ListEntriesJSON", list("", vid, vaultArg),
		mutation{Op: "rename", Path: "entries/work", Target: "entries/work-real"}, mutation{Op: "symlink", Path: "entries/work", Target: "work-real"}))
	add(vsingle("entries-subdir-is-symlink-prefix", "ListEntriesJSON", list("work/", vid, vaultArg),
		mutation{Op: "rename", Path: "entries/work", Target: "entries/work-real"}, mutation{Op: "symlink", Path: "entries/work", Target: "work-real"}))
	add(vsingle("entries-dir-is-symlink", "ListEntriesJSON", list("", vid, vaultArg), mutation{Op: "remove", Path: "manifest.age"},
		mutation{Op: "rename", Path: "entries", Target: "entries-real"}, mutation{Op: "symlink", Path: "entries", Target: "entries-real"}))
	add(vsingle("manifest-is-symlink", "ListEntriesJSON", list("", vid, vaultArg),
		mutation{Op: "rename", Path: "manifest.age", Target: "manifest-real.age"}, mutation{Op: "symlink", Path: "manifest.age", Target: "manifest-real.age"}))

	// ---- VerifyManifestIntegrity ------------------------------------------
	verify := func(id, dir string) stepSpec {
		return fixed("VerifyManifestIntegrity", args(callArgs{VaultDir: dir, Identity: id}))
	}
	add(vsingle("intact", "VerifyManifestIntegrity", verify(vid, vaultArg)))
	add(vsingle("trim-identity", "VerifyManifestIntegrity", verify("\n"+vid+" ", vaultArg)))
	add(vsingle("tampered-entry", "VerifyManifestIntegrity", verify(vid, vaultArg), mutation{Op: "flip", Path: "entries/top.age", Offset: 100}))
	add(vsingle("tampered-entry-appended", "VerifyManifestIntegrity", verify(vid, vaultArg), mutation{Op: "write", Path: "entries/top.age", Text: "tampered"}))
	add(vsingle("missing-entry", "VerifyManifestIntegrity", verify(vid, vaultArg), mutation{Op: "remove", Path: "entries/work/aws.age"}))
	add(vsingle("unknown-extra-entry-still-true", "VerifyManifestIntegrity", verify(vid, vaultArg),
		mutation{Op: "write", Path: "entries/extra.age", B64: sd.X25519["hello"]}))
	add(vsingle("manifest-missing", "VerifyManifestIntegrity", verify(vid, vaultArg), mutation{Op: "remove", Path: "manifest.age"}))
	add(vsingle("manifest-junk", "VerifyManifestIntegrity", verify(vid, vaultArg), mutation{Op: "write", Path: "manifest.age", Text: "junk"}))
	add(vsingle("manifest-empty", "VerifyManifestIntegrity", verify(vid, vaultArg), mutation{Op: "write", Path: "manifest.age", Text: ""}))
	add(vsingle("manifest-truncated", "VerifyManifestIntegrity", verify(vid, vaultArg), mutation{Op: "truncate", Path: "manifest.age", Size: 80}))
	add(vsingle("manifest-flipped-payload", "VerifyManifestIntegrity", verify(vid, vaultArg), mutation{Op: "flip", Path: "manifest.age", Offset: 200}))
	add(vsingle("manifest-is-directory", "VerifyManifestIntegrity", verify(vid, vaultArg),
		mutation{Op: "remove", Path: "manifest.age"}, mutation{Op: "mkdir", Path: "manifest.age"}))
	add(vsingle("manifest-valid-other-identity", "VerifyManifestIntegrity", verify(id2, vaultArg)))
	add(vsingle("missing-dir", "VerifyManifestIntegrity", verify(vid, "$ROOT/missing")))
	add(vsingle("dir-is-file", "VerifyManifestIntegrity", verify(vid, "$ROOT/vault/identity.age")))
	add(vsingle("dir-traversal-not-rejected", "VerifyManifestIntegrity", verify(vid, "$ROOT/vault/../vault")))
	for _, m := range identityMutations(id1)[:8] {
		add(vsingle("bad-identity-"+m.Name, "VerifyManifestIntegrity", verify(m.Value, vaultArg)))
	}
	add(vsingle("config-junk", "VerifyManifestIntegrity", verify(vid, vaultArg), mutation{Op: "write", Path: "config.yaml", Text: "vault: [unclosed\n"}))
	add(vsingle("entries-dir-missing", "VerifyManifestIntegrity", verify(vid, vaultArg), mutation{Op: "remove", Path: "entries"}))

	add(vsingle("config-missing", "VerifyManifestIntegrity", verify(vid, vaultArg), rmConfig))
	add(vsingle("config-missing-tampered-entry", "VerifyManifestIntegrity", verify(vid, vaultArg), rmConfig, mutation{Op: "flip", Path: "entries/top.age", Offset: 100}))
	add(vsingle("config-missing-manifest-missing", "VerifyManifestIntegrity", verify(vid, vaultArg), rmConfig, mutation{Op: "remove", Path: "manifest.age"}))
	add(vsingle("config-empty", "VerifyManifestIntegrity", verify(vid, vaultArg), mutation{Op: "write", Path: "config.yaml", Text: ""}))
	add(vsingle("config-is-directory", "VerifyManifestIntegrity", verify(vid, vaultArg), rmConfig, mutation{Op: "mkdir", Path: "config.yaml"}))
	add(vsingle("config-missing-identity-file-missing", "VerifyManifestIntegrity", verify(vid, vaultArg), rmConfig, mutation{Op: "remove", Path: "identity.age"}))
	add(vsingle("identity-file-missing", "VerifyManifestIntegrity", verify(vid, vaultArg), mutation{Op: "remove", Path: "identity.age"}))
	add(vsingle("manifest-is-symlink", "VerifyManifestIntegrity", verify(vid, vaultArg),
		mutation{Op: "rename", Path: "manifest.age", Target: "manifest-real.age"}, mutation{Op: "symlink", Path: "manifest.age", Target: "manifest-real.age"}))
	add(vsingle("manifest-is-dangling-symlink", "VerifyManifestIntegrity", verify(vid, vaultArg),
		mutation{Op: "remove", Path: "manifest.age"}, mutation{Op: "symlink", Path: "manifest.age", Target: "nowhere.age"}))
	add(vsingle("entry-is-symlink", "VerifyManifestIntegrity", verify(vid, vaultArg),
		mutation{Op: "rename", Path: "entries/top.age", Target: "entries/top-real.age"}, mutation{Op: "symlink", Path: "entries/top.age", Target: "top-real.age"}))
	// Go verifies the manifest entries in map order, so only a symlink that
	// affects exactly one entry has a deterministic first failure.
	add(vsingle("entries-subdir-is-symlink", "VerifyManifestIntegrity", verify(vid, vaultArg),
		mutation{Op: "rename", Path: "entries/notes", Target: "entries/notes-real"}, mutation{Op: "symlink", Path: "entries/notes", Target: "notes-real"}))

	return cs
}

func strp(s string) *string { return &s }
