package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/danieljustus/symaira-vault/pkg/mobilebind"
)

// callArgs carries the arguments of one pkg/mobilebind call. An absent field is
// the empty string, which is exactly what the Go API receives for "".
type callArgs struct {
	Identity      string `json:"identity,omitempty"`
	Recipient     string `json:"recipient,omitempty"`
	Pubkey        string `json:"pubkey,omitempty"`
	Passphrase    string `json:"passphrase,omitempty"`
	VaultDir      string `json:"vaultDir,omitempty"`
	EntryPath     string `json:"entryPath,omitempty"`
	EntryJSON     string `json:"entryJSON,omitempty"`
	Prefix        string `json:"prefix,omitempty"`
	PlaintextB64  string `json:"plaintext_b64,omitempty"`
	CiphertextB64 string `json:"ciphertext_b64,omitempty"`
	// PlaintextPattern, when positive, replaces PlaintextB64 by pattern(n).
	PlaintextPattern int `json:"plaintext_pattern_len,omitempty"`
	// CiphertextRef names a seed ciphertext ("x25519:chunk+"); CiphertextEdit
	// ("flip:N", "truncate:N") derives a malformed variant from it. They keep
	// the 64 KiB-chunk cases from inflating the fixture.
	CiphertextRef  string `json:"ciphertext_ref,omitempty"`
	CiphertextEdit string `json:"ciphertext_edit,omitempty"`
}

// curSeed resolves CiphertextRef; set once per run before any invoke.
var curSeed *seedData

func pattern(n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = byte(i % 251)
	}
	return out
}

func (a callArgs) plaintext() []byte {
	if a.PlaintextPattern > 0 {
		return pattern(a.PlaintextPattern)
	}
	return decodeB64(a.PlaintextB64)
}

func (a callArgs) ciphertext() []byte {
	if a.CiphertextRef == "" {
		return decodeB64(a.CiphertextB64)
	}
	kind, name, _ := strings.Cut(a.CiphertextRef, ":")
	src := curSeed.X25519
	if kind == "scrypt" {
		src = curSeed.Scrypt
	}
	data := decodeB64(src[name])
	if a.CiphertextEdit != "" {
		op, arg, _ := strings.Cut(a.CiphertextEdit, ":")
		var n int
		fmt.Sscanf(arg, "%d", &n)
		switch op {
		case "flip":
			data[n] ^= 0x80
		case "truncate":
			data = data[:n]
		default:
			panic("bad edit " + a.CiphertextEdit)
		}
	}
	return data
}

// functions is the complete pkg/mobilebind export surface, in source order.
var functions = []string{
	"GenerateIdentity", "IdentityPublicKey", "PublicKeyFingerprint",
	"EncryptWithPublicKey", "DecryptWithIdentity",
	"EncryptWithPassphrase", "DecryptWithPassphrase",
	"InitVault", "OpenVaultWithPassphrase",
	"ReadEntryJSON", "WriteEntryJSON", "ListEntriesJSON", "VerifyManifestIntegrity",
}

// observation is the raw result of one call.
type observation struct {
	kind  string // "string", "bytes", "bool" or "none"
	str   string
	data  []byte
	flag  bool
	err   error
	input callArgs
}

func decodeB64(s string) []byte {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		panic(fmt.Sprintf("bad base64 %q: %v", s, err))
	}
	return b
}

// invoke runs the real Go function. This is the only place the oracle is called.
func invoke(fn string, a callArgs) observation {
	o := observation{input: a}
	switch fn {
	case "GenerateIdentity":
		o.kind = "string"
		o.str, o.err = mobilebind.GenerateIdentity()
	case "IdentityPublicKey":
		o.kind = "string"
		o.str, o.err = mobilebind.IdentityPublicKey(a.Identity)
	case "PublicKeyFingerprint":
		o.kind = "string"
		o.str = mobilebind.PublicKeyFingerprint(a.Pubkey)
	case "EncryptWithPublicKey":
		o.kind = "bytes"
		o.data, o.err = mobilebind.EncryptWithPublicKey(a.Recipient, a.plaintext())
	case "DecryptWithIdentity":
		o.kind = "bytes"
		o.data, o.err = mobilebind.DecryptWithIdentity(a.Identity, a.ciphertext())
	case "EncryptWithPassphrase":
		o.kind = "bytes"
		o.data, o.err = mobilebind.EncryptWithPassphrase(a.Passphrase, a.plaintext())
	case "DecryptWithPassphrase":
		o.kind = "bytes"
		o.data, o.err = mobilebind.DecryptWithPassphrase(a.Passphrase, a.ciphertext())
	case "InitVault":
		o.kind = "none"
		o.err = mobilebind.InitVault(a.VaultDir, a.Passphrase)
	case "OpenVaultWithPassphrase":
		o.kind = "string"
		o.str, o.err = mobilebind.OpenVaultWithPassphrase(a.VaultDir, a.Passphrase)
	case "ReadEntryJSON":
		o.kind = "string"
		o.str, o.err = mobilebind.ReadEntryJSON(a.VaultDir, a.EntryPath, a.Identity)
	case "WriteEntryJSON":
		o.kind = "none"
		o.err = mobilebind.WriteEntryJSON(a.VaultDir, a.EntryPath, a.EntryJSON, a.Identity)
	case "ListEntriesJSON":
		o.kind = "string"
		o.str, o.err = mobilebind.ListEntriesJSON(a.VaultDir, a.Prefix, a.Identity)
	case "VerifyManifestIntegrity":
		o.kind = "bool"
		o.flag, o.err = mobilebind.VerifyManifestIntegrity(a.VaultDir, a.Identity)
	default:
		panic("unknown function " + fn)
	}
	return o
}

// shape describes an output that is random by construction (fresh identities,
// ciphertexts). It is verified structurally and by a round trip through the
// matching inverse function instead of by bytes.
type shape struct {
	StringPrefix   string    `json:"string_prefix,omitempty"`
	StringCharset  string    `json:"string_charset,omitempty"`
	BytesPrefixB64 string    `json:"bytes_prefix_b64,omitempty"`
	Length         int       `json:"length"`
	Roundtrip      *stepSpec `json:"roundtrip,omitempty"`
	RoundtripWant  *want     `json:"roundtrip_want,omitempty"`
	Distinct       bool      `json:"distinct_across_calls,omitempty"`
	// ScryptWorkFactor pins the work factor in the passphrase stanza header.
	ScryptWorkFactor int `json:"scrypt_work_factor,omitempty"`
}

// want is the recorded expectation for one call.
type want struct {
	OK       bool    `json:"ok"`
	String   *string `json:"string,omitempty"`
	BytesB64 *string `json:"bytes_b64,omitempty"`
	// Large byte results are recorded as length and digest.
	BytesLen    *int   `json:"bytes_len,omitempty"`
	BytesSHA256 string `json:"bytes_sha256,omitempty"`
	Bool        *bool  `json:"bool,omitempty"`
	Error       string `json:"error,omitempty"`
	Shape       *shape `json:"shape,omitempty"`
}

// stepSpec is one call plus its expectation. In a Roundtrip, the token
// "$OUT" in identity/pubkey/recipient or ciphertext_b64 names the produced value.
type stepSpec struct {
	Function  string   `json:"function"`
	Args      callArgs `json:"args"`
	Normalize []string `json:"normalize,omitempty"`
	Want      want     `json:"want"`
}

const outToken = "$OUT"

var (
	rfc3339 = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,9})?Z$`)
	bech32U = regexp.MustCompile(`^[A-Z0-9]+$`)
	bech32L = regexp.MustCompile(`^[a-z0-9]+$`)
)

// normalizeTimestamps replaces meta.created/updated of a marshalled entry with a
// token, but only when the value has the shipped RFC 3339 UTC spelling.
func normalizeTimestamps(s string) string {
	var doc map[string]json.RawMessage
	if err := json.Unmarshal([]byte(s), &doc); err != nil {
		return s
	}
	metaRaw, ok := doc["meta"]
	if !ok {
		return s
	}
	var meta map[string]json.RawMessage
	if json.Unmarshal(metaRaw, &meta) != nil {
		return s
	}
	for _, key := range []string{"created", "updated"} {
		var v string
		if raw, ok := meta[key]; ok && json.Unmarshal(raw, &v) == nil && rfc3339.MatchString(v) {
			s = strings.Replace(s, `"`+key+`":"`+v+`"`, `"`+key+`":"<TIMESTAMP>"`, 1)
		}
	}
	return s
}

func normalizePaths(s, root string) string {
	if root == "" {
		return s
	}
	for _, r := range []string{root, "/private" + root} {
		s = strings.ReplaceAll(s, r, "$ROOT")
	}
	return s
}

// record converts an observation into the recorded expectation.
func record(o observation, root string, normalize []string) want {
	if o.err != nil {
		return want{Error: normalizePaths(o.err.Error(), root)}
	}
	w := want{OK: true}
	switch o.kind {
	case "string":
		s := normalizePaths(o.str, root)
		for _, n := range normalize {
			if n == "timestamps" {
				s = normalizeTimestamps(s)
			}
		}
		w.String = &s
	case "bytes":
		return wantBytes(o.data)
	case "bool":
		b := o.flag
		w.Bool = &b
	}
	return w
}

func wantBytes(data []byte) want {
	if len(data) > 4096 {
		n := len(data)
		sum := sha256.Sum256(data)
		return want{OK: true, BytesLen: &n, BytesSHA256: hex.EncodeToString(sum[:])}
	}
	s := base64.StdEncoding.EncodeToString(data)
	return want{OK: true, BytesB64: &s}
}

func expandArgs(a callArgs, root string) callArgs {
	r := func(s string) string { return strings.ReplaceAll(s, "$ROOT", root) }
	a.VaultDir = r(a.VaultDir)
	return a
}

// mutation edits the materialised vault before a case runs.
type mutation struct {
	Op     string `json:"op"` // remove, write, flip, truncate, mkdir, symlink
	Path   string `json:"path"`
	Text   string `json:"text,omitempty"`
	B64    string `json:"b64,omitempty"`
	Offset int    `json:"offset,omitempty"`
	Size   int    `json:"size,omitempty"`
	Target string `json:"target,omitempty"`
}

func applyMutation(vaultDir string, m mutation) error {
	target := filepath.Join(vaultDir, filepath.FromSlash(m.Path))
	switch m.Op {
	case "remove":
		return os.RemoveAll(target)
	case "write":
		data := []byte(m.Text)
		if m.B64 != "" {
			data = decodeB64(m.B64)
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
			return err
		}
		return os.WriteFile(target, data, 0o600)
	case "flip":
		data, err := os.ReadFile(target)
		if err != nil {
			return err
		}
		data[m.Offset] ^= 0x01
		return os.WriteFile(target, data, 0o600)
	case "truncate":
		return os.Truncate(target, int64(m.Size))
	case "mkdir":
		return os.MkdirAll(target, 0o700)
	case "symlink":
		_ = os.Remove(target)
		return os.Symlink(m.Target, target)
	}
	return fmt.Errorf("unknown mutation %q", m.Op)
}

// vaultFile is one file of the frozen Go-written seed vault.
type vaultFile struct {
	Path string `json:"path"`
	Mode uint32 `json:"mode"`
	Dir  bool   `json:"dir,omitempty"`
	B64  string `json:"b64,omitempty"`
}

// materialize writes seed files below dir, replacing the placeholder root.
func materialize(files []vaultFile, dir, root string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	for _, f := range files {
		target := filepath.Join(dir, filepath.FromSlash(f.Path))
		if f.Dir {
			if err := os.MkdirAll(target, os.FileMode(f.Mode)); err != nil {
				return err
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
			return err
		}
		data := bytes.ReplaceAll(decodeB64(f.B64), []byte("$ROOT"), []byte(root))
		if err := os.WriteFile(target, data, os.FileMode(f.Mode)); err != nil {
			return err
		}
	}
	return nil
}

// afterSpec snapshots paths below the vault directory after the steps ran.
type afterSpec struct {
	Tree  []string             `json:"tree,omitempty"`
	Files map[string]fileState `json:"files,omitempty"`
}

type fileState struct {
	Dir  bool    `json:"dir,omitempty"`
	Mode uint32  `json:"mode"`
	Text *string `json:"text,omitempty"`
	Size int     `json:"size,omitempty"`
}

func snapshotAfter(vaultDir, root string, paths []string, wantTree bool, textPaths map[string]bool) (afterSpec, error) {
	out := afterSpec{Files: map[string]fileState{}}
	if wantTree {
		err := filepath.WalkDir(vaultDir, func(p string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if p == vaultDir {
				return nil
			}
			rel, _ := filepath.Rel(vaultDir, p)
			out.Tree = append(out.Tree, filepath.ToSlash(rel))
			return nil
		})
		if err != nil {
			return out, err
		}
	}
	for _, rel := range paths {
		info, err := os.Stat(filepath.Join(vaultDir, filepath.FromSlash(rel)))
		if err != nil {
			return out, err
		}
		st := fileState{Dir: info.IsDir(), Mode: uint32(info.Mode().Perm())}
		if !info.IsDir() {
			st.Size = int(info.Size())
			if textPaths[rel] {
				data, err := os.ReadFile(filepath.Join(vaultDir, filepath.FromSlash(rel)))
				if err != nil {
					return out, err
				}
				s := normalizePaths(string(data), root)
				st.Text = &s
				st.Size = 0
			} else {
				st.Size = 0 // size of an encrypted file is not a contract
			}
		}
		out.Files[rel] = st
	}
	return out, nil
}
