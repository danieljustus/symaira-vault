// Command cryptoverify decrypts Rust-produced vectors with the Go oracle.
package main

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"filippo.io/age"

	vaultconfig "github.com/danieljustus/symaira-vault/internal/config"
	cryptopkg "github.com/danieljustus/symaira-vault/internal/crypto"
	vaultpkg "github.com/danieljustus/symaira-vault/internal/vault"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: cryptoverify <rust-output>")
		os.Exit(2)
	}
	values := map[string]string{}
	file, err := os.Open(os.Args[1]) // #nosec G703 -- this local verifier reads only the explicitly selected fixture.
	if err != nil {
		panic(err)
	}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		parts := strings.SplitN(scanner.Text(), "=", 2)
		if len(parts) != 2 {
			closeFile(file)
			fmt.Fprintln(os.Stderr, "invalid vector line")
			os.Exit(1)
		}
		values[parts[0]] = parts[1]
	}
	closeFile(file)
	if err = scanner.Err(); err != nil {
		panic(err)
	}
	id, err := age.ParseX25519Identity("AGE-SECRET-KEY-1HS3YTK69EJH0ZYM8ANNNDWQMPT7ZMLPYGTMC47F5T4EDJ5N7EYMQ4L5CDL")
	if err != nil {
		panic(err)
	}
	id2, err := age.ParseX25519Identity("AGE-SECRET-KEY-18HD87KNMWKY3RW97YR2PYU6HGWDZXAGW6JF74LNNHUA6A8K5ZF9QTWUTK3")
	if err != nil {
		panic(err)
	}
	id3, err := age.ParseX25519Identity("AGE-SECRET-KEY-15KR576PHDPLRQS08427S6X2G492S6GTVELZ6WHN8AKMWW90T0HES2KQ597")
	if err != nil {
		panic(err)
	}
	passphrase := []byte("rust-interop-fixture-passphrase-v1")
	ageCipher := decode(values, "age")
	plain, err := cryptopkg.Decrypt(ageCipher, id)
	if err != nil || string(plain) != "Rust encrypts age for Go" {
		panic("Go could not decrypt Rust age vector")
	}
	reencryptCipher := decode(values, "reencrypt")
	for _, retained := range []*age.X25519Identity{id, id2} {
		plain, err = cryptopkg.Decrypt(reencryptCipher, retained)
		if err != nil || string(plain) != "Rust re-encrypts age for Go" {
			panic("Go could not decrypt Rust re-encryption vector for retained recipient")
		}
	}
	if _, err = cryptopkg.Decrypt(reencryptCipher, id3); err == nil {
		panic("Go decrypted Rust re-encryption vector for removed recipient")
	}

	// Exercise the Rust ciphertext through the real filesystem orchestration,
	// using only an isolated temporary vault and never a production path.
	fixtureDir, err := os.MkdirTemp("", "symvault-cryptoverify-reencrypt-all-")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(fixtureDir)
	cfg := vaultconfig.Default()
	cfg.VaultDir = fixtureDir
	if err := vaultpkg.Init(fixtureDir, id, cfg); err != nil {
		panic(err)
	}
	entryPath := filepath.Join(fixtureDir, "entries", "rust", "entry.age")
	if err := os.MkdirAll(filepath.Dir(entryPath), 0o700); err != nil {
		panic(err)
	}
	if err := os.WriteFile(entryPath, decode(values, "reencrypt_entry"), 0o600); err != nil {
		panic(err)
	}
	for _, retained := range []*age.X25519Identity{id, id2} {
		entry, err := vaultpkg.ReadEntry(fixtureDir, "rust/entry", retained)
		if err != nil || entry.Data["secret"] != "Rust filesystem entry" {
			panic("Go could not read Rust filesystem re-encryption fixture")
		}
	}
	if err := vaultpkg.ReencryptAll(fixtureDir, id, []*age.X25519Recipient{id.Recipient(), id3.Recipient()}); err != nil {
		panic(err)
	}
	for _, retained := range []*age.X25519Identity{id, id3} {
		entry, err := vaultpkg.ReadEntry(fixtureDir, "rust/entry", retained)
		if err != nil || entry.Data["secret"] != "Rust filesystem entry" {
			panic("Go ReencryptAll rejected Rust filesystem fixture")
		}
	}
	if _, err := vaultpkg.ReadEntry(fixtureDir, "rust/entry", id2); err == nil {
		panic("Go ReencryptAll retained removed Rust recipient")
	}

	scryptCipher := decode(values, "scrypt")
	plain, err = cryptopkg.DecryptWithPassphrase(scryptCipher, append([]byte(nil), passphrase...))
	if err != nil || string(plain) != "Rust encrypts scrypt for Go" {
		panic("Go could not decrypt Rust scrypt vector")
	}
	argonCipher := decode(values, "argon2id")
	plain, err = cryptopkg.DecryptWithPassphraseArgon2id(argonCipher, append([]byte(nil), passphrase...))
	if err != nil || string(plain) != "Rust encrypts argon2id for Go" {
		panic("Go could not decrypt Rust argon2id vector")
	}
	fmt.Println("PASS Rust encrypt -> Go decrypt (age, scrypt, argon2id, filesystem ReencryptAll)")
}

func closeFile(file *os.File) {
	if err := file.Close(); err != nil {
		panic(err)
	}
}

func decode(values map[string]string, key string) []byte {
	raw, ok := values[key]
	if !ok {
		panic("missing " + key)
	}
	out, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		panic(err)
	}
	return out
}
