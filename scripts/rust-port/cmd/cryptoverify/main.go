// Command cryptoverify decrypts Rust-produced vectors with the Go oracle.
package main

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"os"
	"strings"

	"filippo.io/age"

	cryptopkg "github.com/danieljustus/symaira-vault/internal/crypto"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: cryptoverify <rust-output>")
		os.Exit(2)
	}
	values := map[string]string{}
	file, err := os.Open(os.Args[1])
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
	passphrase := []byte("rust-interop-fixture-passphrase-v1")
	ageCipher := decode(values, "age")
	plain, err := cryptopkg.Decrypt(ageCipher, id)
	if err != nil || string(plain) != "Rust encrypts age for Go" {
		panic("Go could not decrypt Rust age vector")
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
	fmt.Println("PASS Rust encrypt -> Go decrypt (age, scrypt, argon2id)")
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
