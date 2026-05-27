package vault

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"filippo.io/age"

	vaultcrypto "github.com/danieljustus/symaira-vault/internal/crypto"
	"github.com/danieljustus/symaira-vault/internal/fsutil"
)

func BenchmarkReencryptAll(b *testing.B) {
	tmpDir := b.TempDir()
	entriesDir := filepath.Join(tmpDir, "entries")
	if err := os.MkdirAll(entriesDir, 0o700); err != nil {
		b.Fatalf("mkdir entries: %v", err)
	}

	identity, err := vaultcrypto.GenerateIdentity()
	if err != nil {
		b.Fatalf("generate identity: %v", err)
	}

	for i := 0; i < 50; i++ {
		entry := &Entry{
			Path: fmt.Sprintf("test%d", i),
			Data: map[string]any{
				"password": "secret-password-value-here",
			},
		}

		plaintext, err := entry.MarshalJSON()
		if err != nil {
			b.Fatalf("marshal entry: %v", err)
		}

		ciphertext, err := vaultcrypto.Encrypt(plaintext, identity.Recipient())
		if err != nil {
			b.Fatalf("encrypt: %v", err)
		}

		filePath := filepath.Join(entriesDir, fmt.Sprintf("test%d.age", i))
		if err := fsutil.AtomicWriteFile(filePath, ciphertext, 0o600); err != nil {
			b.Fatalf("write file: %v", err)
		}
	}

	recipient := identity.Recipient()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := ReencryptAll(tmpDir, identity, []*age.X25519Recipient{recipient}); err != nil {
			b.Fatalf("reencrypt: %v", err)
		}
	}
}
