package vault

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"filippo.io/age"

	vaultcrypto "github.com/danieljustus/OpenPass/internal/crypto"
	"github.com/danieljustus/OpenPass/internal/fileutil"
)

const defaultReencryptWorkers = 4

type reencryptTask struct {
	path string
}

type reencryptResult struct {
	path string
	err  error
}

// ReencryptAll walks all .age files in the entries/ directory (recursively),
// decrypts each with the provided identity, re-encrypts with all recipients,
// and writes them back using atomic writes. Progress is printed to stderr.
// Entries are processed in parallel using a bounded worker pool (default 4).
// Returns an error if any file fails.
func ReencryptAll(vaultDir string, identity *age.X25519Identity, recipients []*age.X25519Recipient) error {
	if identity == nil {
		return ErrNilIdentity
	}
	if len(recipients) == 0 {
		return fmt.Errorf("no recipients provided for re-encryption")
	}

	entriesPath := entriesDir(vaultDir)

	type entryFile struct {
		fullPath string
	}
	var files []entryFile

	err := filepath.Walk(entriesPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		if strings.EqualFold(filepath.Ext(info.Name()), ".age") {
			files = append(files, entryFile{fullPath: path})
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("walk entries directory: %w", err)
	}

	if len(files) == 0 {
		return nil
	}

	workers := defaultReencryptWorkers
	if len(files) < workers {
		workers = len(files)
	}

	taskCh := make(chan reencryptTask, len(files))
	resultCh := make(chan reencryptResult, len(files))

	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for task := range taskCh {
				err := reencryptFile(vaultDir, task.path, identity, recipients)
				resultCh <- reencryptResult{path: task.path, err: err}
			}
		}()
	}

	go func() {
		for _, f := range files {
			taskCh <- reencryptTask{path: f.fullPath}
		}
		close(taskCh)
	}()

	go func() {
		wg.Wait()
		close(resultCh)
	}()

	var i int
	for result := range resultCh {
		i++
		fmt.Fprintf(os.Stderr, "Re-encrypting %d/%d...\r", i, len(files))
		if result.err != nil {
			return fmt.Errorf("re-encrypt %s: %w", result.path, result.err)
		}
	}

	if err := RebuildManifest(vaultDir, identity); err != nil {
		return fmt.Errorf("rebuild manifest: %w", err)
	}

	fmt.Fprintf(os.Stderr, "\nRe-encrypted %d entries successfully.\n", len(files))
	return nil
}

// reencryptFile decrypts a single .age file with the identity and re-encrypts
// it with all recipients using an atomic write.
func reencryptFile(vaultDir string, path string, identity *age.X25519Identity, recipients []*age.X25519Recipient) error {
	// #nosec G304 -- path is a .age file within the vault directory passed to the function
	raw, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read file: %w", err)
	}

	plaintext, err := vaultcrypto.Decrypt(raw, identity)
	if err != nil {
		return fmt.Errorf("decrypt: %w", err)
	}
	defer vaultcrypto.Wipe(plaintext)

	ciphertext, err := vaultcrypto.EncryptWithRecipients(plaintext, recipients...)
	if err != nil {
		return fmt.Errorf("encrypt: %w", err)
	}

	if err := fileutil.AtomicWriteFile(path, ciphertext, 0o600); err != nil {
		return fmt.Errorf("atomic write: %w", err)
	}

	return nil
}
