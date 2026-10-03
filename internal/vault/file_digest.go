package vault

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"time"
)

// Hash an opened root-relative descriptor, keeping its metadata and digest
// together when the path is concurrently replaced. No file-sized buffer.
func hashVaultEntry(vaultDir, filePath string, batch *vaultReadBatch) (string, int64, time.Time, error) {
	if err := batch.consume(0); err != nil {
		return "", 0, time.Time{}, err
	}
	release, err := vaultReadAdmission.acquire()
	if err != nil {
		return "", 0, time.Time{}, err
	}
	defer release()
	relative, err := filepath.Rel(vaultDir, filePath)
	if err != nil {
		return "", 0, time.Time{}, err
	}
	var digest string
	var size int64
	var mtime time.Time
	err = withRootedFile(vaultDir, relative, func(file *os.File, path string) error {
		info, statErr := file.Stat()
		if statErr != nil {
			return statErr
		}
		if !info.Mode().IsRegular() {
			return ErrVaultResourceLimit
		}
		if info.Size() > maxEntryCiphertextBytesV1 {
			batch.fail()
			return errEntryReadLimit
		}
		if budgetErr := batch.consume(int(info.Size())); budgetErr != nil {
			return budgetErr
		}
		hash := sha256.New()
		readLimit := int64(maxEntryCiphertextBytesV1)
		if batch != nil {
			readLimit = info.Size()
		}
		size, err = io.CopyBuffer(hash, io.LimitReader(file, readLimit+1), make([]byte, 32*1024))
		if err != nil {
			return err
		}
		if size > readLimit {
			batch.fail()
			return errEntryReadLimit
		}
		if size > info.Size() {
			if budgetErr := batch.consume(int(size - info.Size())); budgetErr != nil {
				return budgetErr
			}
		}
		mtime = info.ModTime()
		digest = hex.EncodeToString(hash.Sum(nil))
		return nil
	})
	return digest, size, mtime, err
}
