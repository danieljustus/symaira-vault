package vault

import (
	"errors"
	"sort"
	"sync"
	"time"

	"filippo.io/age"
)

const (
	maxActiveVaultReads          = 4
	maxPendingVaultReads         = 32
	vaultReadWait                = 10 * time.Second
	maxVaultBatchCiphertextBytes = 256 * 1024 * 1024
	maxVaultPathBytes            = 8 * 1024 * 1024
	maxPseudonymCacheBytes       = 16 * 1024 * 1024
	maxSearchIndexPlaintextBytes = 8 * 1024 * 1024
)

var ErrVaultResourceBusy = errors.New("vault resources are busy")

type readAdmission struct {
	mu              sync.Mutex
	active, pending int
	changed         chan struct{}
}

var vaultReadAdmission = readAdmission{changed: make(chan struct{})}

// A lease covers file allocation, decryption and decoding. The nominal payload
// reservation is 64 MiB per operation; returned objects remain caller-owned.
func (a *readAdmission) acquire() (func(), error) {
	a.mu.Lock()
	if a.active < maxActiveVaultReads {
		a.active++
		a.mu.Unlock()
		return a.releaseOnce(), nil
	}
	if a.pending >= maxPendingVaultReads {
		a.mu.Unlock()
		return nil, ErrVaultResourceBusy
	}
	a.pending++
	deadline := time.Now().Add(vaultReadWait)
	timer := time.NewTimer(vaultReadWait)
	defer timer.Stop()
	for {
		changed := a.changed
		a.mu.Unlock()
		select {
		case <-timer.C:
			a.mu.Lock()
			a.pending--
			a.mu.Unlock()
			return nil, ErrVaultResourceBusy
		case <-changed:
			a.mu.Lock()
			if !time.Now().Before(deadline) {
				a.pending--
				a.mu.Unlock()
				return nil, ErrVaultResourceBusy
			}
			if a.active < maxActiveVaultReads {
				a.pending--
				a.active++
				a.mu.Unlock()
				return a.releaseOnce(), nil
			}
		}
	}
}

func (a *readAdmission) releaseOnce() func() {
	var once sync.Once
	return func() {
		once.Do(func() {
			a.mu.Lock()
			a.active--
			close(a.changed)
			a.changed = make(chan struct{})
			a.mu.Unlock()
		})
	}
}

type vaultReadBatch struct {
	mu              sync.Mutex
	ciphertextBytes int
	decodedBytes    int
	failed          bool
}

func (b *vaultReadBatch) consume(size int) error {
	if b == nil {
		return nil
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.failed || size < 0 || size > maxVaultBatchCiphertextBytes-b.ciphertextBytes {
		b.failed = true
		return ErrVaultResourceLimit
	}
	b.ciphertextBytes += size
	return nil
}

func addVaultPathBytes(total *int, path string) error {
	if len(path) > maxVaultPathBytes-*total {
		return ErrVaultResourceLimit
	}
	*total += len(path)
	return nil
}

func (b *vaultReadBatch) fail() {
	if b != nil {
		b.mu.Lock()
		b.failed = true
		b.mu.Unlock()
	}
}

// Charge conservative node/string retention before materializing a batch entry.
func (b *vaultReadBatch) consumeDecoded(size int) error {
	if b == nil {
		return nil
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.failed || size < 0 || size > maxVaultBatchCiphertextBytes-b.decodedBytes {
		b.failed = true
		return ErrVaultResourceLimit
	}
	b.decodedBytes += size
	return nil
}

// ReadSession is the bounded allowance for one multi-entry operation.
// Its methods are safe to share across the operation's worker pool.
type ReadSession struct {
	vaultDir string
	identity *age.X25519Identity
	batch    vaultReadBatch
}

func NewReadSession(vaultDir string, identity *age.X25519Identity) *ReadSession {
	return &ReadSession{vaultDir: vaultDir, identity: identity}
}

func (s *ReadSession) List(prefix string) ([]string, error) {
	if err := s.batch.consume(0); err != nil {
		return nil, err
	}
	return listWithBudget(s.vaultDir, prefix, s.identity, &s.batch)
}

func (s *ReadSession) Get(path string) (*Entry, error) {
	return readEntryInner(s.vaultDir, path, s.identity, nil, &s.batch)
}

// EntryFiles enumerates physical entry files without resetting this allowance.
func (s *ReadSession) EntryFiles() ([]string, error) {
	if err := s.batch.consume(0); err != nil {
		return nil, err
	}
	files, err := pseudonymizedEntryFiles(s.vaultDir)
	if err != nil {
		s.batch.fail()
		return nil, err
	}
	sort.Strings(files)
	return files, nil
}

func (s *ReadSession) GetFile(path string) (*Entry, error) {
	return readEntryFileWithBudget(s.identity, func(batch *vaultReadBatch) ([]byte, error) {
		return readVaultEntryBounded(s.vaultDir, path, batch)
	}, &s.batch)
}
