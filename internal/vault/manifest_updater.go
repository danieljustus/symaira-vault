package vault

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"sync"
	"time"

	"filippo.io/age"
)

// manifestOpType categorizes queued manifest operations.
type manifestOpType int

const (
	manifestOpUpdate manifestOpType = iota
	manifestOpRemove
	manifestOpFlush
)

// manifestOp represents a single queued manifest operation serialized through
// the worker goroutine. For manifestOpUpdate and manifestOpRemove the done
// channel is nil — these are fire-and-forget. For manifestOpFlush the done
// channel is non-nil and the caller blocks until the flush completes.
type manifestOp struct {
	opType     manifestOpType
	vaultDir   string
	path       string
	ciphertext []byte
	identity   *age.X25519Identity
	done       chan error
}

var (
	manifestCh     chan manifestOp
	manifestChOnce sync.Once
)

// manifestFlushInterval is the debounce window for batching manifest writes.
// Every update/remove operation resets this timer. When the timer fires all
// accumulated changes for the affected vault are flushed in a single read-
// modify-write cycle.
const manifestFlushInterval = 200 * time.Millisecond

// pendingVaultState tracks accumulated manifest changes for a single vault
// directory. All fields are accessed only from the worker goroutine.
type pendingVaultState struct {
	updates  map[string][]byte   // path -> ciphertext
	removes  map[string]bool     // path -> true
	identity *age.X25519Identity // identity used for manifest crypto
	timer    *time.Timer         // debounce timer (nil when idle)
}

// startManifestWorker launches the background goroutine that serializes all
// manifest read-modify-write cycles. The worker accumulates changes and
// flushes them in batches:
//
//   - manifestOpUpdate / manifestOpRemove update the in-memory dirty state
//     and reset a per-vault debounce timer. The caller does NOT block.
//   - When the debounce timer fires, a single load-modify-write cycle applies
//     all pending changes for that vault dir.
//   - manifestOpFlush (with a done channel) triggers an immediate synchronous
//     flush of all vault dirs. Used by FlushManifestUpdates().
//
// The caller MUST release the write lock before sending any operation.
func startManifestWorker() {
	manifestCh = make(chan manifestOp, 256)
	go func() {
		pending := make(map[string]*pendingVaultState)

		// flushVault applies all accumulated changes for one vault dir in a
		// single load-decrypt-modify-marshal-encrypt-write cycle.
		flushVault := func(vaultDir string) {
			pv, ok := pending[vaultDir]
			if !ok {
				return
			}
			// Remove before we process to prevent re-triggers from timer.
			delete(pending, vaultDir)
			if pv.timer != nil {
				pv.timer.Stop()
				pv.timer = nil
			}

			if len(pv.updates) == 0 && len(pv.removes) == 0 {
				return
			}

			m, err := LoadManifest(vaultDir, pv.identity)
			if err != nil {
				if !os.IsNotExist(err) {
					return // best-effort; manifest will be rebuilt on next Open()
				}
				m = &Manifest{
					Version: 1,
					Created: time.Now().UTC(),
					Entries: make(map[string]ManifestEntry),
				}
			}

			now := time.Now().UTC()
			for path, ciphertext := range pv.updates {
				hash := sha256.Sum256(ciphertext)
				m.Entries[path] = ManifestEntry{
					SHA256: hex.EncodeToString(hash[:]),
					Size:   int64(len(ciphertext)),
					MTime:  now,
				}
			}
			for path := range pv.removes {
				delete(m.Entries, path)
			}

			_ = writeManifest(vaultDir, m, pv.identity)
		}

		// flushAll flushes every vault that has pending changes.
		flushAll := func() {
			for vaultDir := range pending {
				flushVault(vaultDir)
			}
		}

		// scheduleFlush resets the debounce timer for a vault dir.
		scheduleFlush := func(vaultDir string, pv *pendingVaultState) {
			if pv.timer != nil {
				pv.timer.Stop()
			}
			pv.timer = time.AfterFunc(manifestFlushInterval, func() {
				manifestCh <- manifestOp{
					opType:   manifestOpFlush,
					vaultDir: vaultDir,
				}
			})
		}

		for op := range manifestCh {
			switch op.opType {
			case manifestOpUpdate:
				pv, ok := pending[op.vaultDir]
				if !ok {
					pv = &pendingVaultState{
						updates:  make(map[string][]byte),
						removes:  make(map[string]bool),
						identity: op.identity,
					}
					pending[op.vaultDir] = pv
				}
				// If the path was pending removal, cancel it.
				delete(pv.removes, op.path)
				pv.updates[op.path] = op.ciphertext
				scheduleFlush(op.vaultDir, pv)

				if op.done != nil {
					op.done <- nil
					close(op.done)
				}

			case manifestOpRemove:
				pv, ok := pending[op.vaultDir]
				if !ok {
					pv = &pendingVaultState{
						updates:  make(map[string][]byte),
						removes:  make(map[string]bool),
						identity: op.identity,
					}
					pending[op.vaultDir] = pv
				}
				// Remove any pending update for this path.
				delete(pv.updates, op.path)
				pv.removes[op.path] = true
				scheduleFlush(op.vaultDir, pv)

				if op.done != nil {
					op.done <- nil
					close(op.done)
				}

			case manifestOpFlush:
				if op.vaultDir == "" {
					// Empty vaultDir means flush everything
					// (called from FlushManifestUpdates).
					flushAll()
				} else {
					flushVault(op.vaultDir)
				}
				if op.done != nil {
					op.done <- nil
					close(op.done)
				}
			}
		}
	}()
}

// queueManifestUpdate enqueues an entry update in the manifest. The update is
// batched with other pending changes and flushed asynchronously after a
// debounce interval. The caller MUST have written the entry file and released
// any write lock before calling this.
//
// Errors from the eventual manifest write are silently dropped — the entry
// file is already on disk and RebuildManifest will repair the manifest.
// Callers that need synchronous consistency should call FlushManifestUpdates.
func queueManifestUpdate(vaultDir, path string, ciphertext []byte, identity *age.X25519Identity) {
	manifestChOnce.Do(startManifestWorker)
	manifestCh <- manifestOp{
		opType:     manifestOpUpdate,
		vaultDir:   vaultDir,
		path:       path,
		ciphertext: ciphertext,
		identity:   identity,
	}
}

// queueManifestRemove enqueues an entry removal from the manifest. The update
// is batched with other pending changes and flushed asynchronously after a
// debounce interval. The caller MUST have removed the entry file and released
// any write lock before calling this.
//
// Errors from the eventual manifest write are silently dropped — the entry
// file is already gone and RebuildManifest will repair the manifest.
// Callers that need synchronous consistency should call FlushManifestUpdates.
func queueManifestRemove(vaultDir, path string, identity *age.X25519Identity) {
	manifestChOnce.Do(startManifestWorker)
	manifestCh <- manifestOp{
		opType:   manifestOpRemove,
		vaultDir: vaultDir,
		path:     path,
		identity: identity,
	}
}

// FlushManifestUpdates blocks until all previously queued manifest operations
// have completed. This is useful before clean shutdown, git operations, or
// when the manifest must be consistent before a subsequent critical operation.
//
// Note: unflushed manifest updates are recoverable via RebuildManifest, so
// it is safe to skip this call before an unclean shutdown.
func FlushManifestUpdates() {
	manifestChOnce.Do(startManifestWorker)
	done := make(chan error, 1)
	manifestCh <- manifestOp{
		opType: manifestOpFlush,
		done:   done,
	}
	<-done
}
