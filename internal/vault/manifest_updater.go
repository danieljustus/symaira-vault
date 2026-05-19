package vault

import (
	"sync"

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
// the worker goroutine. The done channel is closed when the operation completes.
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

// startManifestWorker launches the background goroutine that serializes all
// manifest read-modify-write cycles. Callers send operations and wait on the
// done channel; the lock is released by the caller before sending.
func startManifestWorker() {
	manifestCh = make(chan manifestOp, 256)
	go func() {
		for op := range manifestCh {
			var err error
			switch op.opType {
			case manifestOpUpdate:
				err = UpdateManifestEntry(op.vaultDir, op.path, op.ciphertext, op.identity)
			case manifestOpRemove:
				err = RemoveManifestEntry(op.vaultDir, op.path, op.identity)
			case manifestOpFlush:
			}
			if op.done != nil {
				op.done <- err
				close(op.done)
			}
		}
	}()
}

// queueManifestUpdate enqueues an entry update in the manifest and waits for
// completion. The caller MUST have written the entry file and released any
// write lock before calling this.
func queueManifestUpdate(vaultDir, path string, ciphertext []byte, identity *age.X25519Identity) error {
	manifestChOnce.Do(startManifestWorker)
	done := make(chan error, 1)
	manifestCh <- manifestOp{
		opType:     manifestOpUpdate,
		vaultDir:   vaultDir,
		path:       path,
		ciphertext: ciphertext,
		identity:   identity,
		done:       done,
	}
	return <-done
}

// queueManifestRemove enqueues an entry removal from the manifest and waits
// for completion. The caller MUST have removed the entry file and released any
// write lock before calling this.
func queueManifestRemove(vaultDir, path string, identity *age.X25519Identity) error {
	manifestChOnce.Do(startManifestWorker)
	done := make(chan error, 1)
	manifestCh <- manifestOp{
		opType:   manifestOpRemove,
		vaultDir: vaultDir,
		path:     path,
		identity: identity,
		done:     done,
	}
	return <-done
}

// FlushManifestUpdates blocks until all previously queued manifest operations
// have completed. This is useful before clean shutdown.
func FlushManifestUpdates() {
	manifestChOnce.Do(startManifestWorker)
	done := make(chan error, 1)
	manifestCh <- manifestOp{
		opType: manifestOpFlush,
		done:   done,
	}
	<-done
}
