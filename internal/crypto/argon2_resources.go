package crypto

import (
	"errors"
	"sync"
	"time"
)

// Argon2ResourcePolicyVersion names execution admission, not the wire format.
const Argon2ResourcePolicyVersion = "argon2-resources-v1"

const (
	AutomaticArgon2MaxTime    = 4
	AutomaticArgon2MaxMemory  = 128 * 1024
	AutomaticArgon2MaxThreads = 4
	argon2MemoryBudget        = 256 * 1024
	argon2MaxActive           = 4
	argon2MaxWaiters          = 32
	argon2AdmissionTimeout    = 10 * time.Second
	argon2MaxStanzas          = 4
)

var (
	ErrArgon2Policy    = errors.New("argon2id resource policy: use migrate kdf --allow-legacy-kdf for a historical identity")
	ErrArgon2Busy      = errors.New("argon2id resources busy")
	ErrArgon2Bounds    = errors.New("argon2id parameters out of bounds")
	ErrArgon2Malformed = errors.New("malformed argon2id stanza")
)

// IsArgon2ResourceError identifies failures which must never trigger recovery.
func IsArgon2ResourceError(err error) bool {
	return errors.Is(err, ErrArgon2Policy) || errors.Is(err, ErrArgon2Busy) ||
		errors.Is(err, ErrArgon2Bounds) || errors.Is(err, ErrArgon2Malformed)
}

func validateAutomaticArgon2(p Argon2idParams) error {
	if p.Time > AutomaticArgon2MaxTime || p.Memory > AutomaticArgon2MaxMemory ||
		p.Threads > AutomaticArgon2MaxThreads {
		return ErrArgon2Policy
	}
	return nil
}

func argon2EffectiveMemory(p Argon2idParams) uint32 {
	return max(p.Memory, 8*uint32(p.Threads))
}

type argon2Admission struct {
	mu      sync.Mutex
	changed chan struct{}
	memory  uint32
	active  int
	waiters int
	legacy  bool
}

var processArgon2Admission = argon2Admission{changed: make(chan struct{})}

func (a *argon2Admission) fits(memory uint32, legacy bool) bool {
	if legacy {
		return a.active == 0
	}
	return !a.legacy && a.active < argon2MaxActive && a.memory+memory <= argon2MemoryBudget
}

// acquire reserves before the allocation. Historical reads are exclusive;
// ordinary overload has a bounded number of waiters and a bounded deadline.
func (a *argon2Admission) acquire(memory uint32, legacy bool) (func(), error) {
	a.mu.Lock()
	if !a.fits(memory, legacy) {
		if a.waiters >= argon2MaxWaiters {
			a.mu.Unlock()
			return nil, ErrArgon2Busy
		}
		a.waiters++
		deadline := time.Now().Add(argon2AdmissionTimeout)
		timer := time.NewTimer(argon2AdmissionTimeout)
		defer timer.Stop()
		for !a.fits(memory, legacy) {
			changed := a.changed
			a.mu.Unlock()
			select {
			case <-changed:
				a.mu.Lock()
			case <-timer.C:
				a.mu.Lock()
				a.waiters--
				a.mu.Unlock()
				return nil, ErrArgon2Busy
			}
		}
		a.waiters--
		if !time.Now().Before(deadline) {
			a.mu.Unlock()
			return nil, ErrArgon2Busy
		}
	}
	a.memory += memory
	a.active++
	a.legacy = legacy
	a.mu.Unlock()
	return func() {
		a.mu.Lock()
		a.memory -= memory
		a.active--
		a.legacy = false
		close(a.changed)
		a.changed = make(chan struct{})
		a.mu.Unlock()
	}, nil
}
