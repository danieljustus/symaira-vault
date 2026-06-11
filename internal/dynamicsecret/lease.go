package dynamicsecret

import (
	"context"
	"errors"
	"sync"
	"time"
)

// Lease represents a leased secret with TTL tracking.
type Lease struct {
	ID        string
	Secret    *Secret
	ExpiresAt time.Time
	Revoked   bool
	CreatedAt time.Time
}

// Engine defines the interface for engine-specific revoke operations.
type Engine interface {
	Revoke(ctx context.Context, leaseID string) error
}

// LeaseManager tracks active leases and handles lifecycle operations.
type LeaseManager struct {
	mu        sync.RWMutex
	leases    map[string]*Lease
	engine    Engine
	cleanupCh chan struct{}
	closed    bool
}

// ErrLeaseNotFound is returned when a lease ID does not match any known lease.
var ErrLeaseNotFound = errors.New("lease not found")

// NewLeaseManager creates a new lease manager.
func NewLeaseManager() *LeaseManager {
	return &LeaseManager{
		leases:    make(map[string]*Lease),
		cleanupCh: make(chan struct{}),
	}
}

// SetEngine sets the engine for server-side revocation during cleanup.
func (lm *LeaseManager) SetEngine(engine Engine) {
	lm.mu.Lock()
	defer lm.mu.Unlock()
	lm.engine = engine
}

// Create registers a new lease for the given secret.
func (lm *LeaseManager) Create(secret *Secret) (*Lease, error) {
	lm.mu.Lock()
	defer lm.mu.Unlock()

	now := time.Now().UTC()
	lease := &Lease{
		ID:        secret.LeaseID,
		Secret:    secret,
		ExpiresAt: now.Add(secret.LeaseDuration),
		Revoked:   false,
		CreatedAt: now,
	}
	lm.leases[lease.ID] = lease
	return lease, nil
}

// Revoke marks a lease as revoked.
func (lm *LeaseManager) Revoke(leaseID string) error {
	lm.mu.Lock()
	defer lm.mu.Unlock()

	lease, ok := lm.leases[leaseID]
	if !ok {
		return ErrLeaseNotFound
	}
	lease.Revoked = true
	return nil
}

// Get retrieves a lease by ID.
func (lm *LeaseManager) Get(leaseID string) (*Lease, bool) {
	lm.mu.RLock()
	defer lm.mu.RUnlock()

	lease, ok := lm.leases[leaseID]
	return lease, ok
}

// IsAlive reports whether the lease exists and has not expired or been revoked.
func (lm *LeaseManager) IsAlive(leaseID string) bool {
	lm.mu.RLock()
	defer lm.mu.RUnlock()

	lease, ok := lm.leases[leaseID]
	if !ok {
		return false
	}
	if lease.Revoked {
		return false
	}
	return !time.Now().After(lease.ExpiresAt)
}

// ListActive returns all leases that are still alive.
func (lm *LeaseManager) ListActive() []*Lease {
	lm.mu.RLock()
	defer lm.mu.RUnlock()

	now := time.Now()
	active := make([]*Lease, 0)
	for _, lease := range lm.leases {
		if !lease.Revoked && !now.After(lease.ExpiresAt) {
			active = append(active, lease)
		}
	}
	return active
}

// StartCleanup begins a background goroutine that periodically removes expired leases.
func (lm *LeaseManager) StartCleanup(ctx context.Context, interval time.Duration) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-lm.cleanupCh:
				return
			case <-ticker.C:
				lm.mu.Lock()
				now := time.Now()
				for id, lease := range lm.leases {
					if now.After(lease.ExpiresAt) || lease.Revoked {
						if lm.engine != nil {
							_ = lm.engine.Revoke(context.Background(), id)
						}
						delete(lm.leases, id)
					}
				}
				lm.mu.Unlock()
			}
		}
	}()
}

// Close stops the background cleanup goroutine and releases resources.
func (lm *LeaseManager) Close() error {
	lm.mu.Lock()
	defer lm.mu.Unlock()

	if lm.closed {
		return nil
	}
	lm.closed = true
	close(lm.cleanupCh)
	return nil
}
