package dynamicsecret

import (
	"context"
	"errors"
	"time"

	vaultpkg "github.com/danieljustus/symaira-vault/internal/vault"
)

// Manager orchestrates dynamic secret generation across multiple engines.
// It provides the high-level API for requesting, renewing, and revoking secrets.
type Manager struct {
	vault    *vaultpkg.Vault
	registry *EngineRegistry
	leases   *LeaseManager
}

// ErrEngineNotFound is returned when the requested engine type is not registered.
var ErrEngineNotFound = errors.New("dynamic secret engine not found")

// ErrLeaseNotRenewable is returned when attempting to renew a non-renewable lease.
var ErrLeaseNotRenewable = errors.New("lease is not renewable")

// NewManager creates a new dynamic secret manager with the given vault.
func NewManager(vault *vaultpkg.Vault) *Manager {
	return &Manager{
		vault:    vault,
		registry: NewEngineRegistry(),
		leases:   NewLeaseManager(),
	}
}

// Generate creates a new dynamic secret using the specified engine.
func (m *Manager) Generate(ctx context.Context, engineType string, req GenerateRequest) (*Secret, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	engine, ok := m.registry.Get(engineType)
	if !ok {
		return nil, ErrEngineNotFound
	}

	secret, err := engine.Generate(ctx, req)
	if err != nil {
		return nil, err
	}

	secret.EngineType = engineType
	_, err = m.leases.Create(secret)
	if err != nil {
		return nil, err
	}

	return secret, nil
}

// Revoke invalidates a secret by lease ID.
func (m *Manager) Revoke(ctx context.Context, leaseID string) error {
	lease, ok := m.leases.Get(leaseID)
	if !ok {
		return ErrLeaseNotFound
	}

	engine, ok := m.registry.Get(lease.Secret.EngineType)
	if !ok {
		return ErrEngineNotFound
	}

	if err := engine.Revoke(ctx, leaseID); err != nil {
		return err
	}

	return m.leases.Revoke(leaseID)
}

// Renew extends the TTL of an existing secret lease.
func (m *Manager) Renew(ctx context.Context, leaseID string, increment time.Duration) (*Secret, error) {
	lease, ok := m.leases.Get(leaseID)
	if !ok {
		return nil, ErrLeaseNotFound
	}

	if !lease.Secret.Renewable {
		return nil, ErrLeaseNotRenewable
	}

	return &Secret{
		LeaseID:       lease.Secret.LeaseID,
		LeaseDuration: increment,
		Renewable:     lease.Secret.Renewable,
		Data:          lease.Secret.Data,
		CreatedAt:     lease.Secret.CreatedAt,
		EngineType:    lease.Secret.EngineType,
	}, nil
}

// Lookup retrieves a secret by lease ID.
func (m *Manager) Lookup(ctx context.Context, leaseID string) (*Secret, error) {
	lease, ok := m.leases.Get(leaseID)
	if !ok {
		return nil, ErrLeaseNotFound
	}
	if lease.Revoked {
		return nil, ErrLeaseNotFound
	}
	return lease.Secret, nil
}

// RegisterEngine adds a secret engine to the manager's registry.
func (m *Manager) RegisterEngine(engine SecretEngine) {
	m.registry.Register(engine)
}

// ListEngines returns all registered engine types.
func (m *Manager) ListEngines() []string {
	return m.registry.List()
}

// Close shuts down the manager and its lease cleanup routines.
func (m *Manager) Close() error {
	return m.leases.Close()
}
