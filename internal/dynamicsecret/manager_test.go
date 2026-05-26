package dynamicsecret

import (
	"context"
	"testing"
	"time"

	vaultpkg "github.com/danieljustus/symaira-vault/internal/vault"
)

func TestNewManager(t *testing.T) {
	mockVault := &vaultpkg.Vault{}
	mgr := NewManager(mockVault)

	if mgr == nil {
		t.Fatal("NewManager returned nil")
	}

	// Should start with empty registry
	engines := mgr.ListEngines()
	if len(engines) != 0 {
		t.Errorf("ListEngines() = %v, want empty", engines)
	}
}

func TestManagerRegisterEngine(t *testing.T) {
	mockVault := &vaultpkg.Vault{}
	mgr := NewManager(mockVault)

	mock := NewMockEngine()
	mgr.RegisterEngine(mock)

	engines := mgr.ListEngines()
	if len(engines) != 1 {
		t.Fatalf("ListEngines() = %v, want 1 engine", engines)
	}
	if engines[0] != EngineTypeMock {
		t.Errorf("engine type = %q, want mock", engines[0])
	}
}

func TestManagerGenerate(t *testing.T) {
	mockVault := &vaultpkg.Vault{}
	mgr := NewManager(mockVault)
	defer mgr.Close()

	// Register a mock engine that returns a secret
	mock := NewMockEngine()
	mock.GenerateFunc = func(ctx context.Context, req GenerateRequest) (*Secret, error) {
		return &Secret{
			LeaseID:       "generated-lease",
			LeaseDuration: req.TTL,
			EngineType:    EngineTypeMock,
			Data:          map[string]any{"token": "abc123"},
		}, nil
	}
	mgr.RegisterEngine(mock)

	ctx := context.Background()
	req := GenerateRequest{
		Role:        "admin",
		TTL:         time.Hour,
		Permissions: "read-write",
	}

	secret, err := mgr.Generate(ctx, EngineTypeMock, req)
	if err != nil {
		t.Fatalf("Generate error: %v", err)
	}
	if secret == nil {
		t.Fatal("Generate returned nil secret")
	}
	if secret.LeaseID == "" {
		t.Error("secret.LeaseID is empty")
	}
	if secret.EngineType != EngineTypeMock {
		t.Errorf("secret.EngineType = %q, want mock", secret.EngineType)
	}
	if secret.LeaseDuration != time.Hour {
		t.Errorf("secret.LeaseDuration = %v, want 1h", secret.LeaseDuration)
	}
	if secret.Data["token"] != "abc123" {
		t.Errorf("secret.Data[token] = %v, want abc123", secret.Data["token"])
	}
}

func TestManagerGenerateUnknownEngine(t *testing.T) {
	mockVault := &vaultpkg.Vault{}
	mgr := NewManager(mockVault)
	defer mgr.Close()

	_, err := mgr.Generate(context.Background(), "unknown", GenerateRequest{})
	if err == nil {
		t.Error("Generate with unknown engine = nil, want error")
	}
}

func TestManagerRevoke(t *testing.T) {
	mockVault := &vaultpkg.Vault{}
	mgr := NewManager(mockVault)
	defer mgr.Close()

	// Generate then revoke
	mock := NewMockEngine()
	mock.GenerateFunc = func(ctx context.Context, req GenerateRequest) (*Secret, error) {
		return &Secret{LeaseID: "lease-1"}, nil
	}
	mgr.RegisterEngine(mock)

	secret, err := mgr.Generate(context.Background(), EngineTypeMock, GenerateRequest{})
	if err != nil {
		t.Fatalf("Generate error: %v", err)
	}
	if secret == nil {
		t.Fatal("Generate returned nil secret")
	}

	if err := mgr.Revoke(context.Background(), secret.LeaseID); err != nil {
		t.Errorf("Revoke error: %v", err)
	}

	_, err = mgr.Lookup(context.Background(), secret.LeaseID)
	if err == nil {
		t.Error("Lookup after revoke = nil, want error")
	}
}

func TestManagerRevokeNonExistent(t *testing.T) {
	mockVault := &vaultpkg.Vault{}
	mgr := NewManager(mockVault)
	defer mgr.Close()

	err := mgr.Revoke(context.Background(), "non-existent")
	if err == nil {
		t.Error("Revoke(non-existent) = nil, want error")
	}
}

func TestManagerLookup(t *testing.T) {
	mockVault := &vaultpkg.Vault{}
	mgr := NewManager(mockVault)
	defer mgr.Close()

	mock := NewMockEngine()
	mock.GenerateFunc = func(ctx context.Context, req GenerateRequest) (*Secret, error) {
		return &Secret{LeaseID: "lease-1", Data: map[string]any{"key": "value"}}, nil
	}
	mgr.RegisterEngine(mock)

	secret, err := mgr.Generate(context.Background(), EngineTypeMock, GenerateRequest{})
	if err != nil {
		t.Fatalf("Generate error: %v", err)
	}
	if secret == nil {
		t.Fatal("Generate returned nil secret")
	}

	got, err := mgr.Lookup(context.Background(), secret.LeaseID)
	if err != nil {
		t.Fatalf("Lookup error: %v", err)
	}
	if got == nil {
		t.Fatal("Lookup returned nil")
	}
	if got.LeaseID != secret.LeaseID {
		t.Errorf("Lookup LeaseID = %q, want %q", got.LeaseID, secret.LeaseID)
	}
}

func TestManagerLookupNonExistent(t *testing.T) {
	mockVault := &vaultpkg.Vault{}
	mgr := NewManager(mockVault)
	defer mgr.Close()

	_, err := mgr.Lookup(context.Background(), "non-existent")
	if err == nil {
		t.Error("Lookup(non-existent) = nil, want error")
	}
}

func TestManagerRenew(t *testing.T) {
	mockVault := &vaultpkg.Vault{}
	mgr := NewManager(mockVault)
	defer mgr.Close()

	mock := NewMockEngine()
	mock.GenerateFunc = func(ctx context.Context, req GenerateRequest) (*Secret, error) {
		return &Secret{
			LeaseID:       "lease-1",
			LeaseDuration: time.Hour,
			Renewable:     true,
		}, nil
	}
	mgr.RegisterEngine(mock)

	secret, err := mgr.Generate(context.Background(), EngineTypeMock, GenerateRequest{})
	if err != nil {
		t.Fatalf("Generate error: %v", err)
	}
	if secret == nil {
		t.Fatal("Generate returned nil secret")
	}

	renewed, err := mgr.Renew(context.Background(), secret.LeaseID, 30*time.Minute)
	if err != nil {
		t.Fatalf("Renew error: %v", err)
	}
	if renewed == nil {
		t.Fatal("Renew returned nil")
	}
	if renewed.LeaseDuration != 30*time.Minute {
		t.Errorf("Renewed duration = %v, want 30m", renewed.LeaseDuration)
	}
}

func TestManagerRenewNonRenewable(t *testing.T) {
	mockVault := &vaultpkg.Vault{}
	mgr := NewManager(mockVault)
	defer mgr.Close()

	mock := NewMockEngine()
	mock.GenerateFunc = func(ctx context.Context, req GenerateRequest) (*Secret, error) {
		return &Secret{
			LeaseID:       "lease-1",
			LeaseDuration: time.Hour,
			Renewable:     false,
		}, nil
	}
	mgr.RegisterEngine(mock)

	secret, err := mgr.Generate(context.Background(), EngineTypeMock, GenerateRequest{})
	if err != nil {
		t.Fatalf("Generate error: %v", err)
	}
	if secret == nil {
		t.Fatal("Generate returned nil secret")
	}

	_, err = mgr.Renew(context.Background(), secret.LeaseID, 30*time.Minute)
	if err == nil {
		t.Error("Renew non-renewable = nil, want error")
	}
}

func TestManagerClose(t *testing.T) {
	mockVault := &vaultpkg.Vault{}
	mgr := NewManager(mockVault)

	if err := mgr.Close(); err != nil {
		t.Errorf("Close error: %v", err)
	}
}

func TestManagerMultipleEngines(t *testing.T) {
	mockVault := &vaultpkg.Vault{}
	mgr := NewManager(mockVault)
	defer mgr.Close()

	mgr.RegisterEngine(NewMockEngine())
	mgr.RegisterEngine(NewPostgreSQLEngine("postgres://localhost"))
	mgr.RegisterEngine(NewAWSSTSEngine("arn:aws:iam::123456789012:role/test"))

	engines := mgr.ListEngines()
	if len(engines) != 3 {
		t.Fatalf("ListEngines() = %d, want 3", len(engines))
	}
}

func TestManagerContextCancellation(t *testing.T) {
	mockVault := &vaultpkg.Vault{}
	mgr := NewManager(mockVault)
	defer mgr.Close()

	mock := NewMockEngine()
	mock.GenerateFunc = func(ctx context.Context, req GenerateRequest) (*Secret, error) {
		return &Secret{LeaseID: "lease-1"}, nil
	}
	mgr.RegisterEngine(mock)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := mgr.Generate(ctx, EngineTypeMock, GenerateRequest{})
	if err == nil {
		t.Error("Generate with canceled context = nil, want error")
	}
}
