// Package testutil provides test helpers for the Symaira Vault project.
package testutil

import (
	"testing"

	"filippo.io/age"
)

func TempIdentity(t testing.TB) *age.X25519Identity {
	t.Helper()

	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("generate x25519 identity: %v", err)
	}
	return identity
}
