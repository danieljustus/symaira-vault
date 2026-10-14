package main

import (
	"testing"

	"github.com/danieljustus/symaira-vault/scripts/rust-port/internal/oracletest"
)

// Exercise the production generator against its committed fixture, including
// source provenance and exact output. Synthetic inputs never open a vault.
func TestCommittedFixtureFreshness(t *testing.T) {
	oracletest.Check(t, "tools-call", 4)
}
