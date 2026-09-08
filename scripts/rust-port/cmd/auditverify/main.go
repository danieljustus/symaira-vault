// Command auditverify verifies a Rust-emitted JSONL audit file with the
// production Go verifier. The deterministic fixture key is not a credential.
package main

import (
	"encoding/hex"
	"fmt"
	"os"

	"github.com/danieljustus/symaira-vault/internal/audit"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: auditverify <audit-jsonl>")
		os.Exit(2)
	}
	key := []byte("audit-fixture-old-key-0000000000")
	kid := audit.KeyFingerprint(key)
	result, err := audit.VerifyLog(os.Args[1], key)
	if err != nil {
		fmt.Fprintln(os.Stderr, "FAIL audit verification")
		os.Exit(1)
	}
	if !result.Valid || result.Verified != 2 || result.Tampered != 0 {
		fmt.Fprintln(os.Stderr, "FAIL audit verification")
		os.Exit(1)
	}
	// Keep the computed ID in the code path without printing key material.
	if _, err := hex.DecodeString(kid); err != nil {
		fmt.Fprintln(os.Stderr, "FAIL audit key identifier")
		os.Exit(1)
	}
	fmt.Println("PASS Rust audit output -> Go production verification")
}
