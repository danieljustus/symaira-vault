package crypto

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"sync"
	"testing"
	"time"

	"filippo.io/age"
)

func TestArgon2ResourcePolicyLimits(t *testing.T) {
	exact := Argon2idParams{Time: 4, Memory: 128 * 1024, Threads: 4}
	if err := validateAutomaticArgon2(exact); err != nil {
		t.Fatal(err)
	}
	for _, p := range []Argon2idParams{{Time: 5, Memory: 32, Threads: 1}, {Time: 1, Memory: 128*1024 + 1, Threads: 1}, {Time: 1, Memory: 64, Threads: 5}} {
		if _, err := Argon2idDeriveKey([]byte("public fixture"), []byte("0123456789abcdef"), p); !errors.Is(err, ErrArgon2Policy) {
			t.Fatalf("automatic high-budget derivation reached sink: %v", err)
		}
	}
	// Historical 2 GiB is parsed/classified only, never allocated by this test.
	if _, err := parseArgon2idParams("t=16,m=2097152,p=16"); err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{"t=1,t=2,p=1", "t=1,m=32,p=1,p=2", "t=+1,m=32,p=1", "t=1, m=32,p=1", "t=1,m=32,p=1,x=1"} {
		if _, err := parseArgon2idParams(value); !errors.Is(err, ErrArgon2Malformed) {
			t.Fatalf("ambiguous parameters accepted: %q, %v", value, err)
		}
	}
}

func TestArgon2PreflightRejectsWholeEnvelopeBeforeKDF(t *testing.T) {
	stanza := func(params string) *age.Stanza {
		return &age.Stanza{Type: Argon2idStanzaType, Args: []string{base64.RawStdEncoding.EncodeToString([]byte("0123456789abcdef")), params}, Body: make([]byte, 44)}
	}
	exact := stanza("t=4,m=131072,p=4")
	if err := preflightArgon2id([]*age.Stanza{exact}, false); err != nil {
		t.Fatal(err)
	}
	for _, list := range [][]*age.Stanza{{exact, exact}, {stanza("t=3,m=65536,p=4"), stanza("t=3,m=65536,p=4"), stanza("t=3,m=65536,p=4")}, {stanza("t=1,m=32,p=1"), stanza("t=1,m=32,p=1"), stanza("t=1,m=32,p=1"), stanza("t=1,m=32,p=1"), stanza("t=1,m=32,p=1")}} {
		if _, err := NewArgon2idIdentity("public fixture").Unwrap(list); !errors.Is(err, ErrArgon2Policy) {
			t.Fatalf("cumulative work accepted: %v", err)
		}
	}
	broken := stanza("t=16,m=2097152,p=16")
	broken.Body = make([]byte, 45)
	if _, err := NewArgon2idIdentity("public fixture").Unwrap([]*age.Stanza{broken}); !errors.Is(err, ErrArgon2Malformed) {
		t.Fatalf("malformed wrapping body entered historical KDF: %v", err)
	}
}

func TestHistoricalGoKDFPolicyEnvelopes(t *testing.T) {
	raw, err := os.ReadFile("../../testdata/port/crypto/kdf-policy-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		OracleCommit string `json:"oracle_commit"`
		Identity     string `json:"identity"`
		Passphrase   string `json:"passphrase"`
		Cases        []struct {
			Name       string `json:"name"`
			Ciphertext string `json:"ciphertext"`
			SHA256     string `json:"sha256"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	if fixture.OracleCommit != "caadd5ef95e8f19fabd3ae3d2c04caa296f2fd44" || len(fixture.Cases) != 4 {
		t.Fatal("historical source or inventory changed")
	}
	for i, c := range fixture.Cases {
		ciphertext, err := base64.StdEncoding.DecodeString(c.Ciphertext)
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(ciphertext)
		if hex.EncodeToString(sum[:]) != c.SHA256 {
			t.Fatal("ciphertext integrity changed")
		}
		needsMigration, err := InspectArgon2idPolicy(ciphertext)
		if err != nil || needsMigration != (i < 3) {
			t.Fatalf("%s classification: %v, %v", c.Name, needsMigration, err)
		}
		plain, err := DecryptWithPassphraseArgon2id(ciphertext, []byte(fixture.Passphrase))
		if i < 3 && (!errors.Is(err, ErrArgon2Policy) || errors.Is(err, ErrDecryptionFailed)) {
			t.Fatalf("%s automatic policy bypass: %v", c.Name, err)
		}
		if i == 3 && (err != nil || string(plain) != fixture.Identity) {
			t.Fatalf("minimum historical read regressed: %v", err)
		}
		Wipe(plain)
		identity, err := DecryptIdentityForLegacyKDFMigration(ciphertext, []byte(fixture.Passphrase))
		if err != nil || identity.String() != fixture.Identity {
			t.Fatalf("%s historical compatibility lost: %v", c.Name, err)
		}
		if _, err := DecryptIdentityForLegacyKDFMigration(ciphertext, []byte("wrong public fixture")); !errors.Is(err, ErrDecryptionFailed) || IsArgon2ResourceError(err) {
			t.Fatalf("%s wrong-passphrase classification: %v", c.Name, err)
		}
	}
}

func TestArgon2BoundedAdmissionRunsRealDerivations(t *testing.T) {
	a := &argon2Admission{changed: make(chan struct{})}
	first, err := a.acquire(128*1024, false)
	if err != nil {
		t.Fatal(err)
	}
	second, err := a.acquire(128*1024, false)
	if err != nil {
		t.Fatal(err)
	}
	defer first()
	var group sync.WaitGroup
	results := make(chan error, argon2MaxWaiters)
	for range argon2MaxWaiters {
		group.Add(1)
		go func() {
			defer group.Done()
			key, err := deriveArgon2idKeyAdmitted([]byte("public fixture"), []byte("0123456789abcdef"), Argon2idParams{Time: 1, Memory: 32, Threads: 1}, false, a)
			Wipe(key)
			results <- err
		}()
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		a.mu.Lock()
		waiting := a.waiters
		a.mu.Unlock()
		if waiting == argon2MaxWaiters {
			break
		}
		if time.Now().After(deadline) {
			second()
			group.Wait()
			t.Fatal("actual derivations did not reach bounded admission")
		}
		time.Sleep(time.Millisecond)
	}
	_, err = deriveArgon2idKeyAdmitted([]byte("public fixture"), []byte("0123456789abcdef"), Argon2idParams{Time: 1, Memory: 32, Threads: 1}, false, a)
	if !errors.Is(err, ErrArgon2Busy) {
		t.Fatalf("full queue did not reject derivation: %v", err)
	}
	second()
	group.Wait()
	close(results)
	for err := range results {
		if err != nil {
			t.Fatal(err)
		}
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.active != 1 || a.memory != 128*1024 || a.waiters != 0 {
		t.Fatal("KDF reservations leaked")
	}
}

func TestArgon2LegacyAdmissionExcludesAutomaticDerivation(t *testing.T) {
	a := &argon2Admission{changed: make(chan struct{})}
	release, err := a.acquire(32, true)
	if err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() {
		key, err := deriveArgon2idKeyAdmitted([]byte("public fixture"), []byte("0123456789abcdef"), Argon2idParams{Time: 1, Memory: 32, Threads: 1}, false, a)
		Wipe(key)
		result <- err
	}()
	deadline := time.Now().Add(2 * time.Second)
	for {
		a.mu.Lock()
		waiting := a.waiters
		a.mu.Unlock()
		if waiting == 1 {
			break
		}
		if time.Now().After(deadline) {
			release()
			<-result
			t.Fatal("automatic KDF did not wait for legacy reservation")
		}
		time.Sleep(time.Millisecond)
	}
	select {
	case err := <-result:
		release()
		t.Fatalf("legacy admission allowed automatic KDF: %v", err)
	default:
	}
	release()
	if err := <-result; err != nil {
		t.Fatal(err)
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.active != 0 || a.waiters != 0 || a.memory != 0 {
		t.Fatal("admission leaked resources")
	}
}
