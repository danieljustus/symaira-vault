package sync

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/danieljustus/symaira-vault/internal/vault"
)

const samplePath = "login/example"

func meta(version int, updated time.Time) vault.EntryMetadata {
	return vault.EntryMetadata{Version: version, Updated: updated}
}

func TestWinnerByVersionHigherWins(t *testing.T) {
	a := meta(2, time.Unix(100, 0))
	b := meta(1, time.Unix(200, 0))
	winner, loser := WinnerByVersion(samplePath, a, b)
	if winner.Version != 2 || loser.Version != 1 {
		t.Fatalf("expected higher version to win, got winner=%d loser=%d", winner.Version, loser.Version)
	}
}

func TestWinnerByVersionArgumentOrderIndependent(t *testing.T) {
	// Same inputs swapped: outcome must not depend on argument order.
	a := meta(1, time.Unix(100, 0))
	b := meta(3, time.Unix(50, 0))

	w1, l1 := WinnerByVersion(samplePath, a, b)
	w2, l2 := WinnerByVersion(samplePath, b, a)

	if w1.Version != w2.Version || l1.Version != l2.Version {
		t.Fatalf("argument order changed winner: (%d,%d) vs (%d,%d)", w1.Version, l1.Version, w2.Version, l2.Version)
	}
	if w1.Version != 3 {
		t.Fatalf("expected version 3 to win, got %d", w1.Version)
	}
}

func TestWinnerByVersionTieBreaksUpdated(t *testing.T) {
	ts := time.Unix(100, 0)
	a := meta(1, ts)
	b := meta(1, ts.Add(time.Second))
	winner, _ := WinnerByVersion(samplePath, a, b)
	if !winner.Updated.After(ts) {
		t.Fatalf("expected newer Updated to win on equal version, got %v", winner.Updated)
	}
}

func TestWinnerByVersionFullyDeterministic(t *testing.T) {
	// Equal Version and Updated: the stable metadata-JSON tiebreak must be
	// order-independent and never rely on map iteration.
	a := meta(1, time.Unix(100, 0))
	b := meta(1, time.Unix(100, 0))
	w1, l1 := WinnerByVersion(samplePath, a, b)
	w2, l2 := WinnerByVersion(samplePath, b, a)
	if w1.Version != w2.Version || l1.Version != l2.Version {
		t.Fatalf("non-deterministic tiebreak: (%d,%d) vs (%d,%d)", w1.Version, l1.Version, w2.Version, l2.Version)
	}
}

func TestPreserveConflictCopyLossless(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "login.example.age")
	want := []byte("age-encrypted-blob-do-not-lose")
	if err := os.WriteFile(src, want, 0o600); err != nil {
		t.Fatalf("seed loser: %v", err)
	}

	dst, err := PreserveConflictCopy(src)
	if err != nil {
		t.Fatalf("PreserveConflictCopy: %v", err)
	}
	if dst == src {
		t.Fatalf("conflict copy must not overwrite the loser at its canonical path")
	}
	if _, err := os.Stat(src); err != nil {
		t.Fatalf("loser source must be preserved, but it is gone: %v", err)
	}
	got, err := os.ReadFile(dst)
	if err != nil {
		t.Fatalf("read conflict copy: %v", err)
	}
	if string(got) != string(want) {
		t.Fatalf("conflict copy content mismatch: got %q want %q", got, want)
	}
}

func TestPreserveConflictCopyUniqueNameOnCollision(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "login.example.age")
	if err := os.WriteFile(src, []byte("x"), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	first, err := PreserveConflictCopy(src)
	if err != nil {
		t.Fatalf("first copy: %v", err)
	}
	// A second copy of the same loser must not collide on the same name.
	second, err := PreserveConflictCopy(src)
	if err != nil {
		t.Fatalf("second copy: %v", err)
	}
	if first == second {
		t.Fatalf("two conflict copies must not collide on the same name")
	}
}
