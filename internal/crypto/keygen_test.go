package crypto

import (
	"testing"
	"time"
)

func TestBenchmarkScryptWorkFactor(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping scrypt benchmark in short mode")
	}

	wf, elapsed, err := BenchmarkScryptWorkFactor(250 * time.Millisecond)
	if err != nil {
		t.Fatalf("BenchmarkScryptWorkFactor() error = %v", err)
	}
	if wf < 15 || wf > 22 {
		t.Errorf("BenchmarkScryptWorkFactor() = %d, want between 15 and 22 (took %v)", wf, elapsed)
	}
	if elapsed <= 0 {
		t.Error("BenchmarkScryptWorkFactor() returned zero or negative duration")
	}
}

func TestDefaultScryptWorkFactor(t *testing.T) {
	if got := DefaultScryptWorkFactor; got != 18 {
		t.Errorf("DefaultScryptWorkFactor = %d, want 18", got)
	}
}

func TestBenchmarkScryptWorkFactorShortTarget(t *testing.T) {
	wf, elapsed, err := BenchmarkScryptWorkFactor(time.Millisecond)
	if err != nil {
		t.Fatalf("BenchmarkScryptWorkFactor(1ms) error = %v", err)
	}
	if wf < 1 || wf > 22 {
		t.Errorf("BenchmarkScryptWorkFactor(1ms) = %d, want between 1 and 22 (took %v)", wf, elapsed)
	}
	if elapsed <= 0 {
		t.Error("BenchmarkScryptWorkFactor() returned zero or negative duration")
	}
}
