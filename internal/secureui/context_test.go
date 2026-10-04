package secureui

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSecurePromptCancellationProcessHelper(t *testing.T) {
	if len(os.Args) < 3 || os.Args[len(os.Args)-2] != "prompt-cancellation-helper" {
		return
	}
	if err := os.WriteFile(os.Args[len(os.Args)-1], []byte("public readiness marker"), 0o600); err != nil {
		t.Fatal(err)
	}
	// The real parent must cancel and join this process, rather than waiting for
	// its ordinary prompt timeout. The timer also bounds a failed test helper.
	<-time.NewTimer(30 * time.Second).C
}

func TestSecurePromptContextCancelsActualProcess(t *testing.T) {
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(t.TempDir(), "ready")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := runPrompt(execRunner{}, PromptRequest{Context: ctx, Timeout: 20 * time.Second}, binary,
			[]string{"-test.run=^TestSecurePromptCancellationProcessHelper$", "prompt-cancellation-helper", marker})
		done <- err
	}()
	deadline := time.NewTimer(2 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(5 * time.Millisecond)
	defer tick.Stop()
	ready := false
	for !ready {
		select {
		case <-tick.C:
			_, err := os.Stat(marker)
			ready = err == nil
		case err := <-done:
			t.Fatalf("prompt process exited before cancellation: %v", err)
		case <-deadline.C:
			t.Fatal("prompt process did not start")
		}
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("prompt cancellation error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("cancellation did not terminate and join the real prompt process")
	}
}

type lateAffirmativeRunner struct{ cancel context.CancelFunc }

func (r lateAffirmativeRunner) lookPath(name string) (string, error) { return name, nil }
func (r lateAffirmativeRunner) run(string, []string, time.Duration) ([]byte, error) {
	r.cancel()
	return []byte("yes"), nil
}

func TestSecurePromptContextRejectsLateAffirmative(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	value, err := runPrompt(lateAffirmativeRunner{cancel}, PromptRequest{Context: ctx}, "synthetic", nil)
	if value != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("late affirmative survived cancellation: %q, %v", value, err)
	}
}
