//go:build !windows

package clipboard

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	osSignal "os/signal"
	"strings"
	"syscall"
	"testing"
	"time"
)

// TestStartAutoClearSignalRouterProcessContract has a child catch one signal
// while StartAutoClear is subscribed, then verifies a second signal gets the
// normal process disposition after the timer goroutine returns.
func TestStartAutoClearSignalRouterProcessContract(t *testing.T) {
	if signalName := os.Getenv("SYMVAULT_CLIPBOARD_SIGNAL_CHILD"); signalName != "" {
		signal := clipboardTestSignal(signalName)
		// Keep one explicit subscriber active while StartAutoClear installs its
		// own registration. For SIGINT/SIGTERM this also models Go's separate
		// secure-input subscriber; SIGHUP uses it only as a startup barrier.
		promptSignals := make(chan os.Signal, 1)
		osSignal.Notify(promptSignals, signal)
		defer osSignal.Stop(promptSignals)
		cleared := make(chan struct{})
		done := make(chan struct{})
		go func() {
			StartAutoClear(30, func() { close(cleared) }, nil)
			close(done)
		}()
		deadline := time.NewTimer(3 * time.Second)
		ticker := time.NewTicker(20 * time.Millisecond)
		defer deadline.Stop()
		defer ticker.Stop()
		for {
			select {
			case <-cleared:
				goto clearedBySignal
			case <-ticker.C:
				if err := syscall.Kill(os.Getpid(), signal); err != nil {
					t.Fatalf("deliver active clipboard signal: %v", err)
				}
			case <-deadline.C:
				t.Fatal("active clipboard signal did not clear")
			}
		}
	clearedBySignal:
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Fatal("signal did not end the active auto-clear monitor")
		}
		promptCanceled := signal != syscall.SIGHUP
		select {
		case received := <-promptSignals:
			if received != signal {
				t.Fatalf("prompt signal = %v, want %v", received, signal)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("signal was not broadcast to the concurrent signal subscriber")
		}
		osSignal.Stop(promptSignals)
		fmt.Printf("GO_CLIPBOARD_SIGNAL_RECEIPT signal=%s clear=1 continued=true prompt_canceled=%t\n", signalName, promptCanceled)
		if err := syscall.Kill(os.Getpid(), signal); err != nil {
			t.Fatalf("deliver idle signal: %v", err)
		}
		timer := time.NewTimer(3 * time.Second)
		defer timer.Stop()
		<-timer.C
		t.Fatal("idle signal did not terminate the process")
	}

	for _, signalName := range []string{"SIGINT", "SIGTERM", "SIGHUP"} {
		t.Run(signalName, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
			defer cancel()
			command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestStartAutoClearSignalRouterProcessContract$")
			command.Env = append(os.Environ(), "SYMVAULT_CLIPBOARD_SIGNAL_CHILD="+signalName)
			output, err := command.CombinedOutput()
			exit, ok := err.(*exec.ExitError)
			if !ok {
				t.Fatalf("child did not terminate on idle %s: err=%v output=%s", signalName, err, output)
			}
			status, ok := exit.Sys().(syscall.WaitStatus)
			if !ok || !status.Signaled() || status.Signal() != clipboardTestSignal(signalName) {
				t.Fatalf("child exit does not prove idle %s default: status=%v output=%s", signalName, exit.Sys(), output)
			}
			wantPrompt := "prompt_canceled=false"
			if signalName != "SIGHUP" {
				wantPrompt = "prompt_canceled=true"
			}
			if !strings.Contains(string(output), "GO_CLIPBOARD_SIGNAL_RECEIPT signal="+signalName+" clear=1 continued=true "+wantPrompt) {
				t.Fatalf("child did not prove active %s clear-and-continue: %s", signalName, output)
			}
		})
	}
}

func clipboardTestSignal(name string) syscall.Signal {
	switch name {
	case "SIGINT":
		return syscall.SIGINT
	case "SIGTERM":
		return syscall.SIGTERM
	case "SIGHUP":
		return syscall.SIGHUP
	default:
		panic("unknown test signal")
	}
}
