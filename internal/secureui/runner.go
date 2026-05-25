package secureui

import (
	"context"
	"errors"
	"os/exec"
	"time"

	"github.com/danieljustus/symaira-vault/internal/envfilter"
)

// runner abstracts subprocess execution so backends can be unit-tested with a
// mock. defaultRunner is used in production; tests inject their own.
type runner interface {
	run(name string, args []string, timeout time.Duration) ([]byte, error)
	lookPath(name string) (string, error)
}

type execRunner struct{}

func (execRunner) run(name string, args []string, timeout time.Duration) ([]byte, error) {
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	envfilter.PrepareCmd(cmd)
	out, err := cmd.Output()
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return nil, ErrTimeout
	}
	return out, err
}

func (execRunner) lookPath(name string) (string, error) {
	return exec.LookPath(name)
}

var defaultRunner runner = execRunner{}
