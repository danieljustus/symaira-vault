package secureui

import (
	"context"
	"errors"
	"os/exec"
	"time"

	"github.com/danieljustus/symaira-vault/internal/secrets"
)

// runner abstracts subprocess execution so backends can be unit-tested with a
// mock. defaultRunner is used in production; tests inject their own.
type runner interface {
	run(name string, args []string, timeout time.Duration) ([]byte, error)
	lookPath(name string) (string, error)
}

type execRunner struct{}

func (execRunner) run(name string, args []string, timeout time.Duration) ([]byte, error) {
	return (execRunner{}).runContext(context.Background(), name, args, timeout)
}

func (execRunner) runContext(parent context.Context, name string, args []string, timeout time.Duration) ([]byte, error) {
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	secrets.PrepareCmd(cmd)
	out, err := cmd.Output()
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return nil, ErrTimeout
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	return out, err
}

func runPrompt(r runner, req PromptRequest, name string, args []string) ([]byte, error) {
	if req.Context == nil {
		return r.run(name, args, req.Timeout)
	}
	if err := req.Context.Err(); err != nil {
		return nil, err
	}
	if cr, ok := r.(interface {
		runContext(context.Context, string, []string, time.Duration) ([]byte, error)
	}); ok {
		return cr.runContext(req.Context, name, args, req.Timeout)
	}
	// Test runners retain their original interface; late replies fail closed.
	out, err := r.run(name, args, req.Timeout)
	if canceled := req.Context.Err(); canceled != nil {
		return nil, canceled
	}
	return out, err
}

func (execRunner) lookPath(name string) (string, error) {
	return exec.LookPath(name)
}

var defaultRunner runner = execRunner{}
