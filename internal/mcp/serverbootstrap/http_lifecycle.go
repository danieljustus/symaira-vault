package serverbootstrap

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"time"
)

// HTTPShutdownError reports a failed clean drain. Drained closes after every
// owned callback and deferred cleanup finishes; embedders must retain their
// caller-owned vault resources until that signal after a deadline.
type HTTPShutdownError struct {
	Cause   error
	Drained <-chan struct{}
}

func (*HTTPShutdownError) Error() string   { return "HTTP shutdown did not drain cleanly" }
func (e *HTTPShutdownError) Unwrap() error { return e.Cause }

// httpCallbackOwners prevents WaitGroup additions after shutdown starts. Both
// requests and detached factory callbacks hold ownership until they actually
// return, including factories whose caller has already timed out.
type httpCallbackOwners struct {
	mu      sync.Mutex
	stopped bool
	active  sync.WaitGroup
}

func (o *httpCallbackOwners) begin() bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.stopped {
		return false
	}
	o.active.Add(1)
	return true
}

func (o *httpCallbackOwners) stop() {
	o.mu.Lock()
	o.stopped = true
	o.mu.Unlock()
}

func (o *httpCallbackOwners) handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !o.begin() {
			http.Error(w, "server shutting down", http.StatusServiceUnavailable)
			return
		}
		defer o.active.Done()
		next.ServeHTTP(w, r)
	})
}

// drainHTTP returns only after clean drain or an explicit deadline. On timeout,
// cleanup retains ownership in one waiter until uncooperative callbacks exit.
func drainHTTP(server *http.Server, owners *httpCallbackOwners, timeout time.Duration, cleanup func()) error {
	owners.stop()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	err := server.Shutdown(ctx)
	if err != nil {
		err = errors.Join(err, server.Close())
	}
	done := make(chan struct{})
	go func() {
		owners.active.Wait()
		cleanup()
		close(done)
	}()
	select {
	case <-done:
		if err != nil {
			return &HTTPShutdownError{Cause: err, Drained: done}
		}
		return err
	case <-ctx.Done():
		return &HTTPShutdownError{Cause: errors.Join(err, ctx.Err(), server.Close()), Drained: done}
	}
}
