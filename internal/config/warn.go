package config

import (
	"fmt"
	"os"
	"sync"
)

// WarnFunc is the function signature for deprecation and configuration warnings.
type WarnFunc func(string)

var (
	warnMu   sync.RWMutex
	warnFunc = func(msg string) {
		fmt.Fprintln(os.Stderr, msg)
	}
)

// SetWarnFunc sets the warning callback used when deprecation warnings are encountered.
// If fn is nil, warnings are suppressed.
func SetWarnFunc(fn WarnFunc) {
	warnMu.Lock()
	defer warnMu.Unlock()
	warnFunc = fn
}

func warnf(format string, args ...any) {
	warnMu.RLock()
	fn := warnFunc
	warnMu.RUnlock()
	if fn != nil {
		fn(fmt.Sprintf(format, args...))
	}
}
