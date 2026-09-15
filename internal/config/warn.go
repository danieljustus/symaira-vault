package config

import (
	"fmt"
	"os"
	"sync"
)

// MultipleDocumentsWarning is pinned by the CFG-003 contract; the Rust side
// emits the identical text.
const MultipleDocumentsWarning = "config contains more than one YAML document; only the first is used and the rest are ignored"

// NonPositiveDurationWarning is pinned by the CFG-003 contract; the Rust side
// emits the identical text.
//
// The offending value is deliberately not interpolated: Go reaches this point
// with a parsed time.Duration and would render "-5m0s" where Rust still has the
// scalar text "-5m", so including it would make the two texts differ for no
// benefit. The field name is what the operator needs.
func NonPositiveDurationWarning(field string) string {
	return field + ": not a positive duration; the default is used instead"
}

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
