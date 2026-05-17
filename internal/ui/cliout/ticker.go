package cliout

import "time"

// newTicker is the indirection point for tests (which can substitute a fast
// or controllable ticker). Production code uses time.NewTicker at 100ms.
var newTicker = func() *time.Ticker {
	return time.NewTicker(100 * time.Millisecond)
}
