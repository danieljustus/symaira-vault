package vault

import (
	"sync"
	"time"
)

var (
	metricsMu               sync.RWMutex
	recordOperationDuration = func(op string, duration time.Duration) {}
	recordEntryCount        = func(vaultDir string, count int) {}
)

// SetMetricsHooks configures the metric observation callbacks for vault operations.
func SetMetricsHooks(onDuration func(op string, duration time.Duration), onCount func(vaultDir string, count int)) {
	metricsMu.Lock()
	defer metricsMu.Unlock()
	if onDuration == nil {
		onDuration = func(string, time.Duration) {}
	}
	if onCount == nil {
		onCount = func(string, int) {}
	}
	recordOperationDuration = onDuration
	recordEntryCount = onCount
}

func recordDuration(op string, duration time.Duration) {
	metricsMu.RLock()
	fn := recordOperationDuration
	metricsMu.RUnlock()
	if fn != nil {
		fn(op, duration)
	}
}

func recordCount(vaultDir string, count int) {
	metricsMu.RLock()
	fn := recordEntryCount
	metricsMu.RUnlock()
	if fn != nil {
		fn(vaultDir, count)
	}
}
