package server

import (
	"fmt"
	"math"
	"strconv"
)

const (
	defaultCommandTimeoutSeconds = 30
	minCommandTimeoutSeconds     = 1
	maxCommandTimeoutSeconds     = 300
)

func parseCommandTimeoutSeconds(raw any) (int, error) {
	if raw == nil {
		return defaultCommandTimeoutSeconds, nil
	}

	var value float64
	switch typed := raw.(type) {
	case float64:
		value = typed
	case float32:
		value = float64(typed)
	case int:
		value = float64(typed)
	case int32:
		value = float64(typed)
	case int64:
		value = float64(typed)
	case string:
		parsed, err := strconv.ParseFloat(typed, 64)
		if err != nil {
			return 0, fmt.Errorf("argument \"timeout\" must be numeric")
		}
		value = parsed
	default:
		return 0, fmt.Errorf("argument \"timeout\" must be numeric")
	}

	if math.IsNaN(value) || math.IsInf(value, 0) {
		return 0, fmt.Errorf("argument \"timeout\" must be a finite number")
	}
	if value != math.Trunc(value) {
		return 0, fmt.Errorf("argument \"timeout\" must be a whole number of seconds")
	}
	if value < minCommandTimeoutSeconds || value > maxCommandTimeoutSeconds {
		return 0, fmt.Errorf("argument \"timeout\" must be between %d and %d seconds", minCommandTimeoutSeconds, maxCommandTimeoutSeconds)
	}
	return int(value), nil
}
