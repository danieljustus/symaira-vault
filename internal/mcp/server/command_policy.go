package server

import (
	"fmt"
	"math"
	"path/filepath"
	"strconv"
)

const (
	defaultCommandTimeoutSeconds = 30
	minCommandTimeoutSeconds     = 1
	maxCommandTimeoutSeconds     = 300
)

// parseCommandArray parses the command argument into a slice of strings.
// It returns a user-facing formatting error if the input is invalid.
func parseCommandArray(raw any) ([]string, error) {
	if raw == nil {
		return nil, fmt.Errorf("missing required argument \"command\"")
	}
	cmdSlice, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("argument \"command\" must be an array")
	}
	if len(cmdSlice) == 0 {
		return nil, fmt.Errorf("command array must not be empty")
	}
	command := make([]string, len(cmdSlice))
	for i, v := range cmdSlice {
		str, ok := v.(string)
		if !ok {
			return nil, fmt.Errorf("command[%d] must be a string", i)
		}
		command[i] = str
	}
	return command, nil
}

// checkExecutableAllowlist checks if the first element of command is allowed by the agent profile.
func (s *Server) checkExecutableAllowlist(command []string) error {
	if len(command) == 0 {
		return nil
	}
	if len(s.agent.AllowedExecutables) > 0 {
		exe := filepath.Base(command[0])
		allowed := false
		for _, a := range s.agent.AllowedExecutables {
			if exe == a {
				allowed = true
				break
			}
		}
		if !allowed {
			return fmt.Errorf("command execution denied: executable %q not in agent allowlist", exe)
		}
	}
	return nil
}

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
