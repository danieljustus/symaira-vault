package cli

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const RuntimePortFileName = ".runtime-port"

// runtimePortFile is the on-disk shape written by SaveRuntimePort. Bind is
// omitted by callers that don't have a bind address to record.
type runtimePortFile struct {
	Port int    `json:"port"`
	Bind string `json:"bind,omitempty"`
}

func FindAvailablePort(bind string, preferredPort int) (port int, isPreferred bool, err error) {
	addr := fmt.Sprintf("%s:%d", bind, preferredPort)
	listener, err := net.Listen("tcp", addr)
	if err == nil {
		if closeErr := listener.Close(); closeErr != nil {
			return 0, false, fmt.Errorf("close preferred port probe: %w", closeErr)
		}
		return preferredPort, true, nil
	}

	listener, err = net.Listen("tcp", fmt.Sprintf("%s:0", bind))
	if err != nil {
		return 0, false, fmt.Errorf("no available port found in range %s:*: %w", bind, err)
	}
	defer func() { _ = listener.Close() }()

	actualPort, ok := listener.Addr().(*net.TCPAddr)
	if !ok {
		return 0, false, fmt.Errorf("failed to get TCP address from listener")
	}
	return actualPort.Port, false, nil
}

// SaveRuntimePort persists the running server's port and bind address, so
// other commands (e.g. "device approval-pair") can tell whether the server
// is reachable only from loopback. bind may be empty when unknown.
func SaveRuntimePort(vaultDir, bind string, port int) error {
	cleanDir := filepath.Clean(vaultDir)
	portFile := filepath.Join(cleanDir, RuntimePortFileName)
	cleanPath := filepath.Clean(portFile)
	if !strings.HasPrefix(cleanPath, cleanDir+string(filepath.Separator)) {
		return fmt.Errorf("invalid port file path: outside vault directory")
	}
	data, err := json.Marshal(runtimePortFile{Port: port, Bind: bind})
	if err != nil {
		return fmt.Errorf("marshal runtime port file: %w", err)
	}
	return os.WriteFile(cleanPath, data, 0600)
}

// LoadRuntimeServer returns the persisted port and bind address, if any.
// bind is empty when the file predates bind tracking (the legacy format was
// a bare decimal port number) or the value was never recorded.
func LoadRuntimeServer(vaultDir string) (port int, bind string, ok bool) {
	cleanDir := filepath.Clean(vaultDir)
	portFile := filepath.Join(cleanDir, RuntimePortFileName)
	cleanPath := filepath.Clean(portFile)
	if !strings.HasPrefix(cleanPath, cleanDir+string(filepath.Separator)) {
		return 0, "", false
	}
	data, err := os.ReadFile(cleanPath)
	if err != nil {
		return 0, "", false
	}
	var rf runtimePortFile
	if unmarshalErr := json.Unmarshal(data, &rf); unmarshalErr == nil && rf.Port > 0 {
		return rf.Port, rf.Bind, true
	}
	// Legacy format: a bare decimal port number, no bind info.
	p, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		return 0, "", false
	}
	return p, "", true
}

// LoadRuntimePort returns the persisted port, discarding the bind address.
// See LoadRuntimeServer for callers that need the bind address too.
func LoadRuntimePort(vaultDir string) (int, bool) {
	port, _, ok := LoadRuntimeServer(vaultDir)
	return port, ok
}

func ClearRuntimePort(vaultDir string) error {
	cleanDir := filepath.Clean(vaultDir)
	portFile := filepath.Join(cleanDir, RuntimePortFileName)
	cleanPath := filepath.Clean(portFile)
	if !strings.HasPrefix(cleanPath, cleanDir+string(filepath.Separator)) {
		return fmt.Errorf("invalid port file path: outside vault directory")
	}
	if err := os.Remove(cleanPath); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

func ResolvePort(vaultDir string, configuredPort int) int {
	if port, ok := LoadRuntimePort(vaultDir); ok {
		return port
	}
	if configuredPort > 0 {
		return configuredPort
	}
	return 8080
}
