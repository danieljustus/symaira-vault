package cli

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const RuntimePortFileName = ".runtime-port"

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

func SaveRuntimePort(vaultDir string, port int) error {
	cleanDir := filepath.Clean(vaultDir)
	portFile := filepath.Join(cleanDir, RuntimePortFileName)
	cleanPath := filepath.Clean(portFile)
	if !strings.HasPrefix(cleanPath, cleanDir+string(filepath.Separator)) {
		return fmt.Errorf("invalid port file path: outside vault directory")
	}
	return os.WriteFile(cleanPath, []byte(strconv.Itoa(port)), 0600)
}

func LoadRuntimePort(vaultDir string) (int, bool) {
	cleanDir := filepath.Clean(vaultDir)
	portFile := filepath.Join(cleanDir, RuntimePortFileName)
	cleanPath := filepath.Clean(portFile)
	if !strings.HasPrefix(cleanPath, cleanDir+string(filepath.Separator)) {
		return 0, false
	}
	data, err := os.ReadFile(cleanPath)
	if err != nil {
		return 0, false
	}
	port, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		return 0, false
	}
	return port, true
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
