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

const (
	RuntimePortFileName = ".runtime-port"
	RuntimeTLSFileName  = ".runtime-tls-cert"
)

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

// SaveRuntimeTLSCert records the certificate path used by the running HTTP
// server. It is intentionally separate from the port file: the server may use
// a command-line certificate override that is not persisted in config.yaml.
// The file is private to the vault directory and contains no key material.
func SaveRuntimeTLSCert(vaultDir, certFile string, clientAuthRequired ...bool) error {
	authRequired := len(clientAuthRequired) > 0 && clientAuthRequired[0]
	return SaveRuntimeTLSConfig(vaultDir, certFile, "", "", "", authRequired)
}

// SaveRuntimeTLSConfig records effective TLS paths; it never stores key material.
func SaveRuntimeTLSConfig(vaultDir, certFile, clientCAFile, clientCertFile, clientKeyFile string, clientAuthRequired bool) error {
	cleanDir := filepath.Clean(vaultDir)
	path := filepath.Join(cleanDir, RuntimeTLSFileName)
	if !strings.HasPrefix(filepath.Clean(path), cleanDir+string(filepath.Separator)) {
		return fmt.Errorf("invalid TLS certificate file path: outside vault directory")
	}
	if strings.TrimSpace(certFile) == "" {
		return fmt.Errorf("TLS certificate file path must not be empty")
	}
	data, err := json.Marshal(struct {
		Certificate        string `json:"certificate"`
		ClientCAFile       string `json:"client_ca_file,omitempty"`
		ClientCertificate  string `json:"client_certificate,omitempty"`
		ClientKey          string `json:"client_key,omitempty"`
		ClientAuthRequired bool   `json:"client_auth_required,omitempty"`
	}{Certificate: certFile, ClientCAFile: clientCAFile, ClientCertificate: clientCertFile, ClientKey: clientKeyFile, ClientAuthRequired: clientAuthRequired})
	if err != nil {
		return fmt.Errorf("marshal runtime TLS certificate file: %w", err)
	}
	return os.WriteFile(path, data, 0600)
}

// LoadRuntimeTLSCert returns the certificate path recorded by the running
// server, if any. Invalid or missing records are treated as unavailable.
type RuntimeTLSConfig struct {
	Certificate, ClientCAFile, ClientCertificate, ClientKey string
	ClientAuthRequired                                      bool
}

func LoadRuntimeTLSConfig(vaultDir string) (RuntimeTLSConfig, bool) {
	cleanDir := filepath.Clean(vaultDir)
	path := filepath.Join(cleanDir, RuntimeTLSFileName)
	data, err := os.ReadFile(path) // #nosec G304 -- fixed runtime metadata filename below the selected vault directory; the record holds no key material.
	if err != nil {
		return RuntimeTLSConfig{}, false
	}
	var record struct {
		Certificate        string `json:"certificate"`
		ClientCAFile       string `json:"client_ca_file"`
		ClientCertificate  string `json:"client_certificate"`
		ClientKey          string `json:"client_key"`
		ClientAuthRequired bool   `json:"client_auth_required"`
	}
	if err := json.Unmarshal(data, &record); err != nil || strings.TrimSpace(record.Certificate) == "" {
		return RuntimeTLSConfig{}, false
	}
	return RuntimeTLSConfig{strings.TrimSpace(record.Certificate), strings.TrimSpace(record.ClientCAFile), strings.TrimSpace(record.ClientCertificate), strings.TrimSpace(record.ClientKey), record.ClientAuthRequired}, true
}

func LoadRuntimeTLSCert(vaultDir string) (string, bool) {
	cfg, ok := LoadRuntimeTLSConfig(vaultDir)
	return cfg.Certificate, ok
}

// RuntimeTLSClientAuthRequired reports whether the running server requires
// a client certificate for its TLS connection.
func RuntimeTLSClientAuthRequired(vaultDir string) bool {
	cfg, ok := LoadRuntimeTLSConfig(vaultDir)
	return ok && cfg.ClientAuthRequired
}

// ClearRuntimeTLSCert removes the running server's certificate record.
func ClearRuntimeTLSCert(vaultDir string) error {
	cleanDir := filepath.Clean(vaultDir)
	path := filepath.Join(cleanDir, RuntimeTLSFileName)
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
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
