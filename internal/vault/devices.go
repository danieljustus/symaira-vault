package vault

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/danieljustus/symaira-vault/internal/config"
)

// Device represents a known device in the vault's device registry.
type Device struct {
	Name      string     `json:"name"`
	PublicKey string     `json:"public_key"`
	AddedAt   time.Time  `json:"added_at"`
	LastSeen  *time.Time `json:"last_seen,omitempty"`
}

// DeviceManager manages the local device registry stored in .symvault/devices.json.
type DeviceManager struct {
	vaultDir string
}

// NewDeviceManager creates a new DeviceManager for the given vault directory.
func NewDeviceManager(vaultDir string) *DeviceManager {
	return &DeviceManager{vaultDir: vaultDir}
}

func (dm *DeviceManager) devicesPath() string {
	return filepath.Join(dm.vaultDir, config.DefaultVaultSubdir, "devices.json")
}

func (dm *DeviceManager) ensureDir() error {
	dir := filepath.Dir(dm.devicesPath())
	return os.MkdirAll(dir, 0o700)
}

// LoadDevices reads the device registry from disk.
func (dm *DeviceManager) LoadDevices() ([]Device, error) {
	path := dm.devicesPath()
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return []Device{}, nil
	}

	// #nosec G304 -- path is the devices.json file within the vault directory
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read devices file: %w", err)
	}

	var devices []Device
	if err := json.Unmarshal(data, &devices); err != nil {
		return nil, fmt.Errorf("parse devices file: %w", err)
	}

	return devices, nil
}

// SaveDevices writes the device registry to disk.
func (dm *DeviceManager) SaveDevices(devices []Device) error {
	if err := dm.ensureDir(); err != nil {
		return fmt.Errorf("create devices dir: %w", err)
	}

	data, err := json.MarshalIndent(devices, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal devices: %w", err)
	}

	if err := os.WriteFile(dm.devicesPath(), data, 0o600); err != nil {
		return fmt.Errorf("write devices file: %w", err)
	}

	return nil
}

// AddDevice adds a device to the registry. If a device with the same name exists, it is updated.
func (dm *DeviceManager) AddDevice(device Device) error {
	devices, err := dm.LoadDevices()
	if err != nil {
		return err
	}

	for i, d := range devices {
		if d.Name == device.Name {
			devices[i] = device
			return dm.SaveDevices(devices)
		}
	}

	devices = append(devices, device)
	return dm.SaveDevices(devices)
}

// RemoveDevice removes a device from the registry by name.
func (dm *DeviceManager) RemoveDevice(name string) error {
	devices, err := dm.LoadDevices()
	if err != nil {
		return err
	}

	found := false
	filtered := make([]Device, 0, len(devices))
	for _, d := range devices {
		if d.Name == name {
			found = true
			continue
		}
		filtered = append(filtered, d)
	}

	if !found {
		return fmt.Errorf("device %q not found", name)
	}

	return dm.SaveDevices(filtered)
}

// GetDevice returns a device by name, or nil if not found.
func (dm *DeviceManager) GetDevice(name string) (*Device, error) {
	devices, err := dm.LoadDevices()
	if err != nil {
		return nil, err
	}

	for _, d := range devices {
		if d.Name == name {
			return &d, nil
		}
	}

	return nil, nil
}

// ListDevices returns all registered devices.
func (dm *DeviceManager) ListDevices() ([]Device, error) {
	return dm.LoadDevices()
}
