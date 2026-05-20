package vault

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDeviceManager_NewDeviceManager(t *testing.T) {
	dm := NewDeviceManager("/tmp/test-vault")
	if dm == nil {
		t.Fatal("NewDeviceManager returned nil")
	}
}

func TestDeviceManager_DevicesPath(t *testing.T) {
	dm := NewDeviceManager("/tmp/test-vault")
	expected := "/tmp/test-vault/.openpass/devices.json"
	if got := dm.devicesPath(); got != expected {
		t.Errorf("devicesPath() = %q, want %q", got, expected)
	}
}

func TestDeviceManager_LoadDevices_Empty(t *testing.T) {
	dm := NewDeviceManager(t.TempDir())
	devices, err := dm.LoadDevices()
	if err != nil {
		t.Fatalf("LoadDevices() error = %v", err)
	}
	if len(devices) != 0 {
		t.Errorf("LoadDevices() returned %d devices, want 0", len(devices))
	}
}

func TestDeviceManager_Roundtrip(t *testing.T) {
	dir := t.TempDir()
	dm := NewDeviceManager(dir)

	now := time.Now()
	device := Device{
		Name:      "my-device",
		PublicKey: "age1publickey...",
		AddedAt:   now,
	}

	if err := dm.AddDevice(device); err != nil {
		t.Fatalf("AddDevice() error = %v", err)
	}

	loaded, err := dm.LoadDevices()
	if err != nil {
		t.Fatalf("LoadDevices() error = %v", err)
	}
	if len(loaded) != 1 {
		t.Fatalf("LoadDevices() returned %d devices, want 1", len(loaded))
	}
	if loaded[0].Name != "my-device" {
		t.Errorf("device name = %q, want %q", loaded[0].Name, "my-device")
	}
}

func TestDeviceManager_AddDevice_Update(t *testing.T) {
	dir := t.TempDir()
	dm := NewDeviceManager(dir)

	device := Device{Name: "device1", PublicKey: "key1"}
	if err := dm.AddDevice(device); err != nil {
		t.Fatalf("AddDevice() error = %v", err)
	}

	updated := Device{Name: "device1", PublicKey: "key2"}
	if err := dm.AddDevice(updated); err != nil {
		t.Fatalf("AddDevice() update error = %v", err)
	}

	loaded, _ := dm.LoadDevices()
	if len(loaded) != 1 {
		t.Fatalf("expected 1 device after update, got %d", len(loaded))
	}
	if loaded[0].PublicKey != "key2" {
		t.Errorf("public key = %q, want %q", loaded[0].PublicKey, "key2")
	}
}

func TestDeviceManager_RemoveDevice(t *testing.T) {
	dir := t.TempDir()
	dm := NewDeviceManager(dir)

	dm.AddDevice(Device{Name: "device1", PublicKey: "key1"})
	dm.AddDevice(Device{Name: "device2", PublicKey: "key2"})

	if err := dm.RemoveDevice("device1"); err != nil {
		t.Fatalf("RemoveDevice() error = %v", err)
	}

	loaded, _ := dm.LoadDevices()
	if len(loaded) != 1 {
		t.Fatalf("expected 1 device after removal, got %d", len(loaded))
	}
	if loaded[0].Name != "device2" {
		t.Errorf("remaining device = %q, want %q", loaded[0].Name, "device2")
	}
}

func TestDeviceManager_RemoveDevice_NotFound(t *testing.T) {
	dir := t.TempDir()
	dm := NewDeviceManager(dir)
	err := dm.RemoveDevice("nonexistent")
	if err == nil {
		t.Fatal("RemoveDevice() error = nil, want not found error")
	}
}

func TestDeviceManager_GetDevice(t *testing.T) {
	dir := t.TempDir()
	dm := NewDeviceManager(dir)
	dm.AddDevice(Device{Name: "device1", PublicKey: "key1"})

	device, err := dm.GetDevice("device1")
	if err != nil {
		t.Fatalf("GetDevice() error = %v", err)
	}
	if device == nil {
		t.Fatal("GetDevice() returned nil")
	}
	if device.Name != "device1" {
		t.Errorf("device name = %q, want %q", device.Name, "device1")
	}
}

func TestDeviceManager_GetDevice_NotFound(t *testing.T) {
	dir := t.TempDir()
	dm := NewDeviceManager(dir)
	device, err := dm.GetDevice("nonexistent")
	if err != nil {
		t.Fatalf("GetDevice() error = %v", err)
	}
	if device != nil {
		t.Fatal("GetDevice() should return nil for missing device")
	}
}

func TestDeviceManager_ListDevices(t *testing.T) {
	dir := t.TempDir()
	dm := NewDeviceManager(dir)
	dm.AddDevice(Device{Name: "d1", PublicKey: "k1"})
	dm.AddDevice(Device{Name: "d2", PublicKey: "k2"})

	devices, err := dm.ListDevices()
	if err != nil {
		t.Fatalf("ListDevices() error = %v", err)
	}
	if len(devices) != 2 {
		t.Fatalf("ListDevices() returned %d devices, want 2", len(devices))
	}
}

func TestDeviceManager_LoadDevices_CorruptFile(t *testing.T) {
	dir := t.TempDir()
	dm := NewDeviceManager(dir)

	devicesPath := filepath.Join(dir, ".openpass", "devices.json")
	os.MkdirAll(filepath.Dir(devicesPath), 0o700)
	os.WriteFile(devicesPath, []byte("invalid json"), 0o600)

	_, err := dm.LoadDevices()
	if err == nil {
		t.Fatal("LoadDevices() error = nil, want parse error for corrupt file")
	}
}
