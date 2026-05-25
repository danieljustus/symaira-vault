package installmethod

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestDetectEmptyPath(t *testing.T) {
	t.Parallel()
	method, err := Detect("")
	if method != Unknown {
		t.Fatalf("Detect('') method = %q, want %q", method, Unknown)
	}
	if err != ErrEmptyBinaryPath {
		t.Fatalf("Detect('') err = %v, want %v", err, ErrEmptyBinaryPath)
	}
}

func TestDetectHomebrewPaths(t *testing.T) {
	t.Parallel()
	if runtime.GOOS == "windows" {
		t.Skip("skipping on windows: Unix-specific path test")
	}
	tests := []struct {
		name string
		path string
	}{
		{name: "Apple Silicon", path: "/opt/homebrew/bin/symaira"},
		{name: "Intel Cellar", path: "/usr/local/Cellar/symaira/1.0.0/bin/symaira"},
		{name: "Linuxbrew", path: "/home/linuxbrew/.linuxbrew/bin/symaira"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			method, err := Detect(tt.path)
			if err != nil {
				t.Fatalf("Detect(%q) error = %v", tt.path, err)
			}
			if method != Homebrew {
				t.Fatalf("Detect(%q) = %q, want %q", tt.path, method, Homebrew)
			}
		})
	}
}

func TestDetectDirectDownloadPaths(t *testing.T) {
	t.Parallel()
	if runtime.GOOS == "windows" {
		t.Skip("skipping on windows: Unix-specific path test")
	}
	tests := []struct {
		name string
		path string
	}{
		{name: "user local bin", path: "/usr/local/bin/symaira"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			method, err := Detect(tt.path)
			if err != nil {
				t.Fatalf("Detect(%q) error = %v", tt.path, err)
			}
			if method != DirectDownload {
				t.Fatalf("Detect(%q) = %q, want %q", tt.path, method, DirectDownload)
			}
		})
	}
}

func TestDetectPackageManagerPath(t *testing.T) {
	t.Parallel()
	if runtime.GOOS == "windows" {
		t.Skip("skipping on windows: Unix-specific path test")
	}
	method, err := Detect("/usr/bin/symaira")
	if err != nil {
		t.Fatalf("Detect() error = %v", err)
	}
	if method != PackageManager {
		t.Fatalf("Detect() = %q, want %q", method, PackageManager)
	}
}

func TestDetectGoInstallFromGopath(t *testing.T) {
	t.Parallel()
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skipf("cannot determine home dir: %v", err)
	}
	goBin := filepath.Join(home, "go", "bin", "symaira")
	method, err := Detect(goBin)
	if err != nil {
		t.Fatalf("Detect(%q) error = %v", goBin, err)
	}
	if method != GoInstall {
		t.Fatalf("Detect(%q) = %q, want %q", goBin, method, GoInstall)
	}
}

func setEnv(t *testing.T, key, value string) {
	t.Helper()
	t.Cleanup(func() {
		os.Unsetenv(key)
	})
	os.Setenv(key, value)
}

// envTests groups tests that must not run in parallel because they modify
// global process environment via os.Setenv.
func TestDetectEnvVars(t *testing.T) {
	tmp := t.TempDir()

	t.Run("GOPATH env", func(t *testing.T) {
		binary := filepath.Join(tmp, "bin", "symaira")
		if err := os.MkdirAll(filepath.Dir(binary), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(binary, []byte("fake"), 0644); err != nil {
			t.Fatal(err)
		}
		setEnv(t, "GOPATH", tmp)
		method, err := Detect(binary)
		if err != nil {
			t.Fatalf("Detect() error = %v", err)
		}
		if method != GoInstall {
			t.Fatalf("Detect() = %q, want %q", method, GoInstall)
		}
	})

	t.Run("GOMODCACHE env", func(t *testing.T) {
		binary := filepath.Join(tmp, "bin", "symaira")
		if err := os.MkdirAll(filepath.Dir(binary), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(binary, []byte("fake"), 0644); err != nil {
			t.Fatal(err)
		}
		setEnv(t, "GOMODCACHE", tmp)
		method, err := Detect(binary)
		if err != nil {
			t.Fatalf("Detect() error = %v", err)
		}
		if method != GoInstall {
			t.Fatalf("Detect() = %q, want %q", method, GoInstall)
		}
	})

	t.Run("HOMEBREW_PREFIX env", func(t *testing.T) {
		binary := filepath.Join(tmp, "bin", "symaira")
		if err := os.MkdirAll(filepath.Dir(binary), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(binary, []byte("fake"), 0644); err != nil {
			t.Fatal(err)
		}
		setEnv(t, "HOMEBREW_PREFIX", tmp)
		method, err := Detect(binary)
		if err != nil {
			t.Fatalf("Detect() error = %v", err)
		}
		if method != Homebrew {
			t.Fatalf("Detect() = %q, want %q", method, Homebrew)
		}
	})

	t.Run("layered order env over path", func(t *testing.T) {
		binary := filepath.Join(tmp, "opt", "homebrew", "bin", "symaira")
		if err := os.MkdirAll(filepath.Dir(binary), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(binary, []byte("fake"), 0644); err != nil {
			t.Fatal(err)
		}
		setEnv(t, "HOMEBREW_PREFIX", filepath.Join(tmp, "opt", "homebrew"))
		method, err := Detect(binary)
		if err != nil {
			t.Fatalf("Detect() error = %v", err)
		}
		if method != Homebrew {
			t.Fatalf("Detect() = %q, want %q (env var should take priority)", method, Homebrew)
		}
	})
}

func TestDetectGoCacheMarkers(t *testing.T) {
	t.Parallel()
	if runtime.GOOS == "windows" {
		t.Skip("skipping on windows: Unix-specific path test")
	}
	method, err := Detect("/go/pkg/mod/github.com/danieljustus/symaira-vault@v1.0.0/bin/symaira")
	if err != nil {
		t.Fatalf("Detect() error = %v", err)
	}
	if method != GoInstall {
		t.Fatalf("Detect() = %q, want %q", method, GoInstall)
	}
}

func TestDetectGoInstallAtSign(t *testing.T) {
	t.Parallel()
	if runtime.GOOS == "windows" {
		t.Skip("skipping on windows: Unix-specific path test")
	}
	method, err := Detect("/tmp/gopath/pkg/mod/example.com/symaira@latest/bin/symaira")
	if err != nil {
		t.Fatalf("Detect() error = %v", err)
	}
	if method != GoInstall {
		t.Fatalf("Detect() = %q, want %q", method, GoInstall)
	}
}

func TestDetectUserLocalBins(t *testing.T) {
	t.Parallel()
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skipf("cannot determine home dir: %v", err)
	}

	tests := []struct {
		name string
		path string
	}{
		{name: "home bin", path: filepath.Join(home, "bin", "symaira")},
		{name: "local bin", path: filepath.Join(home, ".local", "bin", "symaira")},
		{name: "cargo bin", path: filepath.Join(home, ".cargo", "bin", "symaira")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			method, err := Detect(tt.path)
			if err != nil {
				t.Fatalf("Detect(%q) error = %v", tt.path, err)
			}
			if method != DirectDownload {
				t.Fatalf("Detect(%q) = %q, want %q", tt.path, method, DirectDownload)
			}
		})
	}
}

func TestDetectHomebrewSymlink(t *testing.T) {
	t.Parallel()
	if runtime.GOOS == "windows" {
		t.Skip("skipping on windows: Unix-specific path test")
	}
	tmp := t.TempDir()

	realBin := filepath.Join(tmp, "Cellar", "symaira", "1.0.0", "bin", "symaira")
	if err := os.MkdirAll(filepath.Dir(realBin), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(realBin, []byte("fake"), 0644); err != nil {
		t.Fatal(err)
	}

	symlinkPath := filepath.Join(tmp, "bin", "symaira")
	if err := os.MkdirAll(filepath.Dir(symlinkPath), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(realBin, symlinkPath); err != nil {
		t.Skipf("cannot create symlink: %v", err)
	}

	method, err := Detect(symlinkPath)
	if err != nil {
		t.Fatalf("Detect() error = %v", err)
	}
	if method != Homebrew {
		t.Fatalf("Detect() = %q, want %q (resolves to Cellar path)", method, Homebrew)
	}
}

func TestDetectUnknownPath(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	binary := filepath.Join(tmp, "symaira")
	if err := os.WriteFile(binary, []byte("fake"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(tmp, 0555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(tmp, 0755) })

	method, err := Detect(binary)
	if err != nil {
		t.Fatalf("Detect() error = %v", err)
	}
	if method != BuildFromSource {
		t.Fatalf("Detect() = %q, want %q", method, BuildFromSource)
	}
}

func TestDetectNonExistentPath(t *testing.T) {
	t.Parallel()
	if runtime.GOOS == "windows" {
		t.Skip("skipping on windows: Unix-specific path test")
	}
	method, err := Detect("/nonexistent/symaira")
	if err != nil {
		t.Fatalf("Detect() error = %v", err)
	}
	if method != Unknown {
		t.Fatalf("Detect() = %q, want %q", method, Unknown)
	}
}

func TestIsSelfUpdateSupported(t *testing.T) {
	t.Parallel()
	tests := []struct {
		method InstallMethod
		want   bool
	}{
		{method: DirectDownload, want: true},
		{method: Homebrew, want: false},
		{method: GoInstall, want: false},
		{method: PackageManager, want: false},
		{method: BuildFromSource, want: false},
		{method: Unknown, want: false},
	}
	for _, tt := range tests {
		t.Run(string(tt.method), func(t *testing.T) {
			got := IsSelfUpdateSupported(tt.method)
			if got != tt.want {
				t.Fatalf("IsSelfUpdateSupported(%q) = %v, want %v", tt.method, got, tt.want)
			}
		})
	}
}

func TestGuidance(t *testing.T) {
	t.Parallel()
	tests := []struct {
		method InstallMethod
		want   string
	}{
		{method: DirectDownload, want: "curl"},
		{method: Homebrew, want: "brew upgrade"},
		{method: GoInstall, want: "go install"},
		{method: PackageManager, want: "apt"},
		{method: BuildFromSource, want: "git pull"},
		{method: Unknown, want: "Unable to determine"},
	}
	for _, tt := range tests {
		t.Run(string(tt.method), func(t *testing.T) {
			got := Guidance(tt.method)
			if got == "" {
				t.Fatalf("Guidance(%q) = empty string", tt.method)
			}
			if got != tt.want && !containsAny(got, tt.want) {
				t.Fatalf("Guidance(%q) = %q, want it to contain %q", tt.method, got, tt.want)
			}
			if tt.method == DirectDownload && !containsAny(got, "install.sh") {
				t.Fatalf("Guidance(DirectDownload) = %q, should mention install.sh", got)
			}
		})
	}
}

func TestGuidanceDefault(t *testing.T) {
	t.Parallel()
	got := Guidance("bogus")
	if got != "" {
		t.Fatalf("Guidance(bogus) = %q, want empty string", got)
	}
}

func TestConstantsAreStrings(t *testing.T) {
	t.Parallel()
	if string(DirectDownload) != "direct-download" {
		t.Fatalf("DirectDownload = %q", DirectDownload)
	}
	if string(Homebrew) != "homebrew" {
		t.Fatalf("Homebrew = %q", Homebrew)
	}
	if string(GoInstall) != "go-install" {
		t.Fatalf("GoInstall = %q", GoInstall)
	}
	if string(PackageManager) != "package-manager" {
		t.Fatalf("PackageManager = %q", PackageManager)
	}
	if string(BuildFromSource) != "build-from-source" {
		t.Fatalf("BuildFromSource = %q", BuildFromSource)
	}
	if string(Unknown) != "unknown" {
		t.Fatalf("Unknown = %q", Unknown)
	}
}

func containsAny(s, substr string) bool {
	return len(substr) > 0 && containsStr(s, substr)
}

func containsStr(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
