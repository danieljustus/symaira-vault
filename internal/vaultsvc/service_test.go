package vaultsvc

import (
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/danieljustus/symaira-vault/internal/config"
	errorspkg "github.com/danieljustus/symaira-vault/internal/errors"
	gitpkg "github.com/danieljustus/symaira-vault/internal/git"
	vaultpkg "github.com/danieljustus/symaira-vault/internal/vault"
)

var testPassphrase = []byte("test-passphrase")

func newTestService(t *testing.T, withGit bool) Service {
	t.Helper()

	vaultDir := t.TempDir()
	cfg := config.Default()
	cfg.Git = &config.GitConfig{AutoPush: false, CommitTemplate: "Update from Symaira Vault"}

	if _, err := vaultpkg.InitWithPassphrase(vaultDir, testPassphrase, cfg); err != nil {
		t.Fatalf("init vault: %v", err)
	}
	if withGit {
		if err := gitpkg.Init(vaultDir); err != nil {
			t.Fatalf("init git: %v", err)
		}
	}

	v, err := vaultpkg.OpenWithPassphrase(vaultDir, testPassphrase)
	if err != nil {
		t.Fatalf("open vault: %v", err)
	}
	return New(slog.Default(), v)
}

func writeTestEntry(t *testing.T, svc Service, path string, data map[string]any) {
	t.Helper()
	if err := svc.WriteEntry(path, &vaultpkg.Entry{Data: data}); err != nil {
		t.Fatalf("write entry %q: %v", path, err)
	}
}

func latestCommitMessage(t *testing.T, svc Service) string {
	t.Helper()
	commits, err := gitpkg.Log(svc.GetDir(), "", 1)
	if err != nil {
		t.Fatalf("read git log: %v", err)
	}
	if len(commits) == 0 {
		t.Fatal("expected at least one git commit")
	}
	return strings.TrimSpace(commits[0].Message)
}

func TestNewAndVault(t *testing.T) {
	svc := newTestService(t, false)
	if svc == nil {
		t.Fatal("New returned nil")
	}
	if svc.Vault() == nil {
		t.Fatal("Vault returned nil")
	}
	if svc.Vault().Dir != svc.GetDir() {
		t.Fatalf("Vault().Dir = %q, GetDir() = %q", svc.Vault().Dir, svc.GetDir())
	}
}

func TestGetField(t *testing.T) {
	svc := newTestService(t, false)
	data := map[string]any{
		"username": "alice",
		"password": "secret",
		"profile":  map[string]any{"email": "alice@example.com"},
	}
	writeTestEntry(t, svc, "work/aws", data)

	tests := []struct {
		name     string
		path     string
		field    string
		want     any
		wantKind errorspkg.ErrorKind
	}{
		{name: "existing field", path: "work/aws", field: "password", want: "secret"},
		{name: "non-existent entry", path: "missing", field: "password", wantKind: errorspkg.ErrNotFound},
		{name: "non-existent field", path: "work/aws", field: "missing", wantKind: errorspkg.ErrFieldNotFound},
		{name: "empty field returns data", path: "work/aws", field: "", want: data},
		{name: "nested entry path", path: "work/aws", field: "username", want: "alice"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := svc.GetField(tt.path, tt.field)
			if tt.wantKind != 0 || tt.name == "non-existent entry" {
				assertServiceErrorKind(t, err, tt.wantKind)
				return
			}
			if err != nil {
				t.Fatalf("GetField returned error: %v", err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("GetField() = %#v, want %#v", got, tt.want)
			}
		})
	}
}

func TestSetFieldAndSetFields(t *testing.T) {
	t.Run("create new entry", func(t *testing.T) {
		svc := newTestService(t, true)
		if err := svc.SetField("github", "password", "secret"); err != nil {
			t.Fatalf("SetField: %v", err)
		}
		got, err := svc.GetField("github", "password")
		if err != nil {
			t.Fatalf("GetField: %v", err)
		}
		if got != "secret" {
			t.Fatalf("password = %#v, want %q", got, "secret")
		}
		if msg := latestCommitMessage(t, svc); !strings.Contains(msg, "Update github") {
			t.Fatalf("latest commit message = %q, want Update github", msg)
		}
	})

	t.Run("update existing entry merges data", func(t *testing.T) {
		svc := newTestService(t, false)
		writeTestEntry(t, svc, "github", map[string]any{"username": "alice", "password": "old"})
		if err := svc.SetField("github", "password", "new"); err != nil {
			t.Fatalf("SetField: %v", err)
		}
		got, err := svc.GetField("github", "")
		if err != nil {
			t.Fatalf("GetField: %v", err)
		}
		want := map[string]any{"username": "alice", "password": "new"}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("merged data = %#v, want %#v", got, want)
		}
	})

	t.Run("set multiple fields", func(t *testing.T) {
		svc := newTestService(t, false)
		fields := map[string]any{"username": "alice", "password": "secret", "url": "https://example.com"}
		if err := svc.SetFields("example", fields); err != nil {
			t.Fatalf("SetFields: %v", err)
		}
		got, err := svc.GetField("example", "")
		if err != nil {
			t.Fatalf("GetField: %v", err)
		}
		if !reflect.DeepEqual(got, fields) {
			t.Fatalf("fields = %#v, want %#v", got, fields)
		}
	})
}

func TestSetFieldRejectsOverlengthValues(t *testing.T) {
	svc := newTestService(t, false)
	longValue := strings.Repeat("a", MaxFieldLength+1)
	err := svc.SetField("github", "password", longValue)
	if err == nil {
		t.Fatal("expected error for overlength field value")
	}
	if !strings.Contains(err.Error(), "exceeds maximum length") {
		t.Fatalf("error message = %q, want length exceeded", err.Error())
	}

	// Value exactly at limit should succeed.
	atLimit := strings.Repeat("b", MaxFieldLength)
	if err := svc.SetField("github", "notes", atLimit); err != nil {
		t.Fatalf("SetField at limit: %v", err)
	}
}

func TestSetFieldsWithProvenance(t *testing.T) {
	svc := newTestService(t, false)
	record := vaultpkg.WriteRecord{Action: "import"}
	if err := svc.SetFieldsWithProvenance("github", map[string]any{"password": "secret"}, record); err != nil {
		t.Fatalf("SetFieldsWithProvenance: %v", err)
	}

	entry, err := svc.GetEntry("github")
	if err != nil {
		t.Fatalf("GetEntry: %v", err)
	}
	if len(entry.Metadata.WriteHistory) != 1 {
		t.Fatalf("write history len = %d, want 1", len(entry.Metadata.WriteHistory))
	}
	if entry.Metadata.WriteHistory[0].Action != "import" {
		t.Errorf("action = %q, want %q", entry.Metadata.WriteHistory[0].Action, "import")
	}
}

func TestDelete(t *testing.T) {
	t.Run("delete existing entry commits", func(t *testing.T) {
		svc := newTestService(t, true)
		writeTestEntry(t, svc, "github", map[string]any{"password": "secret"})
		if err := svc.Delete("github"); err != nil {
			t.Fatalf("Delete: %v", err)
		}
		_, err := svc.GetEntry("github")
		assertServiceErrorKind(t, err, errorspkg.ErrNotFound)
		if msg := latestCommitMessage(t, svc); !strings.Contains(msg, "Delete github") {
			t.Fatalf("latest commit message = %q, want Delete github", msg)
		}
	})

	t.Run("delete missing entry", func(t *testing.T) {
		svc := newTestService(t, false)
		err := svc.Delete("missing")
		assertServiceErrorKind(t, err, errorspkg.ErrNotFound)
	})
}

func TestList(t *testing.T) {
	t.Run("all entries and prefix", func(t *testing.T) {
		svc := newTestService(t, false)
		writeTestEntry(t, svc, "github", map[string]any{"password": "secret"})
		writeTestEntry(t, svc, "work/aws", map[string]any{"password": "aws"})
		writeTestEntry(t, svc, "work/gcp", map[string]any{"password": "gcp"})

		all, err := svc.List("")
		if err != nil {
			t.Fatalf("List all: %v", err)
		}
		wantAll := []string{"github", "work/aws", "work/gcp"}
		if !reflect.DeepEqual(all, wantAll) {
			t.Fatalf("List all = %#v, want %#v", all, wantAll)
		}

		work, err := svc.List("work/")
		if err != nil {
			t.Fatalf("List prefix: %v", err)
		}
		wantWork := []string{"work/aws", "work/gcp"}
		if !reflect.DeepEqual(work, wantWork) {
			t.Fatalf("List prefix = %#v, want %#v", work, wantWork)
		}
	})

	t.Run("empty vault", func(t *testing.T) {
		svc := newTestService(t, false)
		got, err := svc.List("")
		if err != nil {
			t.Fatalf("List: %v", err)
		}
		if len(got) != 0 {
			t.Fatalf("List empty = %#v, want empty slice", got)
		}
	})
}

func TestFind(t *testing.T) {
	svc := newTestService(t, false)
	writeTestEntry(t, svc, "github", map[string]any{"username": "alice", "password": "secret"})
	writeTestEntry(t, svc, "work/aws", map[string]any{"username": "bob", "password": "cloud-secret"})

	tests := []struct {
		name      string
		query     string
		opts      vaultpkg.FindOptions
		wantPaths []string
	}{
		{name: "matching query", query: "cloud", wantPaths: []string{"work/aws"}},
		{name: "no results", query: "does-not-exist", wantPaths: []string{}},
		{name: "max workers option", query: "github", opts: vaultpkg.FindOptions{MaxWorkers: 2}, wantPaths: []string{"github"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches, err := svc.Find(tt.query, tt.opts)
			if err != nil {
				t.Fatalf("Find: %v", err)
			}
			gotPaths := make([]string, 0, len(matches))
			for _, match := range matches {
				gotPaths = append(gotPaths, match.Path)
			}
			slices.Sort(gotPaths)
			if !reflect.DeepEqual(gotPaths, tt.wantPaths) {
				t.Fatalf("Find paths = %#v, want %#v", gotPaths, tt.wantPaths)
			}
		})
	}
}

func TestGetEntry(t *testing.T) {
	svc := newTestService(t, false)
	writeTestEntry(t, svc, "github", map[string]any{"username": "alice"})

	entry, err := svc.GetEntry("github")
	if err != nil {
		t.Fatalf("GetEntry: %v", err)
	}
	if entry.Data["username"] != "alice" {
		t.Fatalf("username = %#v, want %q", entry.Data["username"], "alice")
	}
	if entry.Metadata.Version != 1 {
		t.Fatalf("version = %d, want 1", entry.Metadata.Version)
	}

	_, err = svc.GetEntry("missing")
	assertServiceErrorKind(t, err, errorspkg.ErrNotFound)
}

func TestWriteEntry(t *testing.T) {
	svc := newTestService(t, false)
	created := time.Date(2026, 4, 29, 12, 0, 0, 0, time.UTC)

	if err := svc.WriteEntry("github", &vaultpkg.Entry{
		Data:     map[string]any{"username": "alice", "password": "old"},
		Metadata: vaultpkg.EntryMetadata{Created: created},
	}); err != nil {
		t.Fatalf("WriteEntry new: %v", err)
	}
	entry, err := svc.GetEntry("github")
	if err != nil {
		t.Fatalf("GetEntry: %v", err)
	}
	if entry.Data["password"] != "old" {
		t.Fatalf("password = %#v, want old", entry.Data["password"])
	}

	if err := svc.WriteEntry("github", &vaultpkg.Entry{Data: map[string]any{"password": "new"}}); err != nil {
		t.Fatalf("WriteEntry overwrite: %v", err)
	}
	entry, err = svc.GetEntry("github")
	if err != nil {
		t.Fatalf("GetEntry after overwrite: %v", err)
	}
	if _, ok := entry.Data["username"]; ok {
		t.Fatalf("overwrite preserved username unexpectedly: %#v", entry.Data)
	}
	if entry.Data["password"] != "new" {
		t.Fatalf("password = %#v, want new", entry.Data["password"])
	}
}

func TestErrorTypes(t *testing.T) {
	cause := errors.New("disk full")

	tests := []struct {
		name string
		err  *errorspkg.CLIError
		want string
	}{
		{
			name: "without cause",
			err:  &errorspkg.CLIError{Code: errorspkg.ExitNotFound, Kind: errorspkg.ErrNotFound, Message: "missing entry"},
			want: "missing entry",
		},
		{
			name: "with cause",
			err:  &errorspkg.CLIError{Code: errorspkg.ExitGeneralError, Kind: errorspkg.ErrWriteFailed, Message: "write failed", Cause: cause},
			want: "write failed: disk full",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.err.Error(); got != tt.want {
				t.Fatalf("Error() = %q, want %q", got, tt.want)
			}
		})
	}

	wrappedNotFound := fmt.Errorf("outer: %w", &errorspkg.CLIError{Code: errorspkg.ExitNotFound, Kind: errorspkg.ErrNotFound, Message: "missing"})
	wrappedFieldNotFound := fmt.Errorf("outer: %w", &errorspkg.CLIError{Code: errorspkg.ExitNotFound, Kind: errorspkg.ErrFieldNotFound, Message: "field missing"})
	wrappedWrite := fmt.Errorf("outer: %w", &errorspkg.CLIError{Code: errorspkg.ExitGeneralError, Kind: errorspkg.ErrWriteFailed, Message: "write failed", Cause: cause})

	for _, err := range []error{wrappedNotFound, wrappedFieldNotFound} {
		if !errorspkg.IsNotFound(err) {
			t.Fatalf("IsNotFound(%v) = false, want true", err)
		}
	}
	for _, err := range []error{nil, cause, wrappedWrite, &errorspkg.CLIError{Code: errorspkg.ExitGeneralError, Kind: errorspkg.ErrReadFailed, Message: "read"}} {
		if errorspkg.IsNotFound(err) {
			t.Fatalf("IsNotFound(%v) = true, want false", err)
		}
	}

	if !errorspkg.IsWriteError(wrappedWrite) {
		t.Fatal("IsWriteError(wrapped write) = false, want true")
	}
	for _, err := range []error{nil, cause, wrappedNotFound, &errorspkg.CLIError{Code: errorspkg.ExitGeneralError, Kind: errorspkg.ErrReadFailed, Message: "read"}} {
		if errorspkg.IsWriteError(err) {
			t.Fatalf("IsWriteError(%v) = true, want false", err)
		}
	}

	var cliErr *errorspkg.CLIError
	if !errors.As(wrappedWrite, &cliErr) {
		t.Fatal("errors.As did not extract *CLIError")
	}
	if cliErr.Kind != errorspkg.ErrWriteFailed || !errors.Is(wrappedWrite, cause) {
		t.Fatalf("errors.As/Unwrap mismatch: cliErr=%#v", cliErr)
	}
}

func TestGetIdentityAndGetDir(t *testing.T) {
	svc := newTestService(t, false)
	if svc.GetIdentity() == nil {
		t.Fatal("GetIdentity returned nil")
	}
	if svc.GetIdentity() != svc.Vault().Identity {
		t.Fatal("GetIdentity did not return vault identity")
	}
	if svc.GetDir() == "" {
		t.Fatal("GetDir returned empty string")
	}
	if svc.GetDir() != svc.Vault().Dir {
		t.Fatalf("GetDir = %q, want %q", svc.GetDir(), svc.Vault().Dir)
	}
}

func TestServiceErrorPaths(t *testing.T) {
	svc := newTestService(t, false)

	_, err := svc.GetField("../bad", "password")
	assertServiceErrorKind(t, err, errorspkg.ErrReadFailed)

	err = svc.SetField("../bad", "password", "secret")
	assertServiceErrorKind(t, err, errorspkg.ErrReadFailed)

	err = svc.Delete("../bad")
	assertServiceErrorKind(t, err, errorspkg.ErrWriteFailed)

	_, err = svc.GetEntry("../bad")
	assertServiceErrorKind(t, err, errorspkg.ErrReadFailed)

	err = svc.WriteEntry("github", nil)
	assertServiceErrorKind(t, err, errorspkg.ErrWriteFailed)

	err = svc.WriteEntry("../bad", &vaultpkg.Entry{Data: map[string]any{"password": "secret"}})
	assertServiceErrorKind(t, err, errorspkg.ErrWriteFailed)

	missingVault := New(slog.Default(), &vaultpkg.Vault{Dir: filepath.Join(t.TempDir(), "missing"), Identity: svc.GetIdentity()})
	_, err = missingVault.List("")
	assertServiceErrorKind(t, err, errorspkg.ErrReadFailed)

	_, err = missingVault.Find("anything", vaultpkg.FindOptions{})
	assertServiceErrorKind(t, err, errorspkg.ErrReadFailed)
}

func assertServiceErrorKind(t *testing.T, err error, kind errorspkg.ErrorKind) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected CLIError kind %v, got nil", kind)
	}
	var cliErr *errorspkg.CLIError
	if !errors.As(err, &cliErr) {
		t.Fatalf("error %T is not *errorspkg.CLIError: %v", err, err)
	}
	if cliErr.Kind != kind {
		t.Fatalf("error kind = %v, want %v", cliErr.Kind, kind)
	}
}

func TestMockServiceImplementsService(t *testing.T) {
	var _ Service = NewMockService()
}

func TestMockServiceDefaults(t *testing.T) {
	mock := NewMockService()

	// All methods should return zero values without panicking
	if mock.Vault() == nil {
		t.Error("Vault returned nil")
	}
	if _, err := mock.GetField("path", "field"); err != nil {
		t.Errorf("GetField error: %v", err)
	}
	if err := mock.SetField("path", "field", "value"); err != nil {
		t.Errorf("SetField error: %v", err)
	}
	if err := mock.SetFields("path", map[string]any{"k": "v"}); err != nil {
		t.Errorf("SetFields error: %v", err)
	}
	if err := mock.Delete("path"); err != nil {
		t.Errorf("Delete error: %v", err)
	}
	if entries, err := mock.List("prefix"); err != nil {
		t.Errorf("List error: %v", err)
	} else if entries != nil {
		t.Error("List should return nil by default")
	}
	if matches, err := mock.Find("query", vaultpkg.FindOptions{}); err != nil {
		t.Errorf("Find error: %v", err)
	} else if matches != nil {
		t.Error("Find should return nil by default")
	}
	if entry, err := mock.GetEntry("path"); err != nil {
		t.Errorf("GetEntry error: %v", err)
	} else if entry == nil {
		t.Error("GetEntry returned nil")
	}
	if err := mock.WriteEntry("path", &vaultpkg.Entry{}); err != nil {
		t.Errorf("WriteEntry error: %v", err)
	}
	if mock.GetIdentity() != nil {
		t.Error("GetIdentity should return nil by default")
	}
	if mock.GetDir() != "/mock/dir" {
		t.Errorf("GetDir = %q, want %q", mock.GetDir(), "/mock/dir")
	}
}

func TestMockServiceCustomBehavior(t *testing.T) {
	mock := NewMockService()

	mock.GetFieldFunc = func(path, field string) (any, error) {
		return "custom-value", nil
	}

	value, err := mock.GetField("any", "field")
	if err != nil {
		t.Fatalf("GetField error: %v", err)
	}
	if value != "custom-value" {
		t.Errorf("GetField = %#v, want %q", value, "custom-value")
	}

	mock.SetFieldFunc = func(path, field string, value any) error {
		return nil
	}
	if err := mock.SetField("path", "field", "value"); err != nil {
		t.Errorf("SetField error: %v", err)
	}
}
