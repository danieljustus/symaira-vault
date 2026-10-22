package cmd

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	crud "github.com/danieljustus/symaira-vault/cmd/crud"
	"github.com/danieljustus/symaira-vault/internal/cli"
	clipboardapp "github.com/danieljustus/symaira-vault/internal/clipboard"
	vaultpkg "github.com/danieljustus/symaira-vault/internal/vault"
)

// TestGenerateGetClipboardFixture freezes the user-visible clipboard path of
// `symvault get` (PLATFORM-001, #1244 slice 2) from the production command:
//
//   - the routing decision (clipboard vs stdout),
//   - clipboard.Countdown driven by the real goroutine,
//   - clipboard.VerifyCleared and ErrClipboardNotCleared, including exactly
//     which stderr bytes, exit code and clipboard operations result.
//
// The clipboard is an in-memory fake; no desktop clipboard is read or written,
// and the vault holds synthetic data in a throwaway directory. Timing-sensitive
// scenarios use margins of at least 500ms so the recorded stderr is
// deterministic: a stubbed StartAutoClear waits a fixed time and then runs the
// production clear callback, which is exactly what the cmd tests already do.
// The real StartAutoClear is exercised once, by SIGTERM (unix only).
//
// Not recorded: the race between the final countdown tick and the timer when
// both fire at the same instant (Go prints "0s" or not depending on the
// scheduler); the fixture only contains scenarios where that race cannot occur.
func TestGenerateGetClipboardFixture(t *testing.T) {
	mode := os.Getenv("SYMVAULT_GET_CLIPBOARD_FIXTURE")
	if mode == "" {
		t.Skip("set SYMVAULT_GET_CLIPBOARD_FIXTURE=write or check")
	}
	if runtime.GOOS == "windows" {
		t.Skip("cmd tests are skipped on Windows (see TestMain)")
	}
	root := ".."
	const pin = "861ad93813e3ee43c4ec989f45940d14b05b6eaf"
	files := []string{
		"cmd/crud/get.go",
		"internal/clipboard/clipboard.go",
		"internal/clipboard/clipboard_signal_unix.go",
		"internal/clipboard/interface.go",
		"internal/ui/cliout/cliout.go",
	}
	hash := sha256.New()
	for _, name := range files {
		source, err := os.ReadFile(filepath.Join(root, name)) // #nosec G304 -- fixed compiled-in source list
		if err != nil {
			t.Fatal(err)
		}
		// #nosec G204 -- fixed git operation over compiled-in source paths and immutable pin
		show := exec.Command("git", "show", pin+":"+name)
		show.Dir = root
		pinned, err := show.Output()
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(source, pinned) {
			t.Fatalf("oracle source drift: %s", name)
		}
		_, _ = hash.Write([]byte(name + "\x00"))
		_, _ = hash.Write(source)
		_, _ = hash.Write([]byte{0})
	}
	generator, err := os.ReadFile("get_clipboard_fixture_generator_test.go")
	if err != nil {
		t.Fatal(err)
	}
	generatorHash := sha256.Sum256(generator)

	out := getClipboardFixture{
		Commit:        pin,
		SourceFiles:   files,
		SourceHash:    hex.EncodeToString(hash.Sum(nil)),
		GeneratorHash: hex.EncodeToString(generatorHash[:]),
		Note:          "Recorded from the production `get` command (cobra root + cli.ExecuteRoot) with an in-memory clipboard; no host clipboard or credential was used.",
	}
	for _, s := range getClipboardScenarios() {
		out.Scenarios = append(out.Scenarios, runGetClipboardScenario(t, s))
	}
	out.VerifyCleared = recordVerifyCleared()
	out.Countdown = recordCountdown()

	var buf bytes.Buffer
	encoder := json.NewEncoder(&buf)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(out); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "testdata/port/platform/get_clipboard.json")
	if mode == "write" {
		if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
			t.Fatal(err)
		}
		return
	}
	existing, err := os.ReadFile(path) // #nosec G304 -- fixed fixture path under the repository root
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(existing, buf.Bytes()) {
		t.Fatal("get clipboard fixture stale; regenerate with SYMVAULT_GET_CLIPBOARD_FIXTURE=write")
	}
}

const envPassphraseNotice = "SYMVAULT_PASSPHRASE is active — environment passphrases are visible in process listings and crash dumps.\n"

type getClipboardFixture struct {
	Commit        string               `json:"commit"`
	SourceFiles   []string             `json:"source_files"`
	SourceHash    string               `json:"source_hash"`
	GeneratorHash string               `json:"generator_hash"`
	Note          string               `json:"note"`
	Scenarios     []getClipboardResult `json:"scenarios"`
	VerifyCleared []verifyClearedCase  `json:"verify_cleared"`
	Countdown     []countdownCase      `json:"countdown"`
}

// getClipboardScenario is the recorded input. ReadMode selects what the fake
// clipboard returns from Read after the clear.
type getClipboardScenario struct {
	Name            string `json:"name"`
	Secret          string `json:"secret"`
	AutoClear       int    `json:"auto_clear_seconds"`
	Terminal        bool   `json:"stdout_terminal"`
	CopyByDefault   *bool  `json:"copy_by_default,omitempty"`
	Print           bool   `json:"print"`
	JSON            bool   `json:"json"`
	Quiet           bool   `json:"quiet"`
	CopyError       string `json:"copy_error,omitempty"`
	ClearError      string `json:"clear_error,omitempty"`
	ReadMode        string `json:"read_mode,omitempty"` // honest | restore_secret | other | error
	ReadError       string `json:"read_error,omitempty"`
	TimerStubMillis int    `json:"timer_stub_ms,omitempty"`
	SignalAfterMs   int    `json:"signal_after_ms,omitempty"` // real StartAutoClear + SIGTERM
}

type getClipboardResult struct {
	getClipboardScenario
	Stdout                string   `json:"stdout"`
	Stderr                string   `json:"stderr"`
	ExitCode              int      `json:"exit_code"`
	Ops                   []string `json:"clipboard_ops"`
	FinalClipboard        string   `json:"final_clipboard"`
	StartAutoClearSeconds int      `json:"start_auto_clear_seconds"`
}

func getClipboardScenarios() []getClipboardScenario {
	f := false
	return []getClipboardScenario{
		{Name: "cleared_one_second", Secret: "s3cret-one", AutoClear: 1, Terminal: true, TimerStubMillis: 150, ReadMode: "honest"},
		{Name: "cleared_two_seconds_ticks", Secret: "s3cret-two", AutoClear: 2, Terminal: true, TimerStubMillis: 1500, ReadMode: "honest"},
		{Name: "history_manager_restores_secret", Secret: "s3cret-hist", AutoClear: 1, Terminal: true, TimerStubMillis: 150, ReadMode: "restore_secret"},
		{Name: "history_manager_restores_secret_quiet", Secret: "s3cret-hist", AutoClear: 1, Terminal: true, Quiet: true, TimerStubMillis: 150, ReadMode: "restore_secret"},
		{Name: "clipboard_replaced_by_user", Secret: "s3cret-repl", AutoClear: 1, Terminal: true, TimerStubMillis: 150, ReadMode: "other"},
		{Name: "verify_read_error", Secret: "s3cret-rerr", AutoClear: 1, Terminal: true, TimerStubMillis: 150, ReadMode: "error", ReadError: "paste tool exploded"},
		{Name: "clear_fails_then_still_present", Secret: "s3cret-cfail", AutoClear: 1, Terminal: true, TimerStubMillis: 150, ClearError: "clear boom", ReadMode: "honest"},
		{Name: "empty_value_is_never_flagged", Secret: "", AutoClear: 1, Terminal: true, TimerStubMillis: 150, ReadMode: "restore_secret"},
		{Name: "copy_fails", Secret: "s3cret-copyfail", AutoClear: 1, Terminal: true, CopyError: "no clipboard utilities", ReadMode: "honest"},
		{Name: "auto_clear_disabled_keeps_secret", Secret: "s3cret-keep", AutoClear: 0, Terminal: true, ReadMode: "honest"},
		{Name: "auto_clear_disabled_quiet", Secret: "s3cret-keepq", AutoClear: 0, Terminal: true, Quiet: true, ReadMode: "honest"},
		{Name: "sigterm_clears_early", Secret: "s3cret-sig", AutoClear: 30, Terminal: true, SignalAfterMs: 400, ReadMode: "honest"},
		{Name: "not_a_terminal_prints", Secret: "s3cret-pipe", AutoClear: 1, Terminal: false, ReadMode: "honest"},
		{Name: "print_flag_prints", Secret: "s3cret-print", AutoClear: 1, Terminal: true, Print: true, ReadMode: "honest"},
		{Name: "copy_by_default_false_prints", Secret: "s3cret-nodefault", AutoClear: 1, Terminal: true, CopyByDefault: &f, ReadMode: "honest"},
		{Name: "json_output_never_clipboard", Secret: "s3cret-json", AutoClear: 1, Terminal: true, JSON: true, ReadMode: "honest"},
	}
}

type fakeFixtureClipboard struct {
	mu        sync.Mutex
	s         getClipboardScenario
	content   string
	ops       []string
	readCount int
}

func (c *fakeFixtureClipboard) Copy(text string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.ops = append(c.ops, "copy:"+text)
	if text != "" && c.s.CopyError != "" {
		return errors.New(c.s.CopyError)
	}
	if text == "" && c.s.ClearError != "" {
		return errors.New(c.s.ClearError)
	}
	c.content = text
	return nil
}

func (c *fakeFixtureClipboard) Read() (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.ops = append(c.ops, "read")
	switch c.s.ReadMode {
	case "restore_secret":
		return c.s.Secret, nil
	case "other":
		return "something the user copied later", nil
	case "error":
		return "", errors.New(c.s.ReadError)
	default:
		return c.content, nil
	}
}

func runGetClipboardScenario(t *testing.T, s getClipboardScenario) getClipboardResult {
	t.Helper()
	resetCommandTestState()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
	t.Setenv("XDG_DATA_HOME", filepath.Join(home, ".local", "share"))
	t.Setenv("XDG_CACHE_HOME", filepath.Join(home, ".cache"))
	t.Setenv("NO_COLOR", "1")
	vaultDir, passphrase := initVault(t)
	clipboardYAML := fmt.Sprintf("clipboard:\n  auto_clear_duration: %d\n", s.AutoClear)
	if s.CopyByDefault != nil {
		clipboardYAML += fmt.Sprintf("  copyByDefault: %t\n", *s.CopyByDefault)
	}
	identity, err := vaultpkg.OpenWithPassphrase(vaultDir, passphrase)
	if err != nil {
		t.Fatal(err)
	}
	entry := &vaultpkg.Entry{Data: map[string]any{"password": s.Secret}}
	if err := vaultpkg.WriteEntry(vaultDir, "fixture-entry", entry, identity.Identity); err != nil {
		t.Fatal(err)
	}
	// Written last: opening the vault re-saves config.yaml and drops a false
	// copyByDefault (omitempty), which would silently restore the default.
	if err := os.WriteFile(filepath.Join(vaultDir, "config.yaml"), []byte(clipboardYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	setPassEnv(t, string(passphrase))
	// Resolve the vault through SYMVAULT_VAULT, as the existing
	// copyByDefault command test does.
	oldVaultFlagChanged := cli.VaultFlag.Changed
	cli.VaultFlag.Changed = false
	t.Cleanup(func() { cli.VaultFlag.Changed = oldVaultFlagChanged })
	t.Setenv("SYMVAULT_VAULT", vaultDir)

	fake := &fakeFixtureClipboard{s: s}
	oldClipboard := crud.GetClipboard
	crud.GetClipboard = func() clipboardapp.Clipboard { return fake }
	oldDuration := crud.GetAutoClearDurationFunc
	crud.GetAutoClearDurationFunc = func() int { return s.AutoClear }
	oldStart := crud.StartAutoClear
	startSeconds := 0
	switch {
	case s.SignalAfterMs > 0:
		crud.StartAutoClear = func(duration int, clearFn func(), cancelCh <-chan struct{}) {
			startSeconds = duration
			go func() {
				time.Sleep(time.Duration(s.SignalAfterMs) * time.Millisecond)
				proc, _ := os.FindProcess(os.Getpid())
				_ = proc.Signal(syscall.SIGTERM)
			}()
			clipboardapp.StartAutoClear(duration, clearFn, cancelCh)
		}
	default:
		crud.StartAutoClear = func(duration int, clearFn func(), _ <-chan struct{}) {
			startSeconds = duration
			time.Sleep(time.Duration(s.TimerStubMillis) * time.Millisecond)
			clearFn()
		}
	}
	oldTerminal := cli.IsTerminalFunc
	cli.IsTerminalFunc = func(int) bool { return s.Terminal }
	exitCode := 0
	oldExit := cli.OsExit
	cli.OsExit = func(code int) { exitCode = code }
	cli.ActiveContext = nil
	t.Cleanup(func() {
		crud.GetClipboard = oldClipboard
		crud.GetAutoClearDurationFunc = oldDuration
		crud.StartAutoClear = oldStart
		cli.IsTerminalFunc = oldTerminal
		cli.OsExit = oldExit
		cli.ActiveContext = nil
	})

	var args []string
	if s.Quiet {
		args = append(args, "--quiet")
	}
	if s.JSON {
		args = append(args, "--output", "json")
	}
	args = append(args, "get", "fixture-entry.password")
	if s.Print {
		args = append(args, "--print")
	}
	var stdout string
	stderr := captureStderr(func() {
		stdout = captureStdout(func() {
			root := NewRootCmd()
			root.SetArgs(args)
			_ = cli.ExecuteRoot(root)
			root.SetArgs(nil)
		})
	})
	// Give a straggling countdown goroutine a moment to finish before the
	// scenario's global state is torn down; it writes nothing after cancel.
	time.Sleep(20 * time.Millisecond)
	fake.mu.Lock()
	defer fake.mu.Unlock()
	// The once-per-process env-passphrase notice is unrelated to the clipboard
	// path and would otherwise attach to whichever scenario runs first.
	stderr = strings.ReplaceAll(stderr, envPassphraseNotice, "")
	return getClipboardResult{
		getClipboardScenario:  s,
		Stdout:                stdout,
		Stderr:                strings.ReplaceAll(stderr, vaultDir, "/fixture/vault"),
		ExitCode:              exitCode,
		Ops:                   append([]string{}, fake.ops...),
		FinalClipboard:        fake.content,
		StartAutoClearSeconds: startSeconds,
	}
}

type verifyClearedCase struct {
	Name           string `json:"name"`
	ExpectedAbsent string `json:"expected_absent"`
	NilRead        bool   `json:"nil_read"`
	Current        string `json:"current"`
	ReadError      string `json:"read_error,omitempty"`
	Result         string `json:"result"` // ok | not_cleared | read_error
	ErrorText      string `json:"error_text,omitempty"`
	ReadCalls      int    `json:"read_calls"`
}

func recordVerifyCleared() []verifyClearedCase {
	cases := []verifyClearedCase{
		{Name: "still_contains_secret", ExpectedAbsent: "topsecret", Current: "topsecret"},
		{Name: "cleared_to_empty", ExpectedAbsent: "topsecret", Current: ""},
		{Name: "replaced_by_other", ExpectedAbsent: "topsecret", Current: "other"},
		{Name: "prefix_is_not_a_match", ExpectedAbsent: "topsecret", Current: "topsecret "},
		{Name: "case_differs", ExpectedAbsent: "topsecret", Current: "TOPSECRET"},
		{Name: "nil_read_function", ExpectedAbsent: "x", NilRead: true},
		{Name: "empty_expected_skips_read", ExpectedAbsent: "", Current: "anything"},
		{Name: "read_error_propagates", ExpectedAbsent: "x", ReadError: "paste failed"},
		{Name: "read_error_with_matching_text_still_error", ExpectedAbsent: "x", Current: "x", ReadError: "paste failed"},
		{Name: "multiline_secret", ExpectedAbsent: "a\nb", Current: "a\nb"},
		{Name: "unicode_secret", ExpectedAbsent: "pässwörd ✓", Current: "pässwörd ✓"},
	}
	for i := range cases {
		c := &cases[i]
		var read func() (string, error)
		if !c.NilRead {
			read = func() (string, error) {
				c.ReadCalls++
				if c.ReadError != "" {
					return c.Current, errors.New(c.ReadError)
				}
				return c.Current, nil
			}
		}
		err := clipboardapp.VerifyCleared(c.ExpectedAbsent, read)
		switch {
		case err == nil:
			c.Result = "ok"
		case errors.Is(err, clipboardapp.ErrClipboardNotCleared):
			c.Result = "not_cleared"
			c.ErrorText = err.Error()
		default:
			c.Result = "read_error"
			c.ErrorText = err.Error()
		}
	}
	return cases
}

type countdownCase struct {
	Name         string `json:"name"`
	Duration     int    `json:"duration"`
	NilUpdate    bool   `json:"nil_update"`
	CancelAfterM int    `json:"cancel_after_ms,omitempty"`
	PreCancelled bool   `json:"pre_cancelled,omitempty"`
	Updates      []int  `json:"updates"`
}

func recordCountdown() []countdownCase {
	cases := []countdownCase{
		{Name: "full_run_three", Duration: 3},
		{Name: "full_run_one", Duration: 1},
		{Name: "cancel_after_two_ticks", Duration: 10, CancelAfterM: 2500},
		{Name: "cancel_before_first_tick", Duration: 10, CancelAfterM: 300},
		{Name: "zero_duration", Duration: 0},
		{Name: "negative_duration", Duration: -5},
		{Name: "nil_update_function", Duration: 2, NilUpdate: true},
		{Name: "pre_cancelled_still_reports_first", Duration: 5, PreCancelled: true},
	}
	for i := range cases {
		c := &cases[i]
		c.Updates = []int{}
		var mu sync.Mutex
		update := func(remaining int) {
			mu.Lock()
			c.Updates = append(c.Updates, remaining)
			mu.Unlock()
		}
		var fn func(int)
		if !c.NilUpdate {
			fn = update
		}
		cancel := make(chan struct{})
		if c.PreCancelled {
			close(cancel)
		}
		done := make(chan struct{})
		go func() {
			clipboardapp.Countdown(c.Duration, fn, cancel)
			close(done)
		}()
		if c.CancelAfterM > 0 {
			time.Sleep(time.Duration(c.CancelAfterM) * time.Millisecond)
			close(cancel)
		}
		<-done
	}
	return cases
}
