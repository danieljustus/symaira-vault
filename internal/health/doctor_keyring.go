package health

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

// keyringDumpTimeout bounds the `security dump-keychain` enumeration so a
// locked or slow keychain cannot hang the doctor run (the same failure mode
// as #682/#703, where keychain operations blocked indefinitely).
const keyringDumpTimeout = 5 * time.Second

// isTestOrCIEnv reports whether the process is a `go test` binary or running
// under CI/headless automation. Test and CI processes must never touch the
// real OS keychain; doctor checks that would enumerate it skip instead and
// are unit-tested with injected fakes. Mirrors internal/audit's isTestOrCI
// (kept per-package, see the comment there).
func isTestOrCIEnv() bool {
	if os.Getenv("CI") != "" || os.Getenv("GITHUB_ACTIONS") != "" || os.Getenv("HEADLESS") != "" || os.Getenv("SYMVAULT_TEST_KEYRING") == "memory" {
		return true
	}
	for _, arg := range os.Args {
		if len(arg) >= 6 && arg[:6] == "-test." {
			return true
		}
	}
	if len(os.Args) > 0 {
		base := os.Args[0]
		for i := len(base) - 1; i >= 0; i-- {
			if base[i] == '/' || base[i] == '\\' {
				base = base[i+1:]
				break
			}
		}
		if (len(base) >= 5 && base[len(base)-5:] == ".test") ||
			(len(base) >= 9 && base[len(base)-9:] == ".test.exe") ||
			base == "test" { //nolint:goconst // test-binary sentinel, mirrors internal/audit's isTestOrCI
			return true
		}
	}
	return false
}

// auditKeyringServices are the service names under which audit HMAC keys
// may be stored: the current "symaira" and the legacy "openpass" name used
// before the project rename (May 2026). Both use the identical
// "audit-hmac-key:<vault-dir>" account scheme.
var auditKeyringServices = []string{"symaira", "openpass"}

// keyringAccountEntry is a (service, account) pair found in the OS keychain.
type keyringAccountEntry struct {
	service string
	account string
}

// keyringAuditKeyAccounts returns every account stored under one of
// auditKeyringServices whose account uses the audit-hmac-key: scheme, from
// the default OS keychain (macOS only; empty elsewhere). It is a variable so
// tests can inject a fake entry list without touching the real keychain.
var keyringAuditKeyAccounts = func() ([]keyringAccountEntry, error) {
	if runtime.GOOS != osDarwin {
		return nil, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), keyringDumpTimeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, "security", "dump-keychain").Output()
	if err != nil {
		return nil, fmt.Errorf("enumerate OS keychain: %w", err)
	}
	return parseKeychainDump(out), nil
}

// keyringEntryDelete removes a single generic-password item from the OS
// keychain. It is a variable so tests can record deletions instead of
// invoking the security binary.
var keyringEntryDelete = func(service, account string) error {
	out, err := exec.Command("security", "delete-generic-password", "-s", service, "-a", account).CombinedOutput()
	if err != nil {
		// A missing item (errSecItemNotFound, security exits 44) is not an
		// error here: the entry is already gone, which is the desired state.
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) && exitErr.ExitCode() == 44 {
			return nil
		}
		if strings.Contains(string(out), "could not be found") {
			return nil
		}
		return fmt.Errorf("delete keychain entry: %w", err)
	}
	return nil
}

// parseBlobAttr splits a `security dump-keychain` attribute line of the form
//
//	"svce"<blob>="symaira"
//	0x00000007 <blob>="symaira"
//
// into its attribute name and quoted value. Returns ("", "") for lines that
// are not string blob attributes.
func parseBlobAttr(line string) (key, val string) {
	idx := strings.Index(line, "<blob>=")
	if idx < 0 {
		return "", ""
	}
	key = strings.Trim(strings.TrimSpace(line[:idx]), `"`)
	val = strings.Trim(line[idx+len("<blob>="):], `"`)
	return key, val
}

// parseKeychainDump extracts every (service, account) pair whose service is
// one of auditKeyringServices and whose account uses the audit-hmac-key:
// scheme from a `security dump-keychain` transcript. It understands both
// attribute naming schemes macOS has used over the years: the human-readable
// ("svce"/"acct") and the numeric kSecAttrService/kSecAttrAccount form
// (0x00000007/0x00000008), which macOS prints first within each item. Items
// are separated by "keychain:" header lines (recent macOS prints no blank
// lines between items), so each item is flushed when the next header
// appears.
func parseKeychainDump(data []byte) []keyringAccountEntry {
	var entries []keyringAccountEntry
	var service, account string

	flush := func() {
		if service != "" && strings.HasPrefix(account, "audit-hmac-key:") && containsString(auditKeyringServices, service) {
			entries = append(entries, keyringAccountEntry{service: service, account: account})
		}
		service, account = "", ""
	}

	for _, line := range strings.Split(string(data), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "keychain:") {
			// Item boundary (keychain: header) or legacy blank-line
			// separator: flush the item just parsed.
			if service != "" || account != "" {
				flush()
			}
			continue
		}
		key, val := parseBlobAttr(trimmed)
		switch key {
		case "svce", "0x00000007":
			service = val
		case "acct", "0x00000008":
			account = val
		}
	}
	flush()
	return entries
}

func containsString(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}

// auditKeyringOrphansResult is the pure decision logic behind
// checkAuditKeyringOrphans, unit-testable without a real keychain.
// entries are the stored (service, account) pairs whose account uses the
// audit-hmac-key:<vault-dir> scheme; the fix closure deletes every orphan
// via keyringEntryDelete.
func auditKeyringOrphansResult(entries []keyringAccountEntry) Result {
	r := Result{ID: "audit.keyring.orphans", Name: "Orphaned audit HMAC keys in OS keychain"}

	var orphans []keyringAccountEntry
	for _, e := range entries {
		dir := strings.TrimPrefix(e.account, "audit-hmac-key:")
		if dir == e.account { // account does not use the expected scheme
			continue
		}
		if _, err := os.Stat(dir); err != nil {
			orphans = append(orphans, e)
		}
	}

	if len(orphans) == 0 {
		r.Status = StatusOK
		r.Message = "no orphaned audit HMAC keys in the OS keychain (service \"symaira\")"
		return r
	}

	r.Status = StatusWarn
	r.Message = fmt.Sprintf("%d audit HMAC key(s) in the OS keychain point to a vault directory that no longer exists", len(orphans))
	r.Hint = "run `symvault doctor --fix` to remove the orphaned keychain entries"
	r.Fixable = true
	r.Fix = func() error {
		var firstErr error
		for _, e := range orphans {
			if err := keyringEntryDelete(e.service, e.account); err != nil && firstErr == nil {
				firstErr = err
			}
		}
		return firstErr
	}
	return r
}

// checkAuditKeyringOrphans reports service=symaira keychain entries whose
// vault directory no longer exists. These accumulate when test suites or
// temporary vaults wrote audit HMAC keys into the developer's real keychain
// and the directory was deleted afterwards (issue #801); `doctor --fix`
// purges them so the keychain can be reclaimed.
func checkAuditKeyringOrphans(_ string, _ Options) Result {
	r := Result{ID: "audit.keyring.orphans", Name: "Orphaned audit HMAC keys in OS keychain"}
	if runtime.GOOS != osDarwin {
		r.Status = StatusOK
		r.Message = "not applicable on " + runtime.GOOS
		return r
	}
	if isTestOrCIEnv() {
		r.Status = StatusOK
		r.Message = "keychain enumeration skipped in test/CI environment"
		return r
	}
	accounts, err := keyringAuditKeyAccounts()
	if err != nil {
		r.Status = StatusWarn
		r.Message = "cannot enumerate OS keychain: " + err.Error()
		r.Hint = "ensure the login keychain is unlocked, then re-run `symvault doctor`"
		return r
	}
	return auditKeyringOrphansResult(accounts)
}
