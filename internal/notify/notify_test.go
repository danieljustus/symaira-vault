package notify

import "testing"

func TestParseLevel(t *testing.T) {
	cases := map[string]Level{
		"":         LevelInfo,
		"info":     LevelInfo,
		"warn":     LevelWarn,
		"warning":  LevelWarn,
		"critical": LevelCritical,
		"crit":     LevelCritical,
		"  WARN  ": LevelWarn,
		"unknown":  LevelInfo,
	}
	for in, want := range cases {
		if got := parseLevel(in); got != want {
			t.Errorf("parseLevel(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestSuppressed_NoNotify(t *testing.T) {
	t.Setenv("OPENPASS_NO_NOTIFY", "1")
	t.Setenv("OPENPASS_NOTIFY_LEVEL", "")
	if !suppressed(LevelCritical) {
		t.Errorf("OPENPASS_NO_NOTIFY=1 should suppress LevelCritical")
	}
}

func TestSuppressed_NoNotifyDisabled(t *testing.T) {
	t.Setenv("OPENPASS_NO_NOTIFY", "0")
	t.Setenv("OPENPASS_NOTIFY_LEVEL", "")
	if suppressed(LevelInfo) {
		t.Errorf("OPENPASS_NO_NOTIFY=0 should not suppress")
	}
}

func TestSuppressed_LevelFilter(t *testing.T) {
	t.Setenv("OPENPASS_NO_NOTIFY", "")
	t.Setenv("OPENPASS_NOTIFY_LEVEL", "critical")
	if !suppressed(LevelInfo) {
		t.Errorf("LEVEL=critical should suppress LevelInfo")
	}
	if !suppressed(LevelWarn) {
		t.Errorf("LEVEL=critical should suppress LevelWarn")
	}
	if suppressed(LevelCritical) {
		t.Errorf("LEVEL=critical should NOT suppress LevelCritical")
	}
}

func TestSuppressed_Default(t *testing.T) {
	t.Setenv("OPENPASS_NO_NOTIFY", "")
	t.Setenv("OPENPASS_NOTIFY_LEVEL", "")
	for _, lvl := range []Level{LevelInfo, LevelWarn, LevelCritical} {
		if suppressed(lvl) {
			t.Errorf("default config should not suppress %v", lvl)
		}
	}
}

func TestSuppressed_NoNotify_Symvault(t *testing.T) {
	t.Setenv("SYMVAULT_NO_NOTIFY", "1")
	t.Setenv("SYMVAULT_NOTIFY_LEVEL", "")
	if !suppressed(LevelCritical) {
		t.Errorf("SYMVAULT_NO_NOTIFY=1 should suppress LevelCritical")
	}
}

func TestSuppressed_NoNotifyDisabled_Symvault(t *testing.T) {
	t.Setenv("SYMVAULT_NO_NOTIFY", "0")
	t.Setenv("SYMVAULT_NOTIFY_LEVEL", "")
	if suppressed(LevelInfo) {
		t.Errorf("SYMVAULT_NO_NOTIFY=0 should not suppress")
	}
}

func TestSuppressed_LevelFilter_Symvault(t *testing.T) {
	t.Setenv("SYMVAULT_NO_NOTIFY", "")
	t.Setenv("SYMVAULT_NOTIFY_LEVEL", "critical")
	if !suppressed(LevelInfo) {
		t.Errorf("SYMVAULT_NOTIFY_LEVEL=critical should suppress LevelInfo")
	}
	if !suppressed(LevelWarn) {
		t.Errorf("SYMVAULT_NOTIFY_LEVEL=critical should suppress LevelWarn")
	}
	if suppressed(LevelCritical) {
		t.Errorf("SYMVAULT_NOTIFY_LEVEL=critical should NOT suppress LevelCritical")
	}
}

func TestSuppressed_Default_Symvault(t *testing.T) {
	t.Setenv("SYMVAULT_NO_NOTIFY", "")
	t.Setenv("SYMVAULT_NOTIFY_LEVEL", "")
	for _, lvl := range []Level{LevelInfo, LevelWarn, LevelCritical} {
		if suppressed(lvl) {
			t.Errorf("default config should not suppress %v", lvl)
		}
	}
}

func TestSuppressed_NoNotifyPrecedence(t *testing.T) {
	// SYMVAULT_NO_NOTIFY should take precedence over OPENPASS_NO_NOTIFY
	t.Setenv("SYMVAULT_NO_NOTIFY", "1")
	t.Setenv("OPENPASS_NO_NOTIFY", "0")
	if !suppressed(LevelInfo) {
		t.Errorf("SYMVAULT_NO_NOTIFY=1 should suppress even when OPENPASS_NO_NOTIFY=0")
	}
}

func TestSuppressed_LevelFilterPrecedence(t *testing.T) {
	// SYMVAULT_NOTIFY_LEVEL should take precedence over OPENPASS_NOTIFY_LEVEL
	t.Setenv("SYMVAULT_NOTIFY_LEVEL", "critical")
	t.Setenv("OPENPASS_NOTIFY_LEVEL", "info")
	if !suppressed(LevelInfo) {
		t.Errorf("SYMVAULT_NOTIFY_LEVEL=critical should suppress LevelInfo even when OPENPASS_NOTIFY_LEVEL=info")
	}
	if suppressed(LevelCritical) {
		t.Errorf("SYMVAULT_NOTIFY_LEVEL=critical should NOT suppress LevelCritical")
	}
}
