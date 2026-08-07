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
