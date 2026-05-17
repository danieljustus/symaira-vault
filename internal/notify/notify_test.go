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
