package i18n

import "testing"

func TestT_Fallback(t *testing.T) {
	t.Cleanup(func() { SetLanguage(LangEN) })

	SetLanguage(LangEN)
	if got := T("prompt.passphrase"); got != "Passphrase: " {
		t.Errorf("EN prompt.passphrase = %q, want %q", got, "Passphrase: ")
	}
}

func TestT_GermanOverride(t *testing.T) {
	t.Cleanup(func() { SetLanguage(LangEN) })

	SetLanguage(LangDE)
	if got := T("prompt.passphrase.new"); got != "Neue Passphrase: " {
		t.Errorf("DE override missing: got %q", got)
	}
}

func TestT_UnknownKey(t *testing.T) {
	t.Cleanup(func() { SetLanguage(LangEN) })

	if got := T("does.not.exist"); got != "does.not.exist" {
		t.Errorf("missing key should return key, got %q", got)
	}
}

func TestT_GermanFallsBackToEnglish(t *testing.T) {
	t.Cleanup(func() {
		SetLanguage(LangEN)
		Register(LangDE, "test.only.en", "")
	})

	Register(LangEN, "test.only.en", "EN only")
	Register(LangDE, "test.only.en", "") // empty intentionally

	SetLanguage(LangDE)
	if got := T("test.only.en"); got != "EN only" {
		t.Errorf("expected EN fallback, got %q", got)
	}
}

func TestTf(t *testing.T) {
	t.Cleanup(func() { SetLanguage(LangEN) })

	SetLanguage(LangEN)
	got := Tf("error.read.input", "EOF")
	if got != "could not read input: EOF" {
		t.Errorf("Tf() = %q", got)
	}
}

func TestDetectFromEnv(t *testing.T) {
	cases := []struct {
		name string
		env  map[string]string
		want Language
	}{
		{"de_DE.UTF-8", map[string]string{"LANG": "de_DE.UTF-8"}, LangDE},
		{"en_US.UTF-8", map[string]string{"LANG": "en_US.UTF-8"}, LangEN},
		{"LC_ALL wins over LANG", map[string]string{"LC_ALL": "de_DE", "LANG": "en_US"}, LangDE},
		{"unknown language", map[string]string{"LANG": "ja_JP.UTF-8"}, LangEN},
		{"empty defaults to EN", map[string]string{}, LangEN},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for _, k := range []string{"LC_ALL", "LC_MESSAGES", "LANG"} {
				t.Setenv(k, "")
			}
			for k, v := range tc.env {
				t.Setenv(k, v)
			}
			if got := DetectFromEnv(); got != tc.want {
				t.Errorf("DetectFromEnv() = %v, want %v", got, tc.want)
			}
		})
	}
}
