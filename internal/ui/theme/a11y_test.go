package theme

import "testing"

func TestScreenReaderMode(t *testing.T) {
	cases := []struct {
		name string
		env  map[string]string
		want bool
	}{
		{"explicit on", map[string]string{"OPENPASS_SCREEN_READER": "1"}, true},
		{"explicit off overrides nvda", map[string]string{"OPENPASS_SCREEN_READER": "0", "NVDA_SCREEN_READER": "1"}, false},
		{"nvda detected", map[string]string{"NVDA_SCREEN_READER": "1"}, true},
		{"orca detected", map[string]string{"ORCA_RUNNING": "1"}, true},
		{"unset / default off", map[string]string{}, false},
		{"yes alias", map[string]string{"OPENPASS_SCREEN_READER": "yes"}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for _, k := range []string{"OPENPASS_SCREEN_READER", "NVDA_SCREEN_READER", "ORCA_RUNNING"} {
				t.Setenv(k, "")
			}
			for k, v := range tc.env {
				t.Setenv(k, v)
			}
			if got := ScreenReaderMode(); got != tc.want {
				t.Errorf("ScreenReaderMode() = %v, want %v", got, tc.want)
			}
		})
	}
}
