package apitemplates

import (
	"net/http"
	"reflect"
	"testing"
)

func TestResolveSubstitutionValues(t *testing.T) {
	tmpl := &APITemplate{
		Name:     "test",
		BaseURL:  "https://example.com",
		AuthType: AuthNone,
		Substitutions: []Substitution{
			{Placeholder: "__API_TOKEN__", Field: "credential", In: []SubstitutionSurface{SurfacePath, SurfaceQuery}},
			{Placeholder: "__USER__", Field: "username", In: []SubstitutionSurface{SurfaceHeader}},
		},
	}
	values, redactVals, err := ResolveSubstitutionValues(tmpl, map[string]any{
		"credential": "sekret-token-1",
		"username":   "svc-user",
	})
	if err != nil {
		t.Fatalf("ResolveSubstitutionValues() error = %v", err)
	}
	wantValues := map[string]string{
		"__API_TOKEN__": "sekret-token-1",
		"__USER__":      "svc-user",
	}
	if !reflect.DeepEqual(values, wantValues) {
		t.Errorf("values = %v, want %v", values, wantValues)
	}
	// Redaction list must contain every resolved value, in substitution order.
	wantRedact := []string{"sekret-token-1", "svc-user"}
	if !reflect.DeepEqual(redactVals, wantRedact) {
		t.Errorf("redactVals = %v, want %v", redactVals, wantRedact)
	}
}

func TestResolveSubstitutionValues_MissingField(t *testing.T) {
	tmpl := &APITemplate{
		Name:     "test",
		BaseURL:  "https://example.com",
		AuthType: AuthNone,
		Substitutions: []Substitution{
			{Placeholder: "__API_TOKEN__", Field: "credential", In: []SubstitutionSurface{SurfacePath}},
		},
	}
	values, redactVals, err := ResolveSubstitutionValues(tmpl, map[string]any{"username": "svc-user"})
	if err == nil {
		t.Fatal("ResolveSubstitutionValues() expected error for missing field, got nil")
	}
	wantErr := `no value for placeholder "__API_TOKEN__" (expected vault entry field "credential")`
	if err.Error() != wantErr {
		t.Errorf("error = %q, want %q", err.Error(), wantErr)
	}
	if values != nil {
		t.Errorf("values = %v, want nil on error", values)
	}
	if redactVals != nil {
		t.Errorf("redactVals = %v, want nil on error", redactVals)
	}
}

func TestResolveSubstitutionValues_EmptyValueIsMissing(t *testing.T) {
	tmpl := &APITemplate{
		Name:     "test",
		BaseURL:  "https://example.com",
		AuthType: AuthNone,
		Substitutions: []Substitution{
			{Placeholder: "__API_TOKEN__", Field: "credential", In: []SubstitutionSurface{SurfacePath}},
		},
	}
	// A field present but empty must be treated the same as a missing field.
	_, _, err := ResolveSubstitutionValues(tmpl, map[string]any{"credential": ""})
	if err == nil {
		t.Fatal("ResolveSubstitutionValues() expected error for empty field value, got nil")
	}
}

func TestApplyURLSubstitutions_Path(t *testing.T) {
	subs := []Substitution{
		{Placeholder: "__API_TOKEN__", Field: "credential", In: []SubstitutionSurface{SurfacePath}},
	}
	got := ApplyURLSubstitutions("https://example.com/api/__API_TOKEN__/items", subs, map[string]string{
		"__API_TOKEN__": "sekret-token-1",
	})
	want := "https://example.com/api/sekret-token-1/items"
	if got != want {
		t.Errorf("ApplyURLSubstitutions() = %q, want %q", got, want)
	}
}

func TestApplyURLSubstitutions_Query(t *testing.T) {
	subs := []Substitution{
		{Placeholder: "__API_TOKEN__", Field: "credential", In: []SubstitutionSurface{SurfaceQuery}},
	}
	got := ApplyURLSubstitutions("https://example.com/api/items?access_token=__API_TOKEN__&page=1", subs, map[string]string{
		"__API_TOKEN__": "sekret-token-1",
	})
	want := "https://example.com/api/items?access_token=sekret-token-1&page=1"
	if got != want {
		t.Errorf("ApplyURLSubstitutions() = %q, want %q", got, want)
	}
}

func TestApplyURLSubstitutions_PathAndQuery(t *testing.T) {
	subs := []Substitution{
		{Placeholder: "__API_TOKEN__", Field: "credential", In: []SubstitutionSurface{SurfacePath, SurfaceQuery}},
	}
	got := ApplyURLSubstitutions("https://example.com/api/__API_TOKEN__/items?access_token=__API_TOKEN__", subs, map[string]string{
		"__API_TOKEN__": "sekret-token-1",
	})
	want := "https://example.com/api/sekret-token-1/items?access_token=sekret-token-1"
	if got != want {
		t.Errorf("ApplyURLSubstitutions() = %q, want %q", got, want)
	}
}

func TestApplyURLSubstitutions_SurfaceFiltering(t *testing.T) {
	// Header- and body-surface placeholders must never be applied to URLs.
	subs := []Substitution{
		{Placeholder: "__HEADER_KEY__", Field: "credential", In: []SubstitutionSurface{SurfaceHeader}},
		{Placeholder: "__BODY_KEY__", Field: "credential", In: []SubstitutionSurface{SurfaceBody}},
	}
	raw := "https://example.com/api/items?key=__HEADER_KEY__&body=__BODY_KEY__"
	got := ApplyURLSubstitutions(raw, subs, map[string]string{
		"__HEADER_KEY__": "hdr-sekret",
		"__BODY_KEY__":   "body-sekret",
	})
	if got != raw {
		t.Errorf("ApplyURLSubstitutions() = %q, want unchanged %q", got, raw)
	}
}

func TestApplyURLSubstitutions_MissingValue(t *testing.T) {
	subs := []Substitution{
		{Placeholder: "__API_TOKEN__", Field: "credential", In: []SubstitutionSurface{SurfacePath, SurfaceQuery}},
	}
	raw := "https://example.com/api/__API_TOKEN__/items?key=__API_TOKEN__"
	got := ApplyURLSubstitutions(raw, subs, map[string]string{"__OTHER__": "value"})
	if got != raw {
		t.Errorf("ApplyURLSubstitutions() = %q, want unchanged %q", got, raw)
	}
}

func TestApplyURLSubstitutions_InvalidURLPassthrough(t *testing.T) {
	subs := []Substitution{
		{Placeholder: "__API_TOKEN__", Field: "credential", In: []SubstitutionSurface{SurfacePath}},
	}
	raw := "://not a url"
	got := ApplyURLSubstitutions(raw, subs, map[string]string{"__API_TOKEN__": "sekret"})
	if got != raw {
		t.Errorf("ApplyURLSubstitutions() = %q, want invalid URL passed through unchanged %q", got, raw)
	}
}

func TestApplyURLSubstitutions_MultipleOccurrences(t *testing.T) {
	subs := []Substitution{
		{Placeholder: "__API_TOKEN__", Field: "credential", In: []SubstitutionSurface{SurfacePath}},
	}
	got := ApplyURLSubstitutions("https://example.com/__API_TOKEN__/__API_TOKEN__", subs, map[string]string{
		"__API_TOKEN__": "sekret",
	})
	want := "https://example.com/sekret/sekret"
	if got != want {
		t.Errorf("ApplyURLSubstitutions() = %q, want %q", got, want)
	}
}

func TestApplyBodySubstitutions(t *testing.T) {
	subs := []Substitution{
		{Placeholder: "__API_TOKEN__", Field: "credential", In: []SubstitutionSurface{SurfaceBody}},
		{Placeholder: "__USER__", Field: "username", In: []SubstitutionSurface{SurfaceHeader}},
	}
	body := `{"token":"__API_TOKEN__","user":"__USER__"}`
	got := ApplyBodySubstitutions(body, subs, map[string]string{
		"__API_TOKEN__": "sekret-token-1",
		"__USER__":      "svc-user",
	})
	// Only the body-surface placeholder is replaced; the header-only one stays.
	want := `{"token":"sekret-token-1","user":"__USER__"}`
	if got != want {
		t.Errorf("ApplyBodySubstitutions() = %q, want %q", got, want)
	}
}

func TestApplyBodySubstitutions_MissingValue(t *testing.T) {
	subs := []Substitution{
		{Placeholder: "__API_TOKEN__", Field: "credential", In: []SubstitutionSurface{SurfaceBody}},
	}
	body := `{"token":"__API_TOKEN__"}`
	got := ApplyBodySubstitutions(body, subs, map[string]string{"__OTHER__": "value"})
	if got != body {
		t.Errorf("ApplyBodySubstitutions() = %q, want unchanged %q", got, body)
	}
}

func TestApplyBodySubstitutions_MultipleOccurrences(t *testing.T) {
	subs := []Substitution{
		{Placeholder: "__API_TOKEN__", Field: "credential", In: []SubstitutionSurface{SurfaceBody}},
	}
	got := ApplyBodySubstitutions("__API_TOKEN__-__API_TOKEN__", subs, map[string]string{
		"__API_TOKEN__": "sekret",
	})
	if got != "sekret-sekret" {
		t.Errorf("ApplyBodySubstitutions() = %q, want %q", got, "sekret-sekret")
	}
}

func TestApplyHeaderSubstitutions(t *testing.T) {
	req, _ := http.NewRequest("GET", "https://example.com/api", nil)
	req.Header.Set("X-API-Key", "__API_TOKEN__")
	req.Header.Set("X-User", "__USER__")

	subs := []Substitution{
		{Placeholder: "__API_TOKEN__", Field: "credential", In: []SubstitutionSurface{SurfaceHeader}},
		{Placeholder: "__USER__", Field: "username", In: []SubstitutionSurface{SurfaceBody}},
	}
	ApplyHeaderSubstitutions(req, subs, map[string]string{
		"__API_TOKEN__": "sekret-token-1",
		"__USER__":      "svc-user",
	})

	if got := req.Header.Get("X-API-Key"); got != "sekret-token-1" {
		t.Errorf("X-API-Key = %q, want %q", got, "sekret-token-1")
	}
	// Body-surface placeholder must not be applied to headers.
	if got := req.Header.Get("X-User"); got != "__USER__" {
		t.Errorf("X-User = %q, want unchanged %q", got, "__USER__")
	}
}

func TestApplyHeaderSubstitutions_MissingValue(t *testing.T) {
	req, _ := http.NewRequest("GET", "https://example.com/api", nil)
	req.Header.Set("X-API-Key", "__API_TOKEN__")

	subs := []Substitution{
		{Placeholder: "__API_TOKEN__", Field: "credential", In: []SubstitutionSurface{SurfaceHeader}},
	}
	ApplyHeaderSubstitutions(req, subs, map[string]string{"__OTHER__": "value"})

	if got := req.Header.Get("X-API-Key"); got != "__API_TOKEN__" {
		t.Errorf("X-API-Key = %q, want unchanged %q", got, "__API_TOKEN__")
	}
}

func TestParseOpRef(t *testing.T) {
	tests := []struct {
		name      string
		ref       string
		wantEntry string
		wantField string
		wantErr   string
	}{
		{"vault entry", "op://vault/entry", "entry", "", ""},
		{"last segment is field", "op://vault/nested/entry", "nested", "entry", ""},
		{"entry field", "op://vault/entry/field", "entry", "field", ""},
		{"nested entry field", "op://vault/nested/entry/field", "nested/entry", "field", ""},
		{"missing prefix", "vault/entry", "", "", "expected op:// prefix"},
		{"vault only", "op://vault", "", "", "expected at least vault/entry"},
		{"empty", "", "", "", "expected op:// prefix"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entry, field, err := ParseOpRef(tt.ref)
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("ParseOpRef(%q) expected error %q, got nil", tt.ref, tt.wantErr)
				}
				if err.Error() != tt.wantErr {
					t.Errorf("ParseOpRef(%q) error = %q, want %q", tt.ref, err.Error(), tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseOpRef(%q) error = %v", tt.ref, err)
			}
			if entry != tt.wantEntry {
				t.Errorf("ParseOpRef(%q) entry = %q, want %q", tt.ref, entry, tt.wantEntry)
			}
			if field != tt.wantField {
				t.Errorf("ParseOpRef(%q) field = %q, want %q", tt.ref, field, tt.wantField)
			}
		})
	}
}

func TestEntryRefPath(t *testing.T) {
	tests := []struct {
		name    string
		ref     string
		want    string
		wantErr string
	}{
		{"vault entry", "op://vault/entry", "entry", ""},
		{"nested ref resolves to field, rejected", "op://vault/nested/entry", "", "entry_ref must reference an entry, not a field"},
		{"surrounding whitespace trimmed", "  op://vault/entry  ", "entry", ""},
		{"plain path passthrough", "custom/path", "custom/path", ""},
		{"field reference rejected", "op://vault/entry/field", "", "entry_ref must reference an entry, not a field"},
		{"missing entry", "op://vault", "", "expected at least vault/entry"},
		{"missing prefix", "vault/entry", "vault/entry", ""},
		{"empty", "", "", "entry_ref is required"},
		{"whitespace only", "   ", "", "entry_ref is required"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := EntryRefPath(tt.ref)
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("EntryRefPath(%q) expected error %q, got nil", tt.ref, tt.wantErr)
				}
				if err.Error() != tt.wantErr {
					t.Errorf("EntryRefPath(%q) error = %q, want %q", tt.ref, err.Error(), tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("EntryRefPath(%q) error = %v", tt.ref, err)
			}
			if got != tt.want {
				t.Errorf("EntryRefPath(%q) = %q, want %q", tt.ref, got, tt.want)
			}
		})
	}
}

func TestRedactValues(t *testing.T) {
	got := RedactValues("token=sekret1 user=sekret2 again=sekret1", []string{"sekret1", "sekret2"})
	want := "token=*** user=*** again=***"
	if got != want {
		t.Errorf("RedactValues() = %q, want %q", got, want)
	}
}

func TestRedactValues_EmptyValueSkip(t *testing.T) {
	msg := "token=sekret msg unchanged"
	got := RedactValues(msg, []string{"", "", "sekret"})
	if got != "token=*** msg unchanged" {
		t.Errorf("RedactValues() = %q, want %q", got, "token=*** msg unchanged")
	}
}

func TestRedactValues_NoMatch(t *testing.T) {
	msg := "no secrets here"
	got := RedactValues(msg, []string{"sekret1"})
	if got != msg {
		t.Errorf("RedactValues() = %q, want unchanged %q", got, msg)
	}
}
