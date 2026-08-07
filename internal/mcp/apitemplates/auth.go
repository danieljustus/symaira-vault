package apitemplates

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// ResolveField returns the first non-empty string value from the entry data
// for the given field keys, in order.
func ResolveField(data map[string]any, keys ...string) string {
	for _, key := range keys {
		if v, ok := data[key]; ok {
			if vStr, ok := v.(string); ok && vStr != "" {
				return vStr
			}
		}
	}
	return ""
}

// InjectAuth resolves the credential from the vault entry data and injects
// the appropriate auth header (or query param) into the HTTP request
// according to the template's auth type.
//
//nolint:gocyclo // auth type dispatch is intentionally structured as switch
func InjectAuth(httpReq *http.Request, tmpl *APITemplate, entryData map[string]any) error {
	switch tmpl.AuthType {
	case AuthBearer:
		token := ResolveField(entryData, "credential", "token", "password")
		if token == "" {
			return fmt.Errorf("no bearer token found in vault entry (expected fields: credential, token, or password)")
		}
		httpReq.Header.Set("Authorization", "Bearer "+token)

	case AuthBasic:
		username := ResolveField(entryData, "username")
		password := ResolveField(entryData, "credential", "password")
		if username == "" || password == "" {
			return fmt.Errorf("basic auth requires username and password fields in vault entry")
		}
		auth := base64.StdEncoding.EncodeToString([]byte(username + ":" + password))
		httpReq.Header.Set("Authorization", "Basic "+auth)

	case AuthHeader:
		// For header auth type, we look for the header name and value in entry data
		// The convention is: header_name and header_value in the vault entry
		headerName := ResolveField(entryData, "header_name")
		headerValue := ResolveField(entryData, "header_value", "credential", "token", "password")
		if headerName == "" || headerValue == "" {
			return fmt.Errorf("header auth requires header_name and header_value (or credential/token/password) fields in vault entry")
		}
		httpReq.Header.Set(headerName, headerValue)

	case AuthQueryParam:
		// For query_param auth type, we look for the param name and value in entry data
		// The convention is: param_name and param_value in the vault entry
		paramName := ResolveField(entryData, "param_name")
		paramValue := ResolveField(entryData, "param_value", "credential", "token", "password")
		if paramName == "" || paramValue == "" {
			return fmt.Errorf("query_param auth requires param_name and param_value (or credential/token/password) fields in vault entry")
		}
		q := httpReq.URL.Query()
		q.Set(paramName, paramValue)
		httpReq.URL.RawQuery = q.Encode()

	case AuthNone:
		// No auth header is injected; credentials are delivered through
		// template substitutions (path/query/header/body).

	default:
		return fmt.Errorf("unsupported auth type: %s", tmpl.AuthType)
	}

	return nil
}

// ResolveSubstitutionValues resolves every declared substitution placeholder
// to a non-empty value from the vault entry data. It returns the values by
// placeholder and as a flat slice for error redaction.
func ResolveSubstitutionValues(tmpl *APITemplate, entryData map[string]any) (map[string]string, []string, error) {
	values := make(map[string]string, len(tmpl.Substitutions))
	var redactVals []string
	for _, sub := range tmpl.Substitutions {
		value := ResolveField(entryData, sub.Field)
		if value == "" {
			return nil, nil, fmt.Errorf("no value for placeholder %q (expected vault entry field %q)", sub.Placeholder, sub.Field)
		}
		values[sub.Placeholder] = value
		redactVals = append(redactVals, value)
	}
	return values, redactVals, nil
}

// ApplyURLSubstitutions replaces path- and query-surface placeholders in the
// request URL. Placeholders are restricted to RFC 3986 unreserved characters,
// so the substitution cannot alter the URL scheme or host.
func ApplyURLSubstitutions(rawURL string, subs []Substitution, values map[string]string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	for _, sub := range subs {
		value, ok := values[sub.Placeholder]
		if !ok {
			continue
		}
		for _, surface := range sub.In {
			switch surface {
			case SurfacePath:
				u.Path = strings.ReplaceAll(u.Path, sub.Placeholder, value)
				u.RawPath = ""
			case SurfaceQuery:
				u.RawQuery = strings.ReplaceAll(u.RawQuery, sub.Placeholder, value)
			case SurfaceHeader, SurfaceBody:
				// Applied by the dedicated header/body helpers; the URL
				// does not carry these surfaces.
			}
		}
	}
	return u.String()
}

// ApplyBodySubstitutions replaces body-surface placeholders in the request body.
func ApplyBodySubstitutions(body string, subs []Substitution, values map[string]string) string {
	for _, sub := range subs {
		if !hasSubstitutionSurface(sub.In, SurfaceBody) {
			continue
		}
		value, ok := values[sub.Placeholder]
		if !ok {
			continue
		}
		body = strings.ReplaceAll(body, sub.Placeholder, value)
	}
	return body
}

// ApplyHeaderSubstitutions replaces header-surface placeholders in the values
// of every request header.
func ApplyHeaderSubstitutions(httpReq *http.Request, subs []Substitution, values map[string]string) {
	for _, sub := range subs {
		if !hasSubstitutionSurface(sub.In, SurfaceHeader) {
			continue
		}
		value, ok := values[sub.Placeholder]
		if !ok {
			continue
		}
		for key, vals := range httpReq.Header {
			for i, v := range vals {
				httpReq.Header[key][i] = strings.ReplaceAll(v, sub.Placeholder, value)
			}
		}
	}
}

func hasSubstitutionSurface(surfaces []SubstitutionSurface, want SubstitutionSurface) bool {
	for _, s := range surfaces {
		if s == want {
			return true
		}
	}
	return false
}

// ParseOpRef parses an op:// reference and returns the entry path and field.
// op://vault/entry/field       -> entry="entry", field="field"
// op://vault/nested/entry/field -> entry="nested/entry", field="field"
// op://vault/entry             -> entry="entry", field=""
func ParseOpRef(ref string) (string, string, error) {
	const prefix = "op://"
	if !strings.HasPrefix(ref, prefix) {
		return "", "", fmt.Errorf("expected op:// prefix")
	}

	parts := strings.Split(strings.TrimPrefix(ref, prefix), "/")
	if len(parts) < 2 {
		return "", "", fmt.Errorf("expected at least vault/entry")
	}

	// parts[0] is vault name (ignored)
	if len(parts) == 2 {
		return parts[1], "", nil
	}

	entryPath := strings.Join(parts[1:len(parts)-1], "/")
	field := parts[len(parts)-1]
	return entryPath, field, nil
}

// EntryRefPath resolves a template entry_ref to a vault entry path. The ref
// must reference an entry, not a field.
func EntryRefPath(entryRef string) (string, error) {
	ref := strings.TrimSpace(entryRef)
	if ref == "" {
		return "", fmt.Errorf("entry_ref is required")
	}
	if strings.HasPrefix(ref, "op://") {
		entryPath, field, err := ParseOpRef(ref)
		if err != nil {
			return "", err
		}
		if field != "" {
			return "", fmt.Errorf("entry_ref must reference an entry, not a field")
		}
		return entryPath, nil
	}
	return ref, nil
}

// RedactValues replaces every occurrence of the given secret values in msg
// with "***" so substituted credentials never reach error messages.
func RedactValues(msg string, values []string) string {
	for _, v := range values {
		if v == "" {
			continue
		}
		msg = strings.ReplaceAll(msg, v, "***")
	}
	return msg
}
