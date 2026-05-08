package autotype

import "strings"

// escapeAppleScriptString escapes a string for safe use inside an AppleScript
// keystroke command. It handles backslash, double quote, and control characters
// that could alter script behavior or produce unwanted keystrokes.
func escapeAppleScriptString(text string) string {
	var b strings.Builder
	for _, r := range text {
		switch r {
		case '\\':
			b.WriteString("\\\\")
		case '"':
			b.WriteString("\\\"")
		case '\n':
			b.WriteString("\\n")
		case '\r':
			b.WriteString("\\r")
		case '\t':
			b.WriteString("\\t")
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// escapeSendKeysString escapes a string for safe use with WScript.Shell SendKeys.
// SendKeys interprets the following characters as modifiers or special commands:
//   - Shift      ^  Ctrl      %  Alt
//     ~  Enter      {  Begin special key   }  End special key
//     [  (reserved) ]  (reserved)
//
// To send a literal modifier character it must be wrapped in braces, e.g. {+}.
func escapeSendKeysString(text string) string {
	var b strings.Builder
	for _, r := range text {
		switch r {
		case '+', '^', '%', '~', '{', '}', '[', ']':
			b.WriteRune('{')
			b.WriteRune(r)
			b.WriteRune('}')
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}
