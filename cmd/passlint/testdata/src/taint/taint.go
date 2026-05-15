// Package taint provides the Untrusted type for analysistest.
package taint

import (
	"fmt"
	"io"
)

type Provenance struct {
	Source string
}

type TerminalStyle int

const Terminal TerminalStyle = 0

type Untrusted struct {
	value string
}

func Wrap(value string, provenance ...Provenance) Untrusted {
	return Untrusted{value: value}
}

func (u Untrusted) Render(style TerminalStyle) string {
	return u.value
}

func (u Untrusted) UnsafeRawForStorage() string {
	return u.value
}

func (u Untrusted) Bytes() []byte {
	return []byte(u.value)
}

func (u Untrusted) Provenance() []Provenance {
	return nil
}

func (u Untrusted) Tags() map[string]string {
	return nil
}

func (u Untrusted) Format(f fmt.State, verb rune) {
	_, _ = io.WriteString(f, "<untrusted:source>")
}
