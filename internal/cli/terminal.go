package cli

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/pflag"
	"golang.org/x/term"

	"github.com/danieljustus/OpenPass/internal/ui/cliout"
)

var ReadPasswordFunc func(int) ([]byte, error) = term.ReadPassword
var IsTerminalFunc func(int) bool = term.IsTerminal

// PipeWarningEmitted tracks whether the pipe-input warning has already been
// printed in this process so we only nag once per invocation.
var PipeWarningEmitted bool

// EnvPassphraseWarningEmitted tracks whether the OPENPASS_PASSPHRASE env-var
// warning has already been printed in this process.
var EnvPassphraseWarningEmitted bool

func WarnEnvPassphrase() {
	if EnvPassphraseWarningEmitted || QuietMode {
		return
	}
	if v := os.Getenv("OPENPASS_NO_ENV_WARNING"); v != "" && v != "0" {
		return
	}
	EnvPassphraseWarningEmitted = true
	cliout.Warnf("OPENPASS_PASSPHRASE is set — the passphrase is visible in /proc/PID/environ and may be exposed in process listings and crash dumps.")
}

func WarnPipeRead(label string) {
	if PipeWarningEmitted || QuietMode || NoPipeWarning {
		return
	}
	if v := os.Getenv("OPENPASS_NO_PIPE_WARNING"); v != "" && v != "0" {
		return
	}
	PipeWarningEmitted = true
	cliout.Warnf("Reading %s from a non-TTY source — the producing process may expose it in 'ps' or audit logs. Prefer OPENPASS_PASSPHRASE or 'openpass auth set touchid'.", label)
}

func ReadHiddenInput(prompt string, reader *bufio.Reader) ([]byte, error) {
	fmt.Fprint(os.Stderr, prompt)
	fdRaw := os.Stdin.Fd()
	if fdRaw > uintptr(^uint(0)>>1) {
		return nil, fmt.Errorf("file descriptor %d exceeds int range", fdRaw)
	}
	fd := int(fdRaw)
	if IsTerminalFunc(fd) {
		passphrase, err := ReadPasswordFunc(fd)
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", strings.TrimSuffix(strings.TrimSuffix(prompt, ": "), ":"), err)
		}
		return bytes.TrimSpace(passphrase), nil
	}
	label := strings.TrimSuffix(strings.TrimSuffix(prompt, ": "), ":")
	WarnPipeRead(label)
	if reader != nil {
		line, err := reader.ReadString('\n')
		if err != nil && line == "" {
			return nil, fmt.Errorf("read %s: %w", label, err)
		}
		return bytes.TrimSpace([]byte(line)), nil
	}
	line, err := ReadLineFromStdin()
	if err != nil && line == nil {
		return nil, fmt.Errorf("read %s: %w", label, err)
	}
	return bytes.TrimSpace(line), nil
}

func ReadLineFromStdin() ([]byte, error) {
	var result []byte
	var buf [1]byte
	for {
		n, err := os.Stdin.Read(buf[:])
		if n > 0 {
			if buf[0] == '\n' {
				return result, nil
			}
			result = append(result, buf[0])
		}
		if err != nil {
			if len(result) == 0 {
				return nil, err
			}
			return result, nil
		}
	}
}

func ReadVisibleInput(prompt string) (string, error) {
	fmt.Fprint(os.Stderr, prompt)
	line, err := ReadLineFromStdin()
	if err != nil && len(line) == 0 {
		return "", fmt.Errorf("read response: %w", err)
	}
	return strings.TrimSpace(string(line)), nil
}

func StdinIsTerminal() bool {
	fdRaw := os.Stdin.Fd()
	if fdRaw > uintptr(^uint(0)>>1) {
		return false
	}
	return IsTerminalFunc(int(fdRaw))
}

func GetVaultFlag() *pflag.Flag {
	return VaultFlag
}
