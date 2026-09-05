package diff

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"reflect"
)

// Compare checks the observable contract selected by testCase.
func Compare(testCase Case, left, right Result) error {
	if left.TimedOut != right.TimedOut {
		return fmt.Errorf("timeout mismatch: left=%t right=%t", left.TimedOut, right.TimedOut)
	}
	if left.ExitCode != right.ExitCode {
		return fmt.Errorf("exit mismatch: left=%d right=%d", left.ExitCode, right.ExitCode)
	}
	if left.Signal != right.Signal {
		return fmt.Errorf("signal mismatch: left=%q right=%q", left.Signal, right.Signal)
	}
	if err := compareStream("stdout", testCase.stdoutComparisonMode(), left.Stdout, right.Stdout, left.SandboxRoot, right.SandboxRoot); err != nil {
		return err
	}
	if err := compareStream("stderr", testCase.stderrComparisonMode(), left.Stderr, right.Stderr, left.SandboxRoot, right.SandboxRoot); err != nil {
		return err
	}
	if testCase.CompareFiles && !reflect.DeepEqual(left.Files, right.Files) {
		return fmt.Errorf("filesystem manifest mismatch: left=%s right=%s", digestValue(left.Files), digestValue(right.Files))
	}
	return nil
}

func compareStream(name, mode string, left, right []byte, leftRoot, rightRoot string) error {
	switch mode {
	case comparisonModeIgnore:
		return nil
	case comparisonModeBytes:
	case comparisonModeConsoleText:
		left = normalizeConsole(left, leftRoot)
		right = normalizeConsole(right, rightRoot)
	default:
		return fmt.Errorf("unsupported %s comparison mode %q", name, mode)
	}
	if !bytes.Equal(left, right) {
		return fmt.Errorf("%s mismatch: left_bytes=%d left_sha256=%s right_bytes=%d right_sha256=%s",
			name, len(left), digestBytes(left), len(right), digestBytes(right))
	}
	return nil
}

func normalizeConsole(value []byte, sandboxRoot string) []byte {
	value = bytes.ReplaceAll(value, []byte("\r\n"), []byte("\n"))
	if sandboxRoot != "" {
		value = bytes.ReplaceAll(value, []byte(sandboxRoot), []byte("<SANDBOX>"))
	}
	return value
}

func digestBytes(value []byte) string {
	digest := sha256.Sum256(value)
	return hex.EncodeToString(digest[:])
}

func digestValue(value any) string {
	return digestBytes([]byte(fmt.Sprintf("%#v", value)))
}
