// Package provenance binds a generated fixture's claimed Go oracle commit to
// that commit's immutable git blobs.
//
// A generator can only execute the code compiled into it, which is the working
// tree. Claiming an oracle commit is therefore only honest when the working
// tree's production sources are byte-identical to that commit's blobs.
// Validating the commit as a label alone lets a fixture assert one revision
// while carrying another's behavior.
package provenance

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Digest hashes files as filename/NUL/content/NUL, in the order given.
// Callers sort the list so the digest is stable.
func Digest(root string, files []string) (string, error) {
	hash := sha256.New()
	for _, name := range files {
		path := name
		if root != "" && !filepath.IsAbs(name) {
			path = filepath.Join(root, name)
		}
		content, err := os.ReadFile(path) // #nosec G304 -- fixed production/generator inputs
		if err != nil {
			return "", err
		}
		writeEntry(hash, name, content)
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

// Verify resolves commit to a full object name and compares the working tree's
// digest of files against the same digest taken from that commit's blobs.
// It returns the resolved object name, or an error naming both digests when
// they differ.
func Verify(root, commit string, files []string) (string, error) {
	if commit == "" {
		return "", fmt.Errorf("oracle commit is required for provenance verification")
	}
	working, err := Digest(root, files)
	if err != nil {
		return "", fmt.Errorf("hash working tree sources: %w", err)
	}
	resolvedRaw, err := gitOutput(root, "rev-parse", "--verify", "--end-of-options", commit+"^{commit}")
	if err != nil {
		return "", fmt.Errorf("resolve oracle commit %q: %w", commit, err)
	}
	resolved := strings.TrimSpace(string(resolvedRaw))

	hash := sha256.New()
	for _, name := range files {
		content, err := gitOutput(root, "cat-file", "blob", resolved+":"+name)
		if err != nil {
			return "", fmt.Errorf("read %s at oracle commit %s: %w", name, resolved, err)
		}
		writeEntry(hash, name, content)
	}
	pinned := hex.EncodeToString(hash.Sum(nil))

	if pinned != working {
		return "", fmt.Errorf(
			"oracle provenance mismatch: working tree digest %s does not match commit %s (%s) digest %s; "+
				"the generator would execute code that is not the claimed oracle. "+
				"Regenerate from the claimed commit or advance the pin deliberately",
			working, commit, resolved, pinned)
	}
	return resolved, nil
}

func writeEntry(hash interface{ Write([]byte) (int, error) }, name string, content []byte) {
	_, _ = hash.Write([]byte(name))
	_, _ = hash.Write([]byte{0})
	_, _ = hash.Write(content)
	_, _ = hash.Write([]byte{0})
}

func gitOutput(root string, args ...string) ([]byte, error) {
	cmd := exec.Command("git", args...) // #nosec G204 -- fixed subcommands over a validated repository root
	cmd.Dir = root
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("git %v: %w: %s", args, err, strings.TrimSpace(stderr.String()))
	}
	return out, nil
}
