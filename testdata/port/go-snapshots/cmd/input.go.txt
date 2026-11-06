package cmd

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// confirmInteractive prompts the user for confirmation before a destructive action.
// If force is true, the action is confirmed immediately without prompting.
// Otherwise it prints the prompt to stderr and reads y/N from stdin.
// Returns true if the user confirms, false if they decline.
// Returns an error only if reading from stdin fails.
func confirmInteractive(prompt string, force bool) (bool, error) {
	if force {
		return true, nil
	}
	fmt.Fprintf(os.Stderr, "%s (y/N): ", prompt)
	answer, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && answer == "" {
		return false, fmt.Errorf("read confirmation: %w", err)
	}
	if strings.ToLower(strings.TrimSpace(answer)) != "y" {
		return false, nil
	}
	return true, nil
}
