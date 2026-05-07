// Package cmd implements the OpenPass CLI commands using Cobra.
package cmd

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	cryptopkg "github.com/danieljustus/OpenPass/internal/crypto"
)

// entryFlags holds flag values for entry data collection.
// Fields map 1:1 with CLI flags from add.go and set.go.
type entryFlags struct {
	username        string
	password        string
	generate        bool
	length          int
	url             string
	notes           string
	totpSecret      string
	totpIssuer      string
	totpAccount     string
	force           bool
	skipNotes       bool
	skipTOTPDetails bool
}

// collectEntryData collects entry fields interactively via reader or from flag values.
// When a flag value is non-empty, it is used directly. Otherwise, if reader is non-nil,
// the user is prompted interactively. Password and TOTP secret are wiped from memory
// in all code paths via defer cryptopkg.Wipe().
func collectEntryData(reader *bufio.Reader, flags entryFlags) (map[string]any, error) {
	data := map[string]any{}

	if err := collectUsername(data, reader, flags); err != nil {
		return nil, err
	}
	if err := collectPassword(data, reader, flags); err != nil {
		return nil, err
	}
	if err := collectURL(data, reader, flags); err != nil {
		return nil, err
	}
	collectNotes(data, reader, flags)
	if err := collectTOTP(data, reader, flags); err != nil {
		return nil, err
	}

	return data, nil
}

func collectUsername(data map[string]any, reader *bufio.Reader, flags entryFlags) error {
	if flags.username != "" {
		data["username"] = flags.username
	}
	if reader != nil {
		fmt.Fprint(os.Stderr, "Username (optional): ")
		username, err := reader.ReadString('\n')
		if err != nil && username == "" {
			return fmt.Errorf("read username: %w", err)
		}
		username = strings.TrimSpace(username)
		if username != "" {
			data["username"] = username
		}
	}
	return nil
}

func collectPassword(data map[string]any, reader *bufio.Reader, flags entryFlags) error {
	switch {
	case flags.password != "":
		data["password"] = flags.password
		if !flags.force {
			if err := cryptopkg.ValidatePasswordStrength(flags.password); err != nil {
				return err
			}
		}
	case flags.generate:
		password, err := generatePassword(flags.length, true)
		if err != nil {
			return fmt.Errorf("generate password: %w", err)
		}
		data["password"] = password
	case reader != nil:
		password, err := readHiddenInput("Password: ", reader)
		if err != nil && len(password) == 0 {
			return fmt.Errorf("read password: %w", err)
		}
		defer cryptopkg.Wipe(password)
		if len(password) > 0 {
			data["password"] = string(password)
			if !flags.force {
				if err := cryptopkg.ValidatePasswordStrength(string(password)); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func collectURL(data map[string]any, reader *bufio.Reader, flags entryFlags) error {
	if flags.url != "" {
		data["url"] = flags.url
	} else if reader != nil {
		fmt.Fprint(os.Stderr, "URL (optional): ")
		url, err := reader.ReadString('\n')
		if err != nil && url == "" {
			return fmt.Errorf("read url: %w", err)
		}
		url = strings.TrimSpace(url)
		if url != "" {
			data["url"] = url
		}
	}
	return nil
}

func collectNotes(data map[string]any, reader *bufio.Reader, flags entryFlags) {
	if flags.notes != "" {
		data["notes"] = flags.notes
	} else if reader != nil && !flags.skipNotes {
		fmt.Fprint(os.Stderr, "Notes (optional, end with empty line):\n")
		var notes []string
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				break
			}
			line = strings.TrimSpace(line)
			if line == "" {
				break
			}
			notes = append(notes, line)
		}
		if len(notes) > 0 {
			data["notes"] = strings.Join(notes, "\n")
		}
	}
}

func collectTOTP(data map[string]any, reader *bufio.Reader, flags entryFlags) error {
	if flags.totpSecret != "" {
		totpData := map[string]any{
			"secret": flags.totpSecret,
		}
		if flags.totpIssuer != "" {
			totpData["issuer"] = flags.totpIssuer
		}
		if flags.totpAccount != "" {
			totpData["account_name"] = flags.totpAccount
		}
		data["totp"] = totpData
		return nil
	}

	if reader == nil {
		return nil
	}

	fmt.Fprint(os.Stderr, "TOTP Secret (optional): ")
	totpLine, err := reader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("read TOTP secret: %w", err)
	}
	totpLine = strings.TrimSpace(totpLine)
	if totpLine == "" {
		return nil
	}

	totpSecret := []byte(totpLine)
	defer cryptopkg.Wipe(totpSecret)

	totpData := map[string]any{
		"secret": totpLine,
	}

	if !flags.skipTOTPDetails {
		fmt.Fprint(os.Stderr, "TOTP Issuer (optional): ")
		totpIssuer, err := reader.ReadString('\n')
		if err != nil {
			return fmt.Errorf("read TOTP issuer: %w", err)
		}
		totpIssuer = strings.TrimSpace(totpIssuer)
		if totpIssuer != "" {
			totpData["issuer"] = totpIssuer
		}

		fmt.Fprint(os.Stderr, "TOTP Account (optional): ")
		totpAccount, err := reader.ReadString('\n')
		if err != nil {
			return fmt.Errorf("read TOTP account: %w", err)
		}
		totpAccount = strings.TrimSpace(totpAccount)
		if totpAccount != "" {
			totpData["account_name"] = totpAccount
		}
	}

	data["totp"] = totpData
	return nil
}
