package cli

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	cryptopkg "github.com/danieljustus/OpenPass/internal/crypto"
)

type EntryFlags struct {
	Username        string
	Password        string
	Generate        bool
	Length          int
	URL             string
	Notes           string
	TOTPSecret      string
	TOTPIssuer      string
	TOTPAccount     string
	Force           bool
	SkipNotes       bool
	SkipTOTPDetails bool
}

func CollectEntryData(reader *bufio.Reader, flags EntryFlags) (map[string]any, error) {
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

func collectUsername(data map[string]any, reader *bufio.Reader, flags EntryFlags) error {
	if flags.Username != "" {
		data["username"] = flags.Username
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

func collectPassword(data map[string]any, reader *bufio.Reader, flags EntryFlags) error {
	switch {
	case flags.Password != "":
		data["password"] = flags.Password
		if !flags.Force {
			if err := cryptopkg.ValidatePasswordStrength(flags.Password); err != nil {
				return err
			}
		}
	case flags.Generate:
		password, err := GeneratePassword(flags.Length, true)
		if err != nil {
			return fmt.Errorf("generate password: %w", err)
		}
		data["password"] = password
	case reader != nil:
		password, err := ReadHiddenInput("Password: ", reader)
		if err != nil && len(password) == 0 {
			return fmt.Errorf("read password: %w", err)
		}
		defer cryptopkg.Wipe(password)
		if len(password) > 0 {
			data["password"] = string(password)
			if !flags.Force {
				if err := confirmWeakPassword(string(password)); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func collectURL(data map[string]any, reader *bufio.Reader, flags EntryFlags) error {
	if flags.URL != "" {
		data["url"] = flags.URL
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

func collectNotes(data map[string]any, reader *bufio.Reader, flags EntryFlags) {
	if flags.Notes != "" {
		data["notes"] = flags.Notes
	} else if reader != nil && !flags.SkipNotes {
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

func collectTOTP(data map[string]any, reader *bufio.Reader, flags EntryFlags) error {
	if flags.TOTPSecret != "" {
		totpData := map[string]any{
			"secret": flags.TOTPSecret,
		}
		if flags.TOTPIssuer != "" {
			totpData["issuer"] = flags.TOTPIssuer
		}
		if flags.TOTPAccount != "" {
			totpData["account_name"] = flags.TOTPAccount
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

	if !flags.SkipTOTPDetails {
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

func ConfirmInteractive(prompt string, force bool) (bool, error) {
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

func confirmWeakPassword(password string) error {
	s := cryptopkg.AssessPasswordStrength(password)
	if !s.Weak {
		return nil
	}

	fmt.Fprintf(os.Stderr, "Warning: %s\n", s.Message)
	if IsTerminalFunc(int(os.Stdin.Fd())) {
		ok, err := ConfirmInteractive("Use this password anyway?", false)
		if err != nil {
			return err
		}
		if !ok {
			return fmt.Errorf("password rejected by user")
		}
		return nil
	}
	return fmt.Errorf("%s — use --force to bypass this check (the entry will be tagged as weak)", s.Message)
}
