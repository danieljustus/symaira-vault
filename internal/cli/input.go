package cli

import (
	"bufio"

	cliinput "github.com/danieljustus/symaira-vault/internal/cli/input"
)

type EntryFlags = cliinput.EntryFlags

var CollectEntryData = cliinput.CollectEntryData
var ConfirmInteractive = cliinput.ConfirmInteractive

func init() {
	cliinput.ReadHiddenInputFn = ReadHiddenInput
	cliinput.GeneratePasswordFn = GeneratePassword
	cliinput.IsTerminalFn = IsTerminalFunc
}

func ReadEntryData(reader *bufio.Reader, flags EntryFlags) (map[string]any, error) {
	return CollectEntryData(reader, flags)
}
