package cli

import (
	"bufio"

	cliinput "github.com/danieljustus/symaira-vault/internal/cli/input"
)

type EntryFlags = cliinput.EntryFlags

var defaultInput = cliinput.New(cliinput.Deps{
	ReadHidden: ReadHiddenInput,
	Generate:   GeneratePassword,
	IsTerminal: IsTerminalFunc,
})

var CollectEntryData = func(reader *bufio.Reader, flags EntryFlags) (map[string]any, error) {
	return defaultInput.CollectEntryData(reader, flags)
}

var ConfirmInteractive = func(prompt string, force bool) (bool, error) {
	return defaultInput.ConfirmInteractive(prompt, force)
}

func ReadEntryData(reader *bufio.Reader, flags EntryFlags) (map[string]any, error) {
	return CollectEntryData(reader, flags)
}
