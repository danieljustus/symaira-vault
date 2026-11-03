package cli

import (
	clioutput "github.com/danieljustus/symaira-vault/internal/cli/output"
)

type Printer = clioutput.Printer

var defaultOutput = clioutput.New(clioutput.Deps{
	Quiet:  func() bool { return QuietMode },
	Format: func() string { return OutputFormat },
})

var NewPrinter = func(format string) (clioutput.Printer, error) {
	return defaultOutput.NewPrinter(format)
}

var PrintResult = func(v any) error {
	return defaultOutput.PrintResult(v)
}

var PrintJSON = func(v any) {
	defaultOutput.PrintJSON(v)
}

var WantJSONOutput = func(flagJSON bool) bool {
	return defaultOutput.WantJSONOutput(flagJSON)
}
