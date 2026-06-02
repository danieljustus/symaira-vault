package cli

import (
	clioutput "github.com/danieljustus/symaira-vault/internal/cli/output"
)

type Printer = clioutput.Printer

var NewPrinter = clioutput.NewPrinter
var PrintResult = clioutput.PrintResult
var PrintJSON = clioutput.PrintJSON
var WantJSONOutput = clioutput.WantJSONOutput

func init() {
	clioutput.QuietModeFn = func() bool { return QuietMode }
	clioutput.OutputFormatFn = func() string { return OutputFormat }
}
