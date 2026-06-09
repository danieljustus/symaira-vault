package crud

import (
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	cli "github.com/danieljustus/symaira-vault/internal/cli"

	"github.com/spf13/cobra"

	clipboardapp "github.com/danieljustus/symaira-vault/internal/clipboard"
	configpkg "github.com/danieljustus/symaira-vault/internal/config"
	vaultcrypto "github.com/danieljustus/symaira-vault/internal/crypto"
	errorspkg "github.com/danieljustus/symaira-vault/internal/errors"
	"github.com/danieljustus/symaira-vault/internal/ui/cliout"
	"github.com/danieljustus/symaira-vault/internal/ui/render"
	vaultpkg "github.com/danieljustus/symaira-vault/internal/vault"
	"github.com/danieljustus/symaira-vault/internal/vault/taint"
)

var (
	GetPrint     bool
	GetClipboard = clipboardapp.DefaultClipboard
)

type totpOutput struct {
	Code      string `json:"code"`
	Period    int64  `json:"period"`
	Remaining int    `json:"remaining"`
}

type getEntryOutput struct {
	Fields   map[string]any
	TOTP     *totpOutput
	Path     string
	Modified string
}

var getCmd = &cobra.Command{
	Use:     "get <path[.field]>",
	Aliases: []string{"show", "cat"},
	Short:   "Get a password entry",
	Long:    "Retrieves and displays a password entry. Use path.field syntax to get specific fields.",
	Example: `  # Get a specific field (auto-copies to clipboard on TTY)
  symvault get github.password

  # Substring search fallback (when exact path doesn't exist)
  symvault get git

  # Explicitly print to stdout instead of clipboard
  symvault get github.password --print

  # Output as JSON
  symvault get github --output json

  # Use a specific profile
  symvault get github.password --profile work`,
	Args:              cobra.ExactArgs(1),
	ValidArgsFunction: cli.EntryCompletionFunc,
	RunE: func(cmd *cobra.Command, args []string) error {
		return cli.WithVault(func(v *vaultpkg.Vault, vs *cli.VaultService) error {
			cli.MaybeAutoPull(vs.VaultDir(), v.Config)
			query := args[0]
			path := query
			field := ""

			if idx := strings.LastIndex(query, "."); idx > 0 {
				candidatePath := query[:idx]
				candidateField := query[idx+1:]

				if _, readErr := vs.GetField(candidatePath, candidateField); readErr == nil {
					path = candidatePath
					field = candidateField
				}
			}

			value, err := vs.GetField(path, field)
			if err != nil {
				var cliErr *errorspkg.CLIError
				if !errors.As(err, &cliErr) || cliErr.Code != errorspkg.ExitNotFound {
					if errors.As(err, &cliErr) {
						switch cliErr.Kind {
						case errorspkg.ErrFieldNotFound:
							return errorspkg.NewCLIError(errorspkg.ExitNotFound, cliErr.Message, errorspkg.ErrEntryNotFound)
						default:
						}
					}
					return errorspkg.ReadFailed(err, "cannot read entry")
				}

				matches, findErr := vs.FindEntries(path, vaultpkg.FindOptions{})
				if findErr != nil {
					return errorspkg.ReadFailed(findErr, "search entry")
				}

				switch len(matches) {
				case 0:
					return errorspkg.NewCLIError(errorspkg.ExitNotFound, cliErr.Message, errorspkg.ErrEntryNotFound)
				case 1:
					path = matches[0].Path
					value, err = vs.GetField(path, field)
					if err != nil {
						var cliErr2 *errorspkg.CLIError
						if errors.As(err, &cliErr2) {
							switch cliErr2.Kind {
							case errorspkg.ErrNotFound, errorspkg.ErrFieldNotFound:
								return errorspkg.NewCLIError(errorspkg.ExitNotFound, cliErr2.Message, errorspkg.ErrEntryNotFound)
							default:
							}
						}
						return errorspkg.ReadFailed(err, "cannot read entry")
					}
				default:
					cliout.Warnf("Multiple matches:")
					for _, m := range matches {
						cliout.Warnf("  %s", render.ForTerminal(taint.Wrap(m.Path, taint.Provenance{Source: "cli.path"})))
					}
					return errorspkg.NewCLIError(errorspkg.ExitNotFound, fmt.Sprintf("ambiguous path: %s", path), errorspkg.ErrEntryNotFound)
				}
			}

			if field != "" {
				strValue := fmt.Sprintf("%v", value)

				// Determine if we should copy to clipboard:
				// 1. --output json: never clipboard, always print as JSON
				// 2. --print flag: always print to stdout
				// 3. Not a TTY: print to stdout (for scripts/pipes)
				// 4. TTY + no --print: copy to clipboard (default)
				// 5. Config override: clipboard.printByDefault=false restores old behavior

				if cli.OutputFormat != "text" {
					if printErr := cli.PrintResult(strValue); printErr != nil {
						return printErr
					}
					return nil
				}

				shouldPrint := GetPrint || !cli.IsTerminalFunc(int(os.Stdout.Fd()))
				if !shouldPrint {
					// Check config override
					vaultDir, _ := cli.VaultPath()
					if vaultDir != "" {
						cfg, _ := configpkg.Load(vaultDir + "/config.yaml")
						if cfg != nil && cfg.Clipboard != nil && !cfg.Clipboard.PrintByDefault {
							shouldPrint = true
						}
					}
				}

				if !shouldPrint {
					// Copy to clipboard (default TTY behavior)
					if clipErr := GetClipboard().Copy(strValue); clipErr != nil {
						return errorspkg.Wrap(errorspkg.ExitGeneralError, errorspkg.ErrKindNone, clipErr, "copy to clipboard")
					}
					cliout.Hintf("[copied to clipboard]")

					autoClearDuration := GetAutoClearDuration()
					if autoClearDuration > 0 {
						cancelCh := make(chan struct{})
						go clipboardapp.Countdown(autoClearDuration, func(remaining int) {
							fmt.Fprintf(os.Stderr, "\r[clearing clipboard in %ds] ", remaining)
						}, cancelCh)
						go clipboardapp.StartAutoClear(autoClearDuration, func() {
							close(cancelCh)
							copied := strValue
							if clearErr := GetClipboard().Copy(""); clearErr != nil {
								cliout.Warnf("Warning: failed to clear clipboard: %v", clearErr)
							}
							if verr := clipboardapp.VerifyCleared(copied, GetClipboard().Read); verr != nil {
								fmt.Fprintf(os.Stderr, "\rWarning: %v — consider disabling clipboard-history retention.\n", verr)
							} else {
								fmt.Fprintln(os.Stderr, "\r[clipboard cleared]        ")
							}
						}, cancelCh)
					}
					return nil
				}

				cli.PrintlnQuietAware(strValue)
				return nil
			}

			entry, err := vs.GetEntry(path)
			if err != nil {
				var cliErr3 *errorspkg.CLIError
				if errors.As(err, &cliErr3) {
					switch cliErr3.Kind {
					case errorspkg.ErrNotFound, errorspkg.ErrFieldNotFound:
						return errorspkg.NewCLIError(errorspkg.ExitNotFound, cliErr3.Message, errorspkg.ErrEntryNotFound)
					default:
					}
				}
				return errorspkg.ReadFailed(err, "cannot read entry")
			}

			if cli.OutputFormat != "text" {
				output := getEntryOutput{
					Path:     path,
					Modified: entry.Metadata.Updated.Format("2006-01-02 15:04"),
					Fields:   entry.Data,
				}
				if secret, algorithm, digits, period, hasTOTP := vaultpkg.ExtractTOTP(entry.Data); hasTOTP {
					totpCode, err := vaultcrypto.GenerateTOTP(secret, algorithm, digits, period)
					if err == nil {
						period := int64(totpCode.Period)
						if period == 0 {
							period = 30
						}
						now := time.Now().UTC()
						remaining := period - (now.Unix() % period)
						output.TOTP = &totpOutput{
							Code:      totpCode.Code,
							Period:    period,
							Remaining: int(remaining),
						}
					}
				}
				if err := cli.PrintResult(output); err != nil {
					return err
				}
				return nil
			}

			cli.PrintQuietAware("Path: %s\n", render.ForTerminal(taint.Wrap(path, taint.Provenance{Source: "cli.path"})))
			cli.PrintQuietAware("Modified: %s\n", entry.Metadata.Updated.Format("2006-01-02 15:04"))
			cli.PrintlnQuietAware()

			keys := make([]string, 0, len(entry.Data))
			for k := range entry.Data {
				keys = append(keys, k)
			}
			sort.Strings(keys)

			for _, k := range keys {
				cli.PrintQuietAware("%s: %v\n", k, render.ForTerminal(taint.Wrap(fmt.Sprintf("%v", entry.Data[k]), taint.Provenance{Source: "cli.value"})))
			}

			if secret, algorithm, digits, period, hasTOTP := vaultpkg.ExtractTOTP(entry.Data); hasTOTP {
				totpCode, err := vaultcrypto.GenerateTOTP(secret, algorithm, digits, period)
				if err != nil {
					cliout.Warnf("Warning: could not generate TOTP code: %v", err)
				} else {
					period := int64(totpCode.Period)
					if period == 0 {
						period = 30
					}
					now := time.Now().UTC()
					remaining := period - (now.Unix() % period)

					cli.PrintlnQuietAware()
					fmt.Fprintf(os.Stderr, "TOTP Code: %s (expires in %ds)\n", totpCode.Code, remaining)
				}
			}

			return nil
		})
	},
}

func init() {
	getCmd.Flags().BoolVarP(&GetPrint, "print", "p", false, "Print value to stdout instead of copying to clipboard")
	cli.RootCmd.AddCommand(getCmd)
}

func GetAutoClearDuration() int {
	vaultDir, err := cli.VaultPath()
	if err != nil {
		return 30
	}
	cfg, err := configpkg.Load(vaultDir + "/config.yaml")
	if err != nil {
		return 30
	}
	if cfg.Clipboard == nil {
		return 30
	}
	return cfg.Clipboard.AutoClearDuration
}
