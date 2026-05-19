package cmd

import (
	"context"
	"encoding/csv"
	"os"
	"os/signal"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"unsafe"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	crud "github.com/danieljustus/OpenPass/cmd/crud"
	mcpcmd "github.com/danieljustus/OpenPass/cmd/mcp"
	cli "github.com/danieljustus/OpenPass/internal/cli"
	clipboardapp "github.com/danieljustus/OpenPass/internal/clipboard"
	vaultcrypto "github.com/danieljustus/OpenPass/internal/crypto"
	"github.com/danieljustus/OpenPass/internal/mcp"
	"github.com/danieljustus/OpenPass/internal/mcp/serverbootstrap"
	vaultpkg "github.com/danieljustus/OpenPass/internal/vault"
)

func TestMain(m *testing.M) {
	_ = os.Unsetenv("OPENPASS_MCP_TOKEN")
	restoreScryptWorkFactor := vaultcrypto.SetTestScryptWorkFactor(12)
	if runtime.GOOS == "windows" {
		return // skip cmd tests on Windows: LockFileEx access violation in AcquireWriteLock
	}
	code := m.Run()
	restoreScryptWorkFactor()
	os.Exit(code)
}

func resetCommandTestState() {
	resetCommandFlagGlobals()
	resetCobraCommand(rootCmd)
	resetCommandEnv()
	cli.OsExit = os.Exit
	mcpcmd.ServeSignalNotify = signal.Notify
	mcpcmd.RunStdioServerFunc = func(ctx context.Context, vault *vaultpkg.Vault, agentName string) error {
		return serverbootstrap.RunStdioServer(ctx, vault, agentName, mcp.New)
	}
	mcpcmd.RunHTTPServerFunc = func(ctx context.Context, bind string, port int, vault *vaultpkg.Vault) error {
		vaultDir, _ := vaultPath()
		return serverbootstrap.RunHTTPServer(ctx, bind, port, vault, vaultDir, Version, mcp.New)
	}
	mcpcmd.ServeUnlockVault = unlockVault
}

func resetCommandFlagGlobals() {
	cli.Vault = "~/.openpass"
	crud.SetValue = ""
	crud.SetTOTPSecret = ""
	crud.SetTOTPIssuer = ""
	crud.SetTOTPAccount = ""
	crud.AddValue = ""
	crud.AddGenerate = false
	crud.AddLength = 20
	crud.AddUsername = ""
	crud.AddURL = ""
	crud.AddNotes = ""
	crud.AddTOTPSecret = ""
	crud.AddTOTPIssuer = ""
	crud.AddTOTPAccount = ""
	crud.EditorFlag = ""
	confirmRemove = false
	crud.GetPrint = false
	genLength = 20
	genSymbols = false
	genStore = ""
	crud.GetClipboard = clipboardapp.DefaultClipboard
	cli.OutputFormat = "text"
}

func resetCobraCommand(cmd *cobra.Command) {
	resetCobraCommandSeen(cmd, make(map[*pflag.Flag]bool))
}

func resetCobraCommandSeen(cmd *cobra.Command, seen map[*pflag.Flag]bool) {
	if cmd == nil {
		return
	}

	cmd.SetArgs(nil)
	cmd.SetOut(nil)
	cmd.SetErr(nil)
	cmd.SetIn(nil)
	cmd.SilenceUsage = false
	cmd.SilenceErrors = false

	for _, fs := range []*pflag.FlagSet{cmd.Flags(), cmd.PersistentFlags(), cmd.LocalFlags(), cmd.InheritedFlags()} {
		if fs != nil {
			fs.VisitAll(func(flag *pflag.Flag) {
				if seen[flag] {
					return
				}
				seen[flag] = true

				if sv, ok := flag.Value.(pflag.SliceValue); ok {
					_ = sv.Replace(parseStringSliceDefault(flag.DefValue))
					resetSliceValueChanged(flag.Value)
				} else {
					_ = flag.Value.Set(flag.DefValue)
				}
				flag.Changed = false
			})
		}
	}

	for _, child := range cmd.Commands() {
		resetCobraCommandSeen(child, seen)
	}
}

func resetCommandEnv() {
	_ = os.Unsetenv("OPENPASS_VAULT")
	_ = os.Unsetenv("OPENPASS_PASSPHRASE")
}

func parseStringSliceDefault(defValue string) []string {
	if len(defValue) < 2 || defValue[0] != '[' || defValue[len(defValue)-1] != ']' {
		return []string{}
	}
	inner := defValue[1 : len(defValue)-1]
	if inner == "" {
		return []string{}
	}
	reader := csv.NewReader(strings.NewReader(inner))
	vals, _ := reader.Read()
	return vals
}

func resetSliceValueChanged(v pflag.Value) {
	rv := reflect.ValueOf(v)
	if rv.Kind() == reflect.Ptr {
		rv = rv.Elem()
	}
	if changedField := rv.FieldByName("changed"); changedField.IsValid() && changedField.Kind() == reflect.Bool {
		ptr := unsafe.Pointer(changedField.UnsafeAddr())
		*(*bool)(ptr) = false
	}
}
