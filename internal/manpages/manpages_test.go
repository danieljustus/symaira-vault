package manpages_test

import (
	"bytes"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/cobra/doc"

	vaultcmd "github.com/danieljustus/symaira-vault/cmd"
	"github.com/danieljustus/symaira-vault/internal/config"
	"github.com/danieljustus/symaira-vault/internal/manpages"
)

func TestManpageLiteralText(t *testing.T) {
	cases := []struct{ input, want string }{
		{`C:\ordinary\config.yaml`, `C:\\ordinary\\config.yaml`},
		{".request", `\&.request`},
		{"'request", `\&'request`},
		{"/a__b__c/a`b`c/a[b](c)d/a![b](c)d/a<b>c/a&amp;b/é space", "/a__b__c/a`b`c/a[b](c)d/a![b](c)d/a<b>c/a&amp;b/é space"},
		{"a\n.PS\r\t\x00\a\b\v\f\x1b\x7f\u0085\u2028\u2029", `a\\n.PS\\r\\t\\x00\\a\\b\\v\\f\\x1b\\x7f\\u0085\\u2028\\u2029`},
	}
	for _, c := range cases {
		if got := manpages.LiteralText(c.input); got != c.want {
			t.Errorf("%q: got %q, want %q", c.input, got, c.want)
		}
	}
}

func TestManualConfigPathIsLiteralAndDescriptionsAreRestored(t *testing.T) {
	// No directories with hostile names are created; only the resolved path is
	// documentation input. This is portable even for Windows-forbidden names.
	for _, component := range []string{"ordinary", "s__b0nk_", "a__b__c", "a`b`c", "a[b](c)d", "a![b](c)d", "a<b>c", "a&amp;b", "a\n.PS\r\t\x1b", "SYMVAULTLITERALCONFIGPATH"} {
		t.Run(component, func(t *testing.T) {
			t.Setenv("XDG_CONFIG_HOME", filepath.Join(t.TempDir(), component))
			t.Setenv("SYMVAULT_TEST_KEYRING", "memory")
			root := vaultcmd.NewRootCmd()
			path := filepath.Join(config.DefaultConfigDir(), "config.yaml")
			date := time.Unix(0, 0).UTC()
			for _, name := range []string{"mcp", "serve"} {
				command, _, err := root.Find([]string{name})
				if err != nil || command.Name() != name {
					t.Fatal("missing production command", name, err)
				}
				command.InitDefaultHelpCmd()
				command.InitDefaultHelpFlag()
				original := command.Long
				var helpBefore, helpAfter, page bytes.Buffer
				command.SetOut(&helpBefore)
				if err := command.Help(); err != nil {
					t.Fatal(err)
				}
				header := &doc.GenManHeader{Title: "SYMVAULT", Section: "1", Date: &date, Source: "Symaira Vault", Manual: "Symaira Vault Manual"}
				if err := manpages.Generate(command, header, &page); err != nil {
					t.Fatal(err)
				}
				if !strings.Contains(page.String(), "(default: "+manpages.LiteralText(path)+"; existing installs") {
					t.Fatalf("%s path was not rendered literally: %q", name, page.String())
				}
				if command.Long != original {
					t.Fatal("manual generation changed help description")
				}
				command.SetOut(&helpAfter)
				if err := command.Help(); err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(helpBefore.Bytes(), helpAfter.Bytes()) {
					t.Fatal("help bytes changed")
				}
				if component == "ordinary" {
					var legacy bytes.Buffer
					if err := doc.GenMan(command, header, &legacy); err != nil {
						t.Fatal(err)
					}
					if !bytes.Equal(page.Bytes(), legacy.Bytes()) {
						t.Fatal("ordinary manual bytes changed")
					}
				}
				if err := manpages.Generate(command, header, failingManualWriter{}); err == nil {
					t.Fatal("write failure ignored")
				}
				if command.Long != original {
					t.Fatal("write failure changed help description")
				}
			}
		})
	}
}

type failingManualWriter struct{}

func (failingManualWriter) Write([]byte) (int, error) {
	return 0, errors.New("injected manual write failure")
}

func TestManualLiteralPathDoesNotRewriteOtherDescriptions(t *testing.T) {
	root := &cobra.Command{Use: "symvault"}
	child := &cobra.Command{Use: "unrelated", Long: "Keep **Markdown** and `/a__b__c` exactly as documented."}
	root.AddCommand(child)
	date := time.Unix(0, 0).UTC()
	header := &doc.GenManHeader{Section: "1", Date: &date}
	var actual, expected bytes.Buffer
	if err := manpages.Generate(child, header, &actual); err != nil {
		t.Fatal(err)
	}
	if err := doc.GenMan(child, header, &expected); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(actual.Bytes(), expected.Bytes()) {
		t.Fatal("unrelated Markdown behavior changed")
	}
}
