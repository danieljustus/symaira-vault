// Command portgen freezes the Go Cobra command tree as a language-neutral fixture.
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	vaultcmd "github.com/danieljustus/symaira-vault/cmd"
)

type document struct {
	SchemaVersion int           `json:"schema_version"`
	Oracle        oracle        `json:"oracle"`
	Groups        []group       `json:"groups"`
	Commands      []commandSpec `json:"commands"`
}

type oracle struct {
	Commit  string `json:"commit"`
	Release string `json:"release"`
}

type group struct {
	ID    string `json:"id"`
	Title string `json:"title"`
}

type commandSpec struct {
	Path                string            `json:"path"`
	Name                string            `json:"name"`
	Use                 string            `json:"use"`
	Short               string            `json:"short,omitempty"`
	Long                string            `json:"long,omitempty"`
	Example             string            `json:"example,omitempty"`
	Aliases             []string          `json:"aliases,omitempty"`
	SuggestFor          []string          `json:"suggest_for,omitempty"`
	ValidArgs           []string          `json:"valid_args,omitempty"`
	ArgAliases          []string          `json:"arg_aliases,omitempty"`
	Hidden              bool              `json:"hidden"`
	Deprecated          string            `json:"deprecated,omitempty"`
	GroupID             string            `json:"group_id,omitempty"`
	Annotations         map[string]string `json:"annotations,omitempty"`
	DisableFlagParsing  bool              `json:"disable_flag_parsing"`
	TraverseChildren    bool              `json:"traverse_children"`
	Runnable            bool              `json:"runnable"`
	HasSubcommands      bool              `json:"has_subcommands"`
	ArgumentCountProbes []argProbe        `json:"argument_count_probes,omitempty"`
	LocalFlags          []flagSpec        `json:"local_flags,omitempty"`
	PersistentFlags     []flagSpec        `json:"persistent_flags,omitempty"`
}

type argProbe struct {
	Count    int    `json:"count"`
	Accepted bool   `json:"accepted"`
	Error    string `json:"error,omitempty"`
}

type flagSpec struct {
	Name                string              `json:"name"`
	Shorthand           string              `json:"shorthand,omitempty"`
	Usage               string              `json:"usage"`
	Type                string              `json:"type"`
	Default             string              `json:"default"`
	NoOptDefault        string              `json:"no_opt_default,omitempty"`
	Hidden              bool                `json:"hidden"`
	Deprecated          string              `json:"deprecated,omitempty"`
	ShorthandDeprecated string              `json:"shorthand_deprecated,omitempty"`
	Annotations         map[string][]string `json:"annotations,omitempty"`
}

func main() {
	output := flag.String("output", "testdata/port/cli/command-tree.json", "fixture path")
	check := flag.Bool("check", false, "fail if the fixture differs")
	commit := flag.String("oracle-commit", "", "Go oracle commit for a new fixture")
	release := flag.String("oracle-release", "", "Go oracle release for a new fixture")
	flag.Parse()

	meta := oracle{Commit: *commit, Release: *release}
	if *check {
		existing, err := readDocument(*output)
		if err != nil {
			fatal("read existing fixture: %v", err)
		}
		meta = existing.Oracle
	}
	if meta.Commit == "" || meta.Release == "" {
		fatal("--oracle-commit and --oracle-release are required when generating a fixture")
	}

	generated := buildDocument(vaultcmd.NewRootCmd(), meta)
	content, err := marshalDocument(generated)
	if err != nil {
		fatal("encode fixture: %v", err)
	}
	if *check {
		existing, err := os.ReadFile(*output)
		if err != nil {
			fatal("read fixture: %v", err)
		}
		if !bytes.Equal(existing, content) {
			fatal("command-tree fixture is stale; run make port-fixtures-generate")
		}
		fmt.Printf("PASS command-tree fixture (%d commands)\n", len(generated.Commands))
		return
	}
	if err := os.MkdirAll(filepath.Dir(*output), 0o755); err != nil {
		fatal("create fixture directory: %v", err)
	}
	if err := os.WriteFile(*output, content, 0o644); err != nil {
		fatal("write fixture: %v", err)
	}
	fmt.Printf("WROTE %s (%d commands)\n", *output, len(generated.Commands))
}

func buildDocument(root *cobra.Command, meta oracle) document {
	root.InitDefaultHelpCmd()
	groups := make([]group, 0, len(root.Groups()))
	for _, item := range root.Groups() {
		groups = append(groups, group{ID: item.ID, Title: item.Title})
	}
	commands := make([]commandSpec, 0)
	collectCommands(root, &commands)
	sort.Slice(commands, func(i, j int) bool { return commands[i].Path < commands[j].Path })
	return document{SchemaVersion: 1, Oracle: meta, Groups: groups, Commands: commands}
}

func collectCommands(current *cobra.Command, commands *[]commandSpec) {
	current.InitDefaultHelpFlag()
	current.SetOut(io.Discard)
	current.SetErr(io.Discard)
	spec := commandSpec{
		Path:               current.CommandPath(),
		Name:               current.Name(),
		Use:                current.Use,
		Short:              current.Short,
		Long:               current.Long,
		Example:            current.Example,
		Aliases:            cloneStrings(current.Aliases),
		SuggestFor:         cloneStrings(current.SuggestFor),
		ValidArgs:          cloneStrings(current.ValidArgs),
		ArgAliases:         cloneStrings(current.ArgAliases),
		Hidden:             current.Hidden,
		Deprecated:         current.Deprecated,
		GroupID:            current.GroupID,
		Annotations:        cloneStringMap(current.Annotations),
		DisableFlagParsing: current.DisableFlagParsing,
		TraverseChildren:   current.TraverseChildren,
		Runnable:           current.Runnable(),
		HasSubcommands:     current.HasSubCommands(),
		LocalFlags:         collectFlags(current.LocalNonPersistentFlags()),
		PersistentFlags:    collectFlags(current.PersistentFlags()),
	}
	if current.Args != nil {
		spec.ArgumentCountProbes = probeArgumentCounts(current)
	}
	*commands = append(*commands, spec)
	for _, child := range current.Commands() {
		collectCommands(child, commands)
	}
}

func probeArgumentCounts(command *cobra.Command) []argProbe {
	probes := make([]argProbe, 0, 10)
	for count := 0; count <= 9; count++ {
		args := make([]string, count)
		for i := range args {
			args[i] = fmt.Sprintf("arg-%d", i+1)
		}
		probe := argProbe{Count: count}
		if err := command.Args(command, args); err != nil {
			probe.Error = err.Error()
		} else {
			probe.Accepted = true
		}
		probes = append(probes, probe)
	}
	return probes
}

func collectFlags(set *pflag.FlagSet) []flagSpec {
	flags := make([]flagSpec, 0, set.NFlag())
	set.VisitAll(func(item *pflag.Flag) {
		flags = append(flags, flagSpec{
			Name:                item.Name,
			Shorthand:           item.Shorthand,
			Usage:               item.Usage,
			Type:                item.Value.Type(),
			Default:             item.DefValue,
			NoOptDefault:        item.NoOptDefVal,
			Hidden:              item.Hidden,
			Deprecated:          item.Deprecated,
			ShorthandDeprecated: item.ShorthandDeprecated,
			Annotations:         cloneStringSliceMap(item.Annotations),
		})
	})
	sort.Slice(flags, func(i, j int) bool { return flags[i].Name < flags[j].Name })
	return flags
}

func marshalDocument(value document) ([]byte, error) {
	content, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(content, '\n'), nil
}

func readDocument(path string) (document, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return document{}, err
	}
	var value document
	if err := json.Unmarshal(content, &value); err != nil {
		return document{}, err
	}
	if value.SchemaVersion != 1 {
		return document{}, fmt.Errorf("unsupported schema_version %d", value.SchemaVersion)
	}
	return value, nil
}

func cloneStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	return append([]string(nil), values...)
}

func cloneStringMap(values map[string]string) map[string]string {
	if len(values) == 0 {
		return nil
	}
	result := make(map[string]string, len(values))
	for key, value := range values {
		result[key] = value
	}
	return result
}

func cloneStringSliceMap(values map[string][]string) map[string][]string {
	if len(values) == 0 {
		return nil
	}
	result := make(map[string][]string, len(values))
	for key, value := range values {
		result[key] = cloneStrings(value)
	}
	return result
}

func fatal(format string, args ...any) {
	_, _ = fmt.Fprintf(os.Stderr, "FAIL "+format+"\n", args...)
	os.Exit(1)
}
