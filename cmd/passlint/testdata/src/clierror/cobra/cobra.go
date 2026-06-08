package cobra

// Command is a local stand-in for the real github.com/spf13/cobra.Command
// type. The passlint analyzer matches by local package name + type name, so
// this stub is enough to exercise it in testdata without dragging the real
// dependency into the passlint test binary.
type Command struct {
	Use  string
	RunE func(*Command, []string) error
}
