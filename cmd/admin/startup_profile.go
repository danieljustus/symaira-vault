package admin

import (
	"fmt"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"runtime/trace"
	"sort"
	"strconv"
	"strings"
	"time"

	cli "github.com/danieljustus/symaira-vault/internal/cli"

	"github.com/spf13/cobra"
)

var (
	startupProfileCount     int
	startupProfileTopN      int
	startupProfileTraceFile string
)

var startupProfileCmd = &cobra.Command{
	Use:   "startup-profile",
	Short: "Measure and report CLI startup time",
	Long: `Measure CLI startup time by re-executing the binary multiple times.

Reports min, max, average, and p95 startup times across N iterations.
The measurement covers Go runtime init, all init() functions, cobra
command tree setup, flag parsing, and the PersistentPreRunE hook.

Use --trace to generate a runtime/trace file analyzable with 'go tool trace'.`,
	Example: `  # Measure startup time (default 10 iterations)
  symvault startup-profile

  # Measure with 50 iterations
  symvault startup-profile --count 50

  # Generate a runtime trace for detailed analysis
  symvault startup-profile --trace startup.trace`,
	Annotations: map[string]string{
		cli.RequiresVaultAnnotation: "false",
	},
	RunE: runStartupProfile,
}

func init() {
	startupProfileCmd.Flags().IntVarP(&startupProfileCount, "count", "n", 10, "number of benchmark iterations")
	startupProfileCmd.Flags().IntVar(&startupProfileTopN, "top", 5, "show top N slowest phases in trace breakdown")
	startupProfileCmd.Flags().StringVar(&startupProfileTraceFile, "trace", "", "write a runtime trace file (viewable with 'go tool trace')")
	cli.RootCmd.AddCommand(startupProfileCmd)
}

const envProfileChild = "SYMVAULT_STARTUP_PROFILE_CHILD"

func runStartupProfile(cmd *cobra.Command, args []string) error {
	if os.Getenv(envProfileChild) == "1" {
		return runProfileChild(cmd)
	}

	if startupProfileTraceFile != "" {
		return runProfileWithTrace(cmd)
	}

	return runProfileBenchmark(cmd)
}

func runProfileChild(cmd *cobra.Command) error {
	elapsed := time.Since(cli.StartTime)
	cmd.Printf("%d\n", elapsed.Nanoseconds())
	return nil
}

func runProfileBenchmark(cmd *cobra.Command) error {
	binary, err := resolveBinary()
	if err != nil {
		return err
	}

	count := startupProfileCount
	if count < 1 {
		count = 1
	}

	cmd.Printf("Profiling startup time (%d iterations)...\n\n", count)

	times := make([]time.Duration, 0, count)
	failures := 0

	for i := 0; i < count; i++ {
		start := time.Now()
		c := exec.Command(binary)
		c.Env = append(cleanEnv(), envProfileChild+"=1")
		c.Stdout = nil
		c.Stderr = nil
		if runErr := c.Run(); runErr != nil {
			failures++
			cmd.Printf("  iteration %d: exec failed: %v\n", i+1, runErr)
			continue
		}
		elapsed := time.Since(start)
		times = append(times, elapsed)
	}

	if len(times) == 0 {
		return fmt.Errorf("all %d iterations failed", count)
	}

	sort.Slice(times, func(i, j int) bool { return times[i] < times[j] })

	total := time.Duration(0)
	for _, t := range times {
		total += t
	}
	avg := total / time.Duration(len(times))
	min := times[0]
	max := times[len(times)-1]
	p95 := percentile(times, 95)
	p99 := percentile(times, 99)

	cmd.Println("Startup Time Statistics")
	cmd.Println(strings.Repeat("─", 50))
	cmd.Printf("  Min:        %v\n", min)
	cmd.Printf("  Max:        %v\n", max)
	cmd.Printf("  Avg:        %v\n", avg)
	cmd.Printf("  P95:        %v\n", p95)
	cmd.Printf("  P99:        %v\n", p99)
	cmd.Printf("  Success:    %d / %d iterations\n", len(times), count)
	if failures > 0 {
		cmd.Printf("  Failures:   %d\n", failures)
	}
	cmd.Println()
	cmd.Println("Environment")
	cmd.Println(strings.Repeat("─", 50))
	cmd.Printf("  Go:         %s\n", runtime.Version())
	cmd.Printf("  OS/Arch:    %s/%s\n", runtime.GOOS, runtime.GOARCH)
	cmd.Printf("  CPU:        %d core(s)\n", runtime.NumCPU())
	cmd.Printf("  GOMAXPROCS: %d\n", runtime.GOMAXPROCS(0))
	cmd.Println()

	cmd.Println("Optimization Hints")
	cmd.Println(strings.Repeat("─", 50))
	cmd.Println("  • Init functions run sequentially before main(); heavy inits slow every command.")
	cmd.Println("  • Use lazy initialization (sync.Once) for expensive package-level setup.")
	cmd.Println("  • Reduce import breadth: each imported package adds init() overhead.")
	cmd.Println("  • Consider build tags to exclude unused features from default builds.")
	cmd.Printf("  • Run 'symvault startup-profile --trace startup.trace' then 'go tool trace startup.trace'\n")

	return nil
}

func runProfileWithTrace(cmd *cobra.Command) error {
	f, err := os.Create(startupProfileTraceFile)
	if err != nil {
		return fmt.Errorf("cannot create trace file: %w", err)
	}
	defer f.Close()

	if err := trace.Start(f); err != nil {
		return fmt.Errorf("cannot start trace: %w", err)
	}
	defer trace.Stop()

	cmd.Println("Runtime trace started. Running self-benchmark...")

	binary, err := resolveBinary()
	if err != nil {
		return err
	}

	times := make([]time.Duration, 0, 5)
	for i := 0; i < 5; i++ {
		start := time.Now()
		c := exec.Command(binary)
		c.Env = append(cleanEnv(), envProfileChild+"=1")
		c.Stdout = nil
		c.Stderr = nil
		if runErr := c.Run(); runErr != nil {
			cmd.Printf("  iteration %d: exec failed: %v\n", i+1, runErr)
			continue
		}
		times = append(times, time.Since(start))
	}

	if len(times) > 0 {
		sort.Slice(times, func(i, j int) bool { return times[i] < times[j] })
		var total time.Duration
		for _, t := range times {
			total += t
		}
		cmd.Printf("  Quick benchmark: avg=%v min=%v max=%v (%d runs)\n",
			total/time.Duration(len(times)), times[0], times[len(times)-1], len(times))
	}

	cmd.Printf("\nTrace written to %s\n", startupProfileTraceFile)
	cmd.Println("View with: go tool trace " + startupProfileTraceFile)
	return nil
}

func resolveBinary() (string, error) {
	binary, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("cannot find executable: %w", err)
	}
	resolved, err := filepath.EvalSymlinks(binary)
	if err != nil {
		return binary, nil
	}
	return resolved, nil
}

func cleanEnv() []string {
	env := os.Environ()
	cleaned := make([]string, 0, len(env))
	skipPrefixes := []string{
		"SYMVAULT_",
		"OPENPASS_",
	}
	for _, e := range env {
		skip := false
		for _, p := range skipPrefixes {
			if strings.HasPrefix(e, p) {
				skip = true
				break
			}
		}
		if !skip {
			cleaned = append(cleaned, e)
		}
	}
	return cleaned
}

func percentile(sorted []time.Duration, pct int) time.Duration {
	if len(sorted) == 0 {
		return 0
	}
	idx := int(math.Ceil(float64(pct)/100*float64(len(sorted)))) - 1
	if idx < 0 {
		idx = 0
	}
	if idx >= len(sorted) {
		idx = len(sorted) - 1
	}
	return sorted[idx]
}

func formatDuration(d time.Duration) string {
	if d < time.Microsecond {
		return fmt.Sprintf("%dns", d.Nanoseconds())
	}
	if d < time.Millisecond {
		return fmt.Sprintf("%.1fµs", float64(d.Microseconds()))
	}
	if d < time.Second {
		return fmt.Sprintf("%.1fms", float64(d.Nanoseconds())/1e6)
	}
	return fmt.Sprintf("%.2fs", d.Seconds())
}

// parseChildOutput parses the nanosecond value output by a child profiling run.
func parseChildOutput(line string) (time.Duration, error) {
	line = strings.TrimSpace(line)
	ns, err := strconv.ParseInt(line, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid child output: %q", line)
	}
	return time.Duration(ns), nil
}
