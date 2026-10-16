// oraclebuild applies the existing differential harness's process-tree ownership
// to cold oracle builds. It never substitutes the product compiler or sources.
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/danieljustus/symaira-vault/scripts/rust-port/internal/diff"
)

func main() {
	if len(os.Args) != 5 || !filepath.IsAbs(os.Args[1]) || !filepath.IsAbs(os.Args[2]) || !filepath.IsAbs(os.Args[3]) {
		fmt.Fprintln(os.Stderr, "usage: oraclebuild <absolute-go> <absolute-source> <absolute-output> <package>")
		os.Exit(2)
	}
	// pinned_go resolves caches before HOME isolation. Do not forward credentials
	// or replace the differential harness's isolated HOME/TMP/keyring settings.
	env := map[string]string{}
	for _, key := range []string{"PATH", "GOTOOLCHAIN", "GOWORK", "GOENV", "GOROOT", "GOCACHE", "GOMODCACHE", "GOPATH", "GOOS", "GOARCH", "GOFLAGS", "GOMAXPROCS"} {
		if value, ok := os.LookupEnv(key); ok {
			env[key] = value
		}
	}
	if env["GOTOOLCHAIN"] != "local" || !filepath.IsAbs(env["GOCACHE"]) || !filepath.IsAbs(env["GOMODCACHE"]) {
		fmt.Fprintln(os.Stderr, "oraclebuild requires a resolved local compiler and absolute caches")
		os.Exit(2)
	}
	if !strings.HasPrefix(os.Args[4], ".") {
		fmt.Fprintln(os.Stderr, "oraclebuild requires a source-relative package")
		os.Exit(2)
	}
	result, err := diff.Run(os.Args[1], diff.Case{
		ID:   "oracle-build",
		Args: []string{"-C", os.Args[2], "build", "-trimpath", "-buildvcs=false", "-o", os.Args[3], os.Args[4]},
		Env:  env,
		// Match the existing fixture run_step compile budget, not the 120s CLI budget.
		TimeoutMS: 600_000,
	})
	_, _ = os.Stdout.Write(result.Stdout)
	_, _ = os.Stderr.Write(result.Stderr)
	fmt.Fprintf(os.Stderr, "oraclebuild: exit=%d timed_out=%t cleanup_error=%t\n", result.ExitCode, result.TimedOut, err != nil)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if result.TimedOut {
		os.Exit(124)
	}
	os.Exit(result.ExitCode)
}
