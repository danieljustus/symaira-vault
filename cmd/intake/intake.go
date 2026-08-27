// Package intakecmd implements the `symvault intake` command: review-gated
// local credential intake from loose files. It validates, stages, sniffs and
// parses source files, then writes a quarantined review batch under
// quarantine/<import-id>/ — never normal vault paths. Promotion happens
// through the existing `import review promote` flow.
package intakecmd

import (
	"encoding/json"
	"fmt"
	"io"
	"os/exec"
	"runtime"
	"strings"

	"github.com/spf13/cobra"

	cli "github.com/danieljustus/symaira-vault/internal/cli"
	errorspkg "github.com/danieljustus/symaira-vault/internal/errors"
	"github.com/danieljustus/symaira-vault/internal/intake"
	vaultpkg "github.com/danieljustus/symaira-vault/internal/vault"
)

var (
	intakeDryRun     bool
	intakeJSON       bool
	intakeBatchLimit int64
	intakeFileLimit  int
	intakeMoveTrash  bool
	intakeOCRText    string
)

// NewCommands returns the intake command tree.
func NewCommands() []*cobra.Command {
	return []*cobra.Command{newIntakeCmd()}
}

func newIntakeCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "intake <file...>",
		Short: "Review-gated credential intake from loose files",
		Long: `Validates loose credential material (text files, .env exports, JSON,
screenshots, certificate/key files, backup-code images) and stages it as a
quarantined review batch under quarantine/<import-id>/ for human review
before any agent can read it.

Sources are validated (regular files only, stable size/mtime, per-file and
batch limits), copied atomically into a private spool, content-sniffed (never
trusting extensions), and parsed into field/attachment suggestions. The
exact source bytes are stored as an encrypted attachment with SHA-256, size
and source-type provenance. Nothing is written to normal vault paths.

Promote a batch after review:
  symvault intake review promote <import-id>   (alias of import review promote)

Source files are never deleted unless --move-to-trash is given (macOS only)
and only after the quarantine entry was written and verified.`,
		Example: `  # Dry-run: validate, sniff and show suggestions without writing
  symvault intake ~/Downloads/creds.env ~/Downloads/backup.png --dry-run

  # Machine-readable dry-run (metadata only, never secret values)
  symvault intake ~/Downloads/token.json --dry-run --json

  # Stage a review batch and print the import id
  symvault intake ~/Downloads/elster.p12 ~/Downloads/recovery-codes.png

  # Promote the reviewed batch into normal vault paths
  symvault import review promote intake-20260827-1a2b3c4d`,
		Args: cobra.MinimumNArgs(1),
		RunE: runIntake,
	}
	cmd.Flags().BoolVar(&intakeDryRun, "dry-run", false, "Validate and report without writing anything")
	cmd.Flags().BoolVar(&intakeJSON, "json", false, "Emit machine-readable JSON (metadata only, never secret values)")
	cmd.Flags().Int64Var(&intakeBatchLimit, "batch-limit", intake.DefaultMaxBatchSize, "Maximum total bytes per intake run")
	cmd.Flags().IntVar(&intakeFileLimit, "max-files", intake.DefaultMaxFiles, "Maximum number of files per intake run")
	cmd.Flags().BoolVar(&intakeMoveTrash, "move-to-trash", false, "Move verified source files to the macOS Trash after the quarantine entry is written (macOS only)")
	cmd.Flags().StringVar(&intakeOCRText, "ocr-text", "", "Path to a text file with on-device OCR results; its lines become suggestions for image/PDF sources (macOS client integration)")
	cmd.GroupID = cli.GroupIDSharingSync
	cmd.AddCommand(newIntakeWatchCmd())
	return cmd
}

func runIntake(cmd *cobra.Command, args []string) error {
	if intakeMoveTrash && runtime.GOOS != "darwin" {
		return errorspkg.NewCLIError(errorspkg.ExitInvalidInput, "--move-to-trash is only supported on macOS", nil)
	}

	opts := intake.Options{
		DryRun:       intakeDryRun,
		MaxFileSize:  intake.DefaultMaxFileSize,
		MaxBatchSize: intakeBatchLimit,
		MaxFiles:     intakeFileLimit,
		OCRText:      intakeOCRText,
	}

	spool, err := intake.NewSpool()
	if err != nil {
		return errorspkg.NewCLIError(errorspkg.ExitGeneralError, "create intake spool", err)
	}
	defer spool.Remove()

	results, err := intake.ProcessFiles(spool, args, opts)
	if err != nil {
		return errorspkg.NewCLIError(errorspkg.ExitInvalidInput, "intake", err)
	}

	// Dry-run never touches the vault: validate, sniff, parse, report.
	if intakeDryRun {
		if intakeJSON {
			return emitJSON(cmd.OutOrStdout(), results, "")
		}
		return emitText(results, "")
	}

	return cli.WithVault(func(v *vaultpkg.Vault, vs *cli.VaultService) error {
		importID, _, err := intake.WriteBatch(vs, results, intake.BatchOptions{})
		if err != nil {
			return errorspkg.NewCLIError(errorspkg.ExitGeneralError, "write quarantine batch", err)
		}
		if intakeMoveTrash {
			if err := moveToTrashAfterWrite(results); err != nil {
				cli.PrintQuietAware("Warning: %v\n", err)
			}
		}

		if intakeJSON {
			return emitJSON(cmd.OutOrStdout(), results, importID)
		}
		return emitText(results, importID)
	})
}

func emitJSON(w io.Writer, results []intake.FileResult, importID string) error {
	type output struct {
		ImportID string               `json:"import_id,omitempty"`
		Results  []*intake.FileResult `json:"results"`
	}
	san := make([]*intake.FileResult, 0, len(results))
	for i := range results {
		r := results[i].Sanitized()
		san = append(san, r)
	}
	out := output{ImportID: importID, Results: san}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(out); err != nil {
		return errorspkg.NewCLIError(errorspkg.ExitGeneralError, "encode intake output", err)
	}
	return nil
}

func emitText(results []intake.FileResult, importID string) error {
	ok := 0
	for _, r := range results {
		switch r.Status {
		case "ok":
			ok++
			cli.PrintQuietAware("OK    %s  (%s, %d bytes, sha256 %s)\n", r.File, r.Provenance.SourceType, r.Provenance.Size, shortSHA(r.Provenance.SHA256))
			for _, s := range r.Suggestions {
				label := "field"
				if s.Attachment {
					label = "attachment"
				}
				warn := ""
				if s.Warning != "" {
					warn = fmt.Sprintf("  [!] %s", s.Warning)
				}
				cli.PrintQuietAware("      → %s: %s (conf %.2f)%s\n", label, s.Field, s.Confidence, warn)
			}
		case "skipped":
			cli.PrintQuietAware("SKIP  %s  %s\n", r.File, r.Reason)
		case "error":
			cli.PrintQuietAware("ERROR %s  %s\n", r.File, r.Reason)
		}
	}
	if intakeDryRun {
		cli.PrintQuietAware("Dry run: %d file(s) processed, nothing written.\n", len(results))
		return nil
	}
	if ok == 0 {
		return errorspkg.NewCLIError(errorspkg.ExitGeneralError, "no files were accepted for intake", nil)
	}
	cli.PrintQuietAware("Quarantine import ID: %s\n", importID)
	cli.PrintQuietAware("Review and promote with: symvault import review promote %s\n", importID)
	return nil
}

func shortSHA(sha string) string {
	if len(sha) > 12 {
		return sha[:12]
	}
	return sha
}

// moveToTrash moves a verified source file to the macOS Trash via Finder.
// It is only called after the quarantine entry was written and verified
// (read-back hash check inside WriteBatch), per the intake security contract.
func moveToTrash(path string) error {
	if runtime.GOOS != "darwin" {
		return fmt.Errorf("move to trash is only supported on macOS")
	}
	// Use Finder's delete so the file lands in the user's Trash and can be
	// recovered; never os.Remove for the verified-cleanup action.
	script := fmt.Sprintf("tell application \"Finder\" to delete POSIX file %q", path)
	cmd := osascriptCommand(script)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("move %q to trash: %w (%s)", path, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// osascriptCommand builds an osascript invocation for the given AppleScript.
// Only used on macOS for the verified source-cleanup action.
func osascriptCommand(script string) *exec.Cmd {
	return exec.Command("/usr/bin/osascript", "-e", script)
}

// moveToTrashAfterWrite trashes the source files of every successfully
// written result after the batch write. It reports failures per file without
// aborting the remaining files.
func moveToTrashAfterWrite(results []intake.FileResult) error {
	var failed []string
	for _, r := range results {
		if r.Status != "ok" || r.Provenance == nil {
			continue
		}
		if err := moveToTrash(r.Provenance.SourcePath); err != nil {
			failed = append(failed, fmt.Sprintf("%s: %v", r.Provenance.SourcePath, err))
		}
	}
	if len(failed) > 0 {
		return fmt.Errorf("source cleanup incomplete: %s", strings.Join(failed, "; "))
	}
	return nil
}
