package intake

import (
	"fmt"
	"os"
	"path/filepath"
)

// ProcessFile validates, stages, sniffs and parses one source file. On
// success the result carries provenance, sanitized suggestions and internal
// raw suggestions plus the staged copy for the later batch write. Errors are
// classified: validation failures return *ErrSkipped (deliberate skip), all
// other failures are hard errors for that file.
func ProcessFile(spool *Spool, sourcePath string, opts Options) (FileResult, error) {
	res := FileResult{File: sourcePath}

	stagePath, prov, err := spool.Stage(sourcePath, opts.MaxFileSize)
	if err != nil {
		if isRejectError(err) {
			res.Status = "skipped"
			res.Reason = err.Error()
			return res, nil
		}
		res.Status = "error"
		res.Reason = err.Error()
		return res, nil
	}
	res.spoolPath = stagePath
	res.Provenance = &prov

	data, err := os.ReadFile(stagePath) // #nosec G304 -- staged spool copy created by intake
	if err != nil {
		res.Status = "error"
		res.Reason = fmt.Sprintf("read staged copy: %v", err)
		return res, nil
	}
	res.sourceBytes = data

	// Content sniffing overrides the extension-based type recorded during
	// staging: a ".txt" file holding PEM still parses as a certificate.
	st := Sniff(data, prov.SourceName)
	prov.SourceType = st

	raw := Parse(data, st, prov.SourceName)
	res.raw = raw
	for _, sug := range raw {
		res.Suggestions = append(res.Suggestions, sug.Sanitize())
	}
	res.Status = "ok"
	return res, nil
}

// ProcessFiles runs ProcessFile for each path, enforcing the batch limits.
// Files are staged sequentially; the spool owns all staged copies until the
// caller removes it.
func ProcessFiles(spool *Spool, paths []string, opts Options) ([]FileResult, error) {
	if len(paths) == 0 {
		return nil, fmt.Errorf("no input files")
	}
	if opts.MaxFiles <= 0 {
		opts.MaxFiles = DefaultMaxFiles
	}
	if opts.MaxFileSize <= 0 {
		opts.MaxFileSize = DefaultMaxFileSize
	}
	if opts.MaxBatchSize <= 0 {
		opts.MaxBatchSize = DefaultMaxBatchSize
	}
	if len(paths) > opts.MaxFiles {
		return nil, fmt.Errorf("batch exceeds the %d file limit (%d given)", opts.MaxFiles, len(paths))
	}

	var total int64
	var results []FileResult
	for _, p := range paths {
		res, err := ProcessFile(spool, p, opts)
		if err != nil {
			return results, err
		}
		if res.Provenance != nil {
			total += res.Provenance.Size
			if total > opts.MaxBatchSize {
				res = FileResult{
					File:   p,
					Status: "skipped",
					Reason: fmt.Sprintf("batch exceeds the %d byte total limit", opts.MaxBatchSize),
				}
			}
		}
		results = append(results, res)
	}
	return results, nil
}

// isRejectError reports whether err is a deliberate per-file rejection
// (symlink, non-regular file, over-limit, unstable file) that should be
// reported as a skip rather than a hard failure.
func isRejectError(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	prefixes := []string{
		"reject ",
		"stat ",
	}
	for _, p := range prefixes {
		if len(msg) >= len(p) && msg[:len(p)] == p {
			return true
		}
	}
	return false
}

// CleanupResultFiles removes private spool staging for the given results.
// Source files are never touched.
func CleanupResultFiles(results []FileResult) {
	for _, r := range results {
		if r.spoolPath != "" {
			_ = os.Remove(r.spoolPath)
		}
	}
}

// DirExists is a small helper for callers that need to pre-validate a batch
// directory.
func DirExists(path string) bool {
	fi, err := os.Stat(path)
	return err == nil && fi.IsDir()
}

// BaseName returns the base name of a source path for display.
func BaseName(path string) string { return filepath.Base(path) }
