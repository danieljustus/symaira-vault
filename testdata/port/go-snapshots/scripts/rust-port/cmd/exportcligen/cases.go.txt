package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"fmt"
	"strings"
)

func closed(argv ...string) Step { return Step{Argv: argv} }

func piped(stdin string, argv ...string) Step { return Step{Argv: argv, Stdin: &stdin} }

func text(path string, mode uint32, data string) FileSpec {
	return FileSpec{Path: path, Kind: "file", Mode: mode, Data: data}
}

func dir(path string, mode uint32) FileSpec { return FileSpec{Path: path, Kind: "dir", Mode: mode} }

func link(path, target string) FileSpec { return FileSpec{Path: path, Kind: "symlink", Target: target} }

func rawFile(path string, mode uint32, data []byte) FileSpec {
	spec := FileSpec{Path: path, Kind: "file", Mode: mode}
	setData(&spec, data)
	return spec
}

func newCase(id, class, seed, desc string, steps ...Step) Case {
	return Case{ID: id, Class: class, Seed: seed, Desc: desc, Steps: steps}
}

func (c Case) withPre(specs ...FileSpec) Case { c.Pre = append(c.Pre, specs...); return c }

func (c Case) withEnv(key, value string) Case {
	env := map[string]string{}
	for k, v := range c.Env {
		env[k] = v
	}
	env[key] = value
	c.Env = env
	return c
}

func (c Case) tail(marker string) Case { c.StderrTailFrom = marker; return c }

func (c Case) without(keys ...string) Case { c.Unset = append(c.Unset, keys...); return c }

type caseBuilder struct {
	seeds map[string][]FileSpec
	cases []Case
	err   error
}

func (b *caseBuilder) add(cases ...Case) { b.cases = append(b.cases, cases...) }

func (b *caseBuilder) archive(path string, mode uint32, members []member) FileSpec {
	spec, err := archiveFile(path, mode, members)
	if err != nil && b.err == nil {
		b.err = err
	}
	return spec
}

func gzipBytes(raw []byte) []byte {
	var out bytes.Buffer
	gw := gzip.NewWriter(&out)
	_, _ = gw.Write(raw)
	_ = gw.Close()
	return out.Bytes()
}

// vaultMembers returns the entries seed as archive members, minus anything the
// predicate drops.
func (b *caseBuilder) vaultMembers(skip func(rel string) bool) []member {
	return seedMembers(b.seeds["entries"], skip)
}

func noGit(rel string) bool { return strings.HasPrefix(rel, ".git") }

func buildCases(seeds map[string][]FileSpec) ([]Case, error) {
	b := &caseBuilder{seeds: seeds}
	for _, name := range []string{"empty", "entries"} {
		if _, ok := seeds[name]; !ok {
			return nil, fmt.Errorf("seed %q missing", name)
		}
	}
	b.exportCases()
	b.backupCases()
	b.restoreCases()
	b.roundTripCases()
	if b.err != nil {
		return nil, b.err
	}
	seen := map[string]bool{}
	for _, c := range b.cases {
		if seen[c.ID] {
			return nil, fmt.Errorf("duplicate case id %s", c.ID)
		}
		seen[c.ID] = true
	}
	return b.cases, nil
}

func (b *caseBuilder) exportCases() {
	const e = "entries"
	jsonYes := []string{"export", "--format", "json", "--yes"}
	b.add(
		// ---- output formats and plain runs
		newCase("export-json-stdout-yes", "export-run", e, "JSON to stdout with --yes: payload then the count line on stdout, warning on stderr", closed(jsonYes...)),
		newCase("export-csv-stdout-short-y", "export-run", e, "CSV to stdout with -y (attachment notice on stderr)", closed("export", "--format", "csv", "-y")),
		newCase("export-json-output-file", "export-output", e, "--output FILE writes the payload to a 0600 file; stdout carries only the count line", closed("export", "--format", "json", "--yes", "--output", "out.json")),
		newCase("export-csv-output-equals-form", "export-output", e, "--format=csv --output=FILE equals forms", closed("export", "--format=csv", "--output=out.csv", "-y")),
		newCase("export-yes-bool-true-equals", "export-confirm", e, "--yes=true is the same as --yes", closed("export", "--format", "json", "--yes=true")),
		// ---- mapping
		newCase("export-json-mapping", "export-mapping", e, "JSON with a rename mapping", closed("export", "--format", "json", "-y", "--mapping", "password=pw,username=user")),
		newCase("export-csv-mapping-spaces", "export-mapping", e, "CSV mapping with padding spaces and a trailing comma", closed("export", "--format", "csv", "-y", "--mapping", " password = pw , username = user ,")),
		newCase("export-csv-mapping-collision", "export-mapping", e, "two fields mapped to one CSV header", closed("export", "--format", "csv", "-y", "--mapping", "username=same,password=same")),
		// Deliberately absent: a JSON mapping that sends two fields to one key.
		// The Go exporter ranges over a map, so which value wins differs from run
		// to run (the generator's two-run check rejected it).
		newCase("export-mapping-path-key", "export-mapping", e, "mapping the path column itself", closed("export", "--format", "csv", "-y", "--mapping", "path=title")),
		newCase("export-mapping-unknown-field", "export-mapping", e, "a mapping for a field no entry has", closed("export", "--format", "csv", "-y", "--mapping", "nosuch=x")),
		newCase("export-mapping-extra-equals", "export-mapping", e, "a=b=c: the column keeps the second =", closed("export", "--format", "csv", "-y", "--mapping", "password=a=b")),
		newCase("export-mapping-only-commas", "export-mapping", e, "only separators is an empty mapping", closed("export", "--format", "csv", "-y", "--mapping", ",,")),
		newCase("export-mapping-empty-value", "export-mapping", e, "--mapping with an empty value", closed("export", "--format", "csv", "-y", "--mapping", "")),
		newCase("export-mapping-no-equals", "export-mapping", e, "mapping pair without =", closed("export", "--format", "json", "-y", "--mapping", "password")),
		newCase("export-mapping-empty-field", "export-mapping", e, "mapping pair with an empty field", closed("export", "--format", "json", "-y", "--mapping", "=x")),
		newCase("export-mapping-empty-column", "export-mapping", e, "mapping pair with an empty column", closed("export", "--format", "json", "-y", "--mapping", "x=")),
		newCase("export-mapping-error-before-vault", "export-mapping", "", "an invalid mapping is reported before the vault is looked at", closed("export", "--format", "json", "-y", "--mapping", "bad")),
		newCase("export-mapping-error-before-prompt", "export-mapping", e, "an invalid mapping is reported before the confirmation prompt", closed("export", "--format", "json", "--mapping", "bad")),
		// ---- format
		newCase("export-format-missing", "export-format", e, "required --format missing", closed("export", "-y")),
		newCase("export-format-missing-no-vault", "export-format", "", "required --format is checked before the vault", closed("export", "-y")),
		newCase("export-format-yaml", "export-format", e, "unsupported format", closed("export", "--format", "yaml", "-y")),
		newCase("export-format-uppercase", "export-format", e, "format names are case-sensitive", closed("export", "--format", "JSON", "-y")),
		newCase("export-format-empty", "export-format", e, "--format with an empty value is unsupported, not missing", closed("export", "--format", "", "-y")),
		newCase("export-format-needs-argument", "export-format", e, "--format as the last token", closed("export", "-y", "--format")),
		newCase("export-format-before-mapping", "export-format", e, "format validation precedes mapping validation", closed("export", "--format", "yaml", "--mapping", "bad", "-y")),
		newCase("export-format-before-vault", "export-format", "", "format validation precedes the vault check", closed("export", "--format", "yaml", "-y")),
		newCase("export-format-last-wins", "export-format", e, "a repeated --format keeps the last value", closed("export", "--format", "yaml", "--format", "csv", "-y")),
		// ---- argv / flags
		newCase("export-no-short-format-flag", "export-argv", e, "-f is not a flag of export", closed("export", "-f", "json", "-y")),
		newCase("export-extra-positional", "export-argv", e, "export takes no positional argument", closed("export", "extra", "--format", "json", "-y")),
		newCase("export-unknown-flag", "export-argv", e, "unknown long flag", closed("export", "--format", "json", "-y", "--bogus")),
		newCase("export-yes-invalid-bool", "export-argv", e, "--yes=maybe", closed("export", "--format", "json", "--yes=maybe")),
		newCase("export-help", "export-argv", e, "export --help prints the cobra help", closed("export", "--help")),
		newCase("export-json-flag-gate", "export-argv", e, "global --json is refused by the output-format gate", closed("export", "--format", "json", "-y", "--json")),
		newCase("export-output-before-command", "export-argv", e, "a global-looking --output before the command binds export's own --output", closed("--output", "before.json", "export", "--format", "json", "-y")),
		newCase("export-output-named-yaml", "export-argv", e, "--output yaml is a file name, not an output format", closed("export", "--format", "csv", "-y", "--output", "yaml")),
		newCase("export-quiet-yes", "export-quiet", e, "--quiet --yes suppresses the warning and the count line", closed("--quiet", "export", "--format", "json", "--yes")),
		newCase("export-quiet-prompt", "export-quiet", e, "--quiet without --yes still shows warning and prompt", piped("y\n", "--quiet", "export", "--format", "json")),
		newCase("export-quiet-empty-vault", "export-quiet", "empty", "--quiet suppresses the no-entries line", closed("--quiet", "export", "--format", "json", "-y")),
		// ---- confirmation
		newCase("export-confirm-closed-stdin", "export-confirm", e, "no --yes and a closed stdin: the read error is the failure", closed("export", "--format", "json")),
		newCase("export-confirm-empty-stdin", "export-confirm", e, "no --yes and an empty pipe", piped("", "export", "--format", "json")),
		newCase("export-confirm-y", "export-confirm", e, "answer y", piped("y\n", "export", "--format", "json")),
		newCase("export-confirm-upper-y", "export-confirm", e, "answer Y is accepted case-insensitively", piped("Y\n", "export", "--format", "json")),
		newCase("export-confirm-yes-word", "export-confirm", e, "the word yes is not y", piped("yes\n", "export", "--format", "json")),
		newCase("export-confirm-n", "export-confirm", e, "answer n cancels with exit 0", piped("n\n", "export", "--format", "json")),
		newCase("export-confirm-blank", "export-confirm", e, "a blank answer cancels", piped("\n", "export", "--format", "json")),
		newCase("export-confirm-y-without-newline", "export-confirm", e, "y then EOF without a newline", piped("y", "export", "--format", "json")),
		newCase("export-confirm-padded-y", "export-confirm", e, "padding spaces around y are trimmed", piped("  y \n", "export", "--format", "json")),
		newCase("export-confirm-crlf-y", "export-confirm", e, "y with CRLF", piped("y\r\n", "export", "--format", "json")),
		newCase("export-confirm-yy", "export-confirm", e, "yy is not y", piped("yy\n", "export", "--format", "json")),
		newCase("export-confirm-first-line-only", "export-confirm", e, "only the first line is read", piped("n\ny\n", "export", "--format", "json")),
		newCase("export-confirm-extra-input-ignored", "export-confirm", e, "text after the first newline is ignored when it says y", piped("y\ngarbage\n", "export", "--format", "json")),
		newCase("export-cancel-leaves-no-output-file", "export-confirm", e, "a canceled export creates no --output file and no audit record", piped("n\n", "export", "--format", "json", "--output", "out.json")),
		newCase("export-confirm-then-output-file", "export-confirm", e, "confirmed export to a file", piped("y\n", "export", "--format", "csv", "--output", "out.csv")),
		newCase("export-confirm-no-vault", "export-confirm", "", "a confirmed export without a vault fails as not initialized", piped("y\n", "export", "--format", "json")),
		newCase("export-confirm-closed-stdin-no-vault", "export-confirm", "", "the prompt precedes the vault check", closed("export", "--format", "json")),
		newCase("export-yes-no-vault", "export-vault", "", "--yes without a vault", closed(jsonYes...)),
		newCase("export-yes-false-answers-y", "export-confirm", e, "--yes=false prompts like no flag", piped("y\n", "export", "--format", "json", "--yes=false")),
		// ---- vault selection and failures
		newCase("export-vault-flag", "export-vault", e, "--vault selects the vault instead of the environment", closed("--vault", "{VAULT}", "export", "--format", "csv", "-y")).without("SYMVAULT_VAULT"),
		newCase("export-vault-flag-wins-over-env", "export-vault", e, "--vault beats SYMVAULT_VAULT", closed("--vault", "{VAULT}", "export", "--format", "csv", "-y")).withEnv("SYMVAULT_VAULT", "{ROOT}/other"),
		// Deliberately absent (shared vault-open diagnostics, not these commands): a
		// wrong or missing passphrase, a corrupt identity file and a vault path
		// with ".." (Go's config loader refuses it) fail inside the unlock/config
		// layer with that layer's wording for every command.
		newCase("export-vault-empty-directory", "export-vault", "", "an existing but uninitialised vault directory", closed(jsonYes...)).withPre(dir("vault", 0o700)),
		// ---- empty vault
		newCase("export-empty-vault-json", "export-empty", "empty", "no entries: message on stdout, nothing exported", closed(jsonYes...)),
		newCase("export-empty-vault-csv-output", "export-empty", "empty", "no entries with --output: the file is not created", closed("export", "--format", "csv", "-y", "--output", "out.csv")),
		// ---- output destinations
		newCase("export-output-existing-keeps-mode", "export-output", e, "an existing 0644 file is truncated in place and keeps its mode", closed("export", "--format", "json", "-y", "--output", "out.json")).withPre(text("work/out.json", 0o644, strings.Repeat("old content that is longer than the export. ", 200))),
		newCase("export-output-existing-readonly", "export-output", e, "an existing 0400 file cannot be opened for writing", closed("export", "--format", "json", "-y", "--output", "out.json")).withPre(text("work/out.json", 0o400, "keep me\n")),
		newCase("export-output-is-directory", "export-output", e, "--output names a directory", closed("export", "--format", "json", "-y", "--output", "outdir")).withPre(dir("work/outdir", 0o755)),
		newCase("export-output-missing-parent", "export-output", e, "--output below a missing directory", closed("export", "--format", "json", "-y", "--output", "nodir/out.json")),
		newCase("export-output-parent-is-file", "export-output", e, "--output below a regular file", closed("export", "--format", "json", "-y", "--output", "plain/out.json")).withPre(text("work/plain", 0o644, "x")),
		newCase("export-output-unwritable-directory", "export-output", e, "--output into a 0500 directory", closed("export", "--format", "json", "-y", "--output", "ro/out.json")).withPre(dir("work/ro", 0o500)),
		newCase("export-output-dash-is-a-file", "export-output", e, "--output - writes a file named -", closed("export", "--format", "json", "-y", "--output", "-")),
		newCase("export-output-empty-string-is-stdout", "export-output", e, "--output \"\" is the stdout default", closed("export", "--format", "json", "-y", "--output", "")),
		newCase("export-output-through-symlink", "export-output", e, "--output through a symlink writes the target", closed("export", "--format", "json", "-y", "--output", "link.json")).withPre(text("work/real.json", 0o644, "old\n"), link("work/link.json", "real.json")),
		newCase("export-output-dangling-symlink", "export-output", e, "--output through a dangling symlink creates the target", closed("export", "--format", "json", "-y", "--output", "dangling.json")).withPre(link("work/dangling.json", "created-by-export.json")),
		newCase("export-output-absolute-path", "export-output", e, "--output with an absolute path", closed("export", "--format", "csv", "-y", "--output", "{WORK}/abs.csv")),
		newCase("export-output-inside-vault", "export-output", e, "--output into the vault directory", closed("export", "--format", "json", "-y", "--output", "{VAULT}/plain-export.json")),
		newCase("export-output-twice", "export-output", e, "two exports to one file: the second truncates the first", closed("export", "--format", "json", "-y", "--output", "out.dat"), closed("export", "--format", "csv", "-y", "--mapping", "path=p", "--output", "out.dat")),
		newCase("export-output-then-stdout", "export-output", e, "a file export followed by a stdout export", closed("export", "--format", "csv", "-y", "--output", "out.csv"), closed("export", "--format", "csv", "-y")),
		// ---- unreadable entry
		newCase("export-corrupt-first-entry-json-stdout", "export-entry-error", e, "the first entry cannot be decrypted (JSON, stdout)", closed(jsonYes...)).withPre(text("vault/entries/a/first.age", 0o600, "corrupt\n")).tail("cannot read entry a/first: "),
		newCase("export-corrupt-first-entry-json-file", "export-entry-error", e, "the first entry cannot be decrypted (JSON, file): what is left in the file", closed("export", "--format", "json", "-y", "--output", "out.json")).withPre(text("vault/entries/a/first.age", 0o600, "corrupt\n")).tail("cannot read entry a/first: "),
		newCase("export-corrupt-first-entry-csv-file", "export-entry-error", e, "the first entry cannot be decrypted (CSV, file): the file is created empty", closed("export", "--format", "csv", "-y", "--output", "out.csv")).withPre(text("vault/entries/a/first.age", 0o600, "corrupt\n")).tail("cannot read entry a/first: "),
		// ---- audit trail
		newCase("export-audit-record-written", "export-audit", e, "a successful export appends one audit record; two exports append two", closed(jsonYes...), closed("export", "--format", "csv", "-y")),
	)
}

func (b *caseBuilder) backupCases() {
	const e = "entries"
	extras := []FileSpec{
		text("vault/exec.sh", 0o755, "#!/bin/sh\n"),
		text("vault/readonly.txt", 0o400, "ro\n"),
		dir("vault/emptydir", 0o750),
		text("vault/entries/sp ace/ü.age", 0o640, "spaced\n"),
		link("vault/entries-link", "entries"),
		link("vault/dangling-link", "nowhere"),
	}
	b.add(
		newCase("backup-plain", "backup-run", e, "backup to ARCHIVE.tar.gz in the working directory", closed("backup", "out.tar.gz")),
		newCase("backup-appends-suffix", "backup-run", e, "an archive path without .tar.gz gets the suffix", closed("backup", "out")),
		newCase("backup-tgz-suffix-appended", "backup-run", e, ".tgz is not .tar.gz", closed("backup", "out.tgz")),
		newCase("backup-double-suffix-kept", "backup-run", e, "a path already ending in .tar.gz is kept", closed("backup", "out.tar.gz.tar.gz")),
		newCase("backup-bare-suffix-name", "backup-run", e, "the argument .tar.gz is its own suffix", closed("backup", ".tar.gz")),
		newCase("backup-empty-argument", "backup-run", e, "an empty ARCHIVE argument becomes .tar.gz", closed("backup", "")),
		newCase("backup-directory-argument", "backup-run", e, "ARCHIVE ending in a slash becomes DIR/.tar.gz", closed("backup", "exists/")).withPre(dir("work/exists", 0o755)),
		newCase("backup-absolute-path", "backup-run", e, "an absolute archive path is printed as given", closed("backup", "{WORK}/abs")),
		newCase("backup-exclude-git", "backup-exclude-git", e, "--exclude-git drops .git and, through the prefix test, .gitignore", closed("backup", "--exclude-git", "out.tar.gz")),
		newCase("backup-exclude-git-prefix-quirk", "backup-exclude-git", e, "every top-level name starting with .git is dropped (.github, .gitx, .gitmodules)", closed("backup", "--exclude-git", "out.tar.gz")).withPre(text("vault/.github-notes", 0o600, "n\n"), dir("vault/.gitx", 0o700), text("vault/.gitx/f", 0o600, "f\n"), text("vault/.gitmodules", 0o600, "m\n"), text("vault/entries/.git-keep", 0o600, "k\n")),
		newCase("backup-exclude-git-false", "backup-exclude-git", e, "--exclude-git=false keeps everything", closed("backup", "--exclude-git=false", "out.tar.gz")),
		newCase("backup-exclude-git-true-equals", "backup-exclude-git", e, "--exclude-git=true", closed("backup", "--exclude-git=true", "out.tar.gz")),
		newCase("backup-exclude-git-after-argument", "backup-exclude-git", e, "the flag may follow the argument", closed("backup", "out.tar.gz", "--exclude-git")),
		newCase("backup-exclude-git-invalid-bool", "backup-exclude-git", e, "--exclude-git=maybe", closed("backup", "--exclude-git=maybe", "out.tar.gz")),
		newCase("backup-modes-and-skips", "backup-members", e, "executable, read-only, empty-directory and spaced names are archived with their modes; symlinks are skipped", closed("backup", "out.tar.gz")).withPre(extras...),
		newCase("backup-vault-flag", "backup-run", e, "--vault selects the vault", closed("--vault", "{VAULT}", "backup", "out.tar.gz")).without("SYMVAULT_VAULT"),
		newCase("backup-quiet", "backup-run", e, "--quiet suppresses the confirmation line", closed("--quiet", "backup", "out.tar.gz")),
		newCase("backup-existing-file-overwritten", "backup-destination", e, "an existing archive file is truncated in place and keeps its mode", closed("backup", "out.tar.gz")).withPre(text("work/out.tar.gz", 0o644, strings.Repeat("stale archive bytes ", 500))),
		newCase("backup-existing-readonly-file", "backup-destination", e, "an existing 0400 archive file cannot be opened for writing", closed("backup", "out.tar.gz")).withPre(text("work/out.tar.gz", 0o400, "keep\n")),
		newCase("backup-destination-is-directory", "backup-destination", e, "the archive path is a directory", closed("backup", "out.tar.gz")).withPre(dir("work/out.tar.gz", 0o755)),
		newCase("backup-creates-missing-directories", "backup-destination", e, "missing parent directories are created with mode 0700", closed("backup", "a/b/c/out.tar.gz")),
		newCase("backup-parent-is-file", "backup-destination", e, "a regular file where a parent directory is needed", closed("backup", "plain/out.tar.gz")).withPre(text("work/plain", 0o644, "x")),
		newCase("backup-unwritable-parent", "backup-destination", e, "the parent exists but is not writable", closed("backup", "ro/out.tar.gz")).withPre(dir("work/ro", 0o500)),
		newCase("backup-unwritable-grandparent", "backup-destination", e, "a missing directory below an unwritable one", closed("backup", "ro/new/out.tar.gz")).withPre(dir("work/ro", 0o500)),
		newCase("backup-no-vault", "backup-vault", "", "no vault directory", closed("backup", "out.tar.gz")),
		newCase("backup-empty-vault-directory", "backup-vault", "", "an existing but uninitialised vault directory", closed("backup", "out.tar.gz")).withPre(dir("vault", 0o700)),
		newCase("backup-no-vault-creates-nothing", "backup-vault", "", "a failed backup leaves no archive and no directory", closed("backup", "newdir/out.tar.gz")),
		newCase("backup-minimal-vault", "backup-vault", "", "a hand-built minimal vault", closed("backup", "out.tar.gz")).withPre(dir("vault", 0o700), text("vault/identity.age", 0o600, "id\n"), text("vault/config.yaml", 0o600, "k: v\n"), dir("vault/entries", 0o700)),
		newCase("backup-unreadable-file", "backup-vault", e, "a file that cannot be read aborts the backup after earlier members are written", closed("backup", "out.tar.gz")).withPre(text("vault/zz-unreadable", 0o000, "secret\n")),
		newCase("backup-no-argument", "backup-argv", e, "missing ARCHIVE", closed("backup")),
		newCase("backup-two-arguments", "backup-argv", e, "two ARCHIVE arguments", closed("backup", "a.tar.gz", "b.tar.gz")),
		newCase("backup-unknown-flag", "backup-argv", e, "unknown flag", closed("backup", "--bogus", "out.tar.gz")),
		newCase("backup-argument-after-double-dash", "backup-argv", e, "-- makes a dash-prefixed name an argument", closed("backup", "--", "--odd")),
		newCase("backup-help", "backup-argv", e, "backup --help", closed("backup", "--help")),
		newCase("backup-json-flag-gate", "backup-argv", e, "--json is refused by the output-format gate", closed("backup", "out.tar.gz", "--json")),
		newCase("backup-twice-same-path", "backup-destination", e, "a second backup replaces the first archive", closed("backup", "out.tar.gz"), closed("backup", "--exclude-git", "out.tar.gz")),
	)
}

func (b *caseBuilder) restoreCases() {
	full := b.vaultMembers(nil)
	nogit := b.vaultMembers(noGit)
	without := func(prefix string) []member {
		return b.vaultMembers(func(rel string) bool { return noGit(rel) || strings.HasPrefix(rel, prefix) })
	}
	in := func(mode uint32, members []member) FileSpec { return b.archive("work/in.tar.gz", mode, members) }
	validTar, _ := buildGz(nogit)
	b.add(
		newCase("restore-fresh-full-archive", "restore-run", "", "restore a full backup into a missing vault directory", closed("restore", "in.tar.gz"), closed("list")).withPre(in(0o644, full)),
		newCase("restore-fresh-no-git-archive", "restore-run", "", "restore an archive without .git", closed("restore", "in.tar.gz"), closed("list")).withPre(in(0o644, nogit)),
		newCase("restore-into-empty-existing-directory", "restore-target", "", "the vault directory exists and is empty", closed("restore", "in.tar.gz"), closed("list")).withPre(dir("vault", 0o755), in(0o644, nogit)),
		newCase("restore-into-other-vault-merges", "restore-target", "empty", "restore an archive over a different initialised vault: files overwritten, others kept", closed("restore", "in.tar.gz"), closed("list")).withPre(in(0o644, nogit)),
		newCase("restore-over-same-vault-no-git", "restore-target", "entries", "restore a backup over the vault it came from (without .git)", closed("restore", "in.tar.gz"), closed("list")).withPre(in(0o644, nogit)),
		newCase("restore-over-same-vault-full", "restore-target", "entries", "restore a full backup over the vault it came from: read-only .git objects", closed("restore", "in.tar.gz"), closed("list")).withPre(in(0o644, full)),
		newCase("restore-extra-files-preserved", "restore-target", "entries", "files not in the archive stay", closed("restore", "in.tar.gz")).withPre(in(0o644, nogit), text("vault/extra.txt", 0o600, "mine\n"), dir("vault/extra-dir", 0o700)),
		newCase("restore-existing-readonly-file-in-writable-dir", "restore-target", "", "an existing read-only file that the archive overwrites", closed("restore", "in.tar.gz")).withPre(dir("vault", 0o700), text("vault/identity.age", 0o400, "old identity\n"), in(0o644, nogit)),
		newCase("restore-file-over-directory", "restore-target", "", "the archive file lands on an existing directory", closed("restore", "in.tar.gz")).withPre(dir("vault", 0o700), dir("vault/identity.age", 0o700), in(0o644, nogit)),
		newCase("restore-directory-over-file", "restore-target", "", "an archive directory lands on an existing file", closed("restore", "in.tar.gz")).withPre(dir("vault", 0o700), text("vault/entries", 0o600, "file\n"), in(0o644, nogit)),
		newCase("restore-vault-path-is-file", "restore-target", "", "the vault path is a regular file", closed("restore", "in.tar.gz")).withPre(text("vault", 0o600, "file\n"), in(0o644, nogit)),
		newCase("restore-unwritable-vault-parent", "restore-target", "", "the vault directory cannot be created", closed("--vault", "{ROOT}/ro/v", "restore", "in.tar.gz")).withPre(dir("ro", 0o500), in(0o644, nogit)),
		newCase("restore-target-is-symlink", "restore-target", "", "an existing target that is a symlink is refused", closed("restore", "in.tar.gz")).withPre(dir("vault", 0o700), link("vault/identity.age", "{WORK}/elsewhere"), in(0o644, nogit)),
		newCase("restore-parent-is-symlink", "restore-target", "", "a symlinked parent directory inside the vault", closed("restore", "in.tar.gz")).withPre(dir("vault", 0o700), dir("escape", 0o700), link("vault/entries", "{ROOT}/escape"), in(0o644, nogit)),
		newCase("restore-vault-dir-is-symlink", "restore-target", "", "the vault directory itself is a symlink", closed("restore", "in.tar.gz")).withPre(dir("real-vault", 0o700), link("vault", "{ROOT}/real-vault"), in(0o644, nogit)),
		// ---- archive file problems
		newCase("restore-archive-missing", "restore-archive", "", "ARCHIVE does not exist", closed("restore", "nosuch.tar.gz")),
		newCase("restore-archive-missing-existing-vault", "restore-archive", "entries", "a missing archive leaves the vault untouched", closed("restore", "nosuch.tar.gz")),
		newCase("restore-archive-is-directory", "restore-archive", "", "ARCHIVE is a directory", closed("restore", "adir")).withPre(dir("work/adir", 0o755)),
		newCase("restore-archive-not-gzip", "restore-archive", "", "ARCHIVE is not gzip", closed("restore", "in.tar.gz")).withPre(text("work/in.tar.gz", 0o644, "this is not a gzip stream\n")),
		newCase("restore-archive-empty-file", "restore-archive", "", "ARCHIVE is empty", closed("restore", "in.tar.gz")).withPre(text("work/in.tar.gz", 0o644, "")),
		newCase("restore-archive-gzip-not-tar", "restore-archive", "", "ARCHIVE is gzip of plain text", closed("restore", "in.tar.gz")).withPre(rawFile("work/in.tar.gz", 0o644, gzipBytes([]byte(strings.Repeat("not a tar archive ", 64))))),
		newCase("restore-archive-truncated-gzip", "restore-archive", "", "ARCHIVE is cut in half", closed("restore", "in.tar.gz")).withPre(rawFile("work/in.tar.gz", 0o644, validTar[:len(validTar)/2])),
		newCase("restore-archive-unreadable-file", "restore-archive", "", "ARCHIVE exists but is not readable", closed("restore", "in.tar.gz")).withPre(rawFile("work/in.tar.gz", 0o000, validTar)),
		newCase("restore-archive-without-extension", "restore-archive", "", "restore does not require a .tar.gz name", closed("restore", "backup-file")).withPre(rawFile("work/backup-file", 0o644, validTar)),
		newCase("restore-archive-empty-tar", "restore-archive", "", "a valid gzip tar with no members", closed("restore", "in.tar.gz")).withPre(in(0o644, nil)),
		// ---- required files
		newCase("restore-missing-identity", "restore-verify", "", "no identity.age in the archive: files are already written", closed("restore", "in.tar.gz")).withPre(in(0o644, b.vaultMembers(func(rel string) bool { return noGit(rel) || rel == "identity.age" }))),
		newCase("restore-missing-config", "restore-verify", "", "no config.yaml in the archive", closed("restore", "in.tar.gz")).withPre(in(0o644, b.vaultMembers(func(rel string) bool { return noGit(rel) || rel == "config.yaml" }))),
		newCase("restore-missing-entries-directory", "restore-verify", "", "no entries directory in the archive", closed("restore", "in.tar.gz")).withPre(in(0o644, without("entries"))),
		newCase("restore-missing-required-existing-vault-covers", "restore-verify", "entries", "the archive lacks identity.age but the vault already has one: verification passes", closed("restore", "in.tar.gz")).withPre(in(0o644, b.vaultMembers(func(rel string) bool { return noGit(rel) || rel == "identity.age" }))),
		// ---- hostile members
		newCase("restore-member-dotdot", "restore-member", "", "a member escaping with ..", closed("restore", "in.tar.gz")).withPre(in(0o644, append(append([]member{}, nogit...), fileMember("../evil.txt", 0o600, "evil\n")))),
		newCase("restore-member-nested-dotdot", "restore-member", "", "a member escaping through a nested ..", closed("restore", "in.tar.gz")).withPre(in(0o644, append(append([]member{}, nogit...), fileMember("entries/../../evil.txt", 0o600, "evil\n")))),
		newCase("restore-member-absolute", "restore-member", "", "an absolute member name", closed("restore", "in.tar.gz")).withPre(in(0o644, append(append([]member{}, nogit...), fileMember("/abs-evil.txt", 0o600, "evil\n")))),
		newCase("restore-member-backslash", "restore-member", "", "a backslash in a member name", closed("restore", "in.tar.gz")).withPre(in(0o644, append(append([]member{}, nogit...), fileMember(`dir\evil.txt`, 0o600, "evil\n")))),
		newCase("restore-member-dot", "restore-member", "", "a member named .", closed("restore", "in.tar.gz")).withPre(in(0o644, append([]member{dirMember(".", 0o755)}, nogit...))),
		newCase("restore-member-unclean-name", "restore-member", "", "a member name that path.Clean would change", closed("restore", "in.tar.gz")).withPre(in(0o644, append(append([]member{}, nogit...), fileMember("entries//twice.age", 0o600, "x\n")))),
		newCase("restore-member-symlink", "restore-member", "", "a symlink member", closed("restore", "in.tar.gz")).withPre(in(0o644, append(append([]member{}, nogit...), member{name: "sneaky", typ: tar.TypeSymlink, mode: 0o777, link: "/etc/passwd"}))),
		newCase("restore-member-hardlink", "restore-member", "", "a hard-link member", closed("restore", "in.tar.gz")).withPre(in(0o644, append(append([]member{}, nogit...), member{name: "hard", typ: tar.TypeLink, mode: 0o600, link: "identity.age"}))),
		newCase("restore-member-duplicate-name", "restore-member", "", "the same name twice: the later content wins", closed("restore", "in.tar.gz")).withPre(in(0o644, append(append([]member{}, nogit...), fileMember("dup.txt", 0o600, "first\n"), fileMember("dup.txt", 0o600, "second\n")))),
		newCase("restore-member-mode-clamping", "restore-member", "", "archive modes are clamped to 0700 (dirs) and 0600 (files)", closed("restore", "in.tar.gz")).withPre(in(0o644, append(append([]member{}, nogit...), dirMember("entries/wide", 0o777), fileMember("entries/wide/exec.age", 0o777, "x\n"), fileMember("entries/wide/ro.age", 0o444, "y\n"), fileMember("entries/wide/zero.age", 0o000, "z\n"), fileMember("entries/wide/setuid.age", 0o4755, "s\n"), dirMember("entries/sticky", 0o1777)))),
		newCase("restore-member-implicit-parents", "restore-member", "", "file members whose parent directories are not in the archive", closed("restore", "in.tar.gz")).withPre(in(0o644, append(append([]member{}, nogit...), fileMember("deep/er/file.txt", 0o644, "d\n")))),
		newCase("restore-member-trailing-slash-dir", "restore-member", "", "a directory member written with a trailing slash", closed("restore", "in.tar.gz")).withPre(in(0o644, append([]member{dirMember("entries/", 0o755)}, withoutEntriesDir(nogit)...))),
		// ---- argv
		newCase("restore-vault-flag-relative", "restore-argv", "", "--vault with a relative path is printed as given", closed("--vault", "rel-vault", "restore", "in.tar.gz")).without("SYMVAULT_VAULT").withPre(in(0o644, nogit)),
		newCase("restore-vault-flag-and-env", "restore-argv", "", "--vault beats SYMVAULT_VAULT", closed("--vault", "{ROOT}/chosen", "restore", "in.tar.gz")).withPre(in(0o644, nogit)),
		newCase("restore-quiet", "restore-argv", "", "--quiet suppresses the confirmation line", closed("--quiet", "restore", "in.tar.gz")).withPre(in(0o644, nogit)),
		newCase("restore-no-argument", "restore-argv", "entries", "missing ARCHIVE", closed("restore")),
		newCase("restore-two-arguments", "restore-argv", "entries", "two ARCHIVE arguments", closed("restore", "a.tar.gz", "b.tar.gz")),
		newCase("restore-unknown-flag", "restore-argv", "entries", "unknown flag", closed("restore", "--bogus", "in.tar.gz")).withPre(in(0o644, nogit)),
		newCase("restore-no-exclude-git-flag", "restore-argv", "entries", "restore has no --exclude-git", closed("restore", "--exclude-git", "in.tar.gz")).withPre(in(0o644, nogit)),
		newCase("restore-help", "restore-argv", "entries", "restore --help", closed("restore", "--help")),
		newCase("restore-json-flag-gate", "restore-argv", "", "--json is refused by the output-format gate", closed("restore", "in.tar.gz", "--json")).withPre(in(0o644, nogit)),
		newCase("restore-no-vault-env", "restore-argv", "", "without SYMVAULT_VAULT or --vault the default vault below HOME is used", closed("restore", "in.tar.gz")).without("SYMVAULT_VAULT").withPre(in(0o644, nogit)),
	)
}

func withoutEntriesDir(members []member) []member {
	var out []member
	for _, m := range members {
		if m.name == "entries" {
			continue
		}
		out = append(out, m)
	}
	return out
}

func (b *caseBuilder) roundTripCases() {
	const e = "entries"
	b.add(
		newCase("roundtrip-backup-restore-list-get", "roundtrip", e, "backup, restore into a second vault, then list/get/export from it",
			closed("backup", "rt.tar.gz"),
			closed("--vault", "{ROOT}/restored", "restore", "rt.tar.gz"),
			closed("--vault", "{ROOT}/restored", "list"),
			// Not --print: a plaintext print records an expose_plaintext audit entry
			// in Go, which the native get does not write yet (a get-command gap).
			closed("--vault", "{ROOT}/restored", "get", "work/example.password", "--digest"),
			closed("--vault", "{ROOT}/restored", "get", "work/example.password", "--length"),
			closed("--vault", "{ROOT}/restored", "export", "--format", "json", "-y"),
			closed("export", "--format", "json", "-y"),
		),
		newCase("roundtrip-exclude-git", "roundtrip", e, "a backup without git history restores into a working vault",
			closed("backup", "--exclude-git", "rt.tar.gz"),
			closed("--vault", "{ROOT}/restored", "restore", "rt.tar.gz"),
			closed("--vault", "{ROOT}/restored", "list"),
			closed("--vault", "{ROOT}/restored", "export", "--format", "csv", "-y"),
		),
		newCase("roundtrip-restore-over-original", "roundtrip", e, "restore the backup over the vault it was taken from",
			closed("backup", "rt.tar.gz"),
			closed("restore", "rt.tar.gz"),
			closed("list"),
		),
		newCase("roundtrip-restore-over-original-exclude-git", "roundtrip", e, "restore a git-less backup over the original vault",
			closed("backup", "--exclude-git", "rt.tar.gz"),
			closed("restore", "rt.tar.gz"),
			closed("export", "--format", "json", "-y"),
		),
		newCase("roundtrip-empty-vault", "roundtrip", "empty", "backup and restore of a vault without entries",
			closed("backup", "rt.tar.gz"),
			closed("--vault", "{ROOT}/restored", "restore", "rt.tar.gz"),
			closed("--vault", "{ROOT}/restored", "list"),
			closed("--vault", "{ROOT}/restored", "export", "--format", "json", "-y"),
		),
		newCase("roundtrip-export-to-file-then-backup", "roundtrip", e, "a plaintext export file inside the vault is part of the next backup",
			closed("export", "--format", "json", "-y", "--output", "{VAULT}/plain.json"),
			closed("backup", "rt.tar.gz"),
		),
	)
}
