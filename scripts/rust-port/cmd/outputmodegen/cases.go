package main

import "strings"

// seedPlan is a named starting state built once by the oracle.
type seedPlan struct {
	name  string
	steps []seedStep
}

// caseSpec is one scenario: a base argv run once per accepted output mode.
type caseSpec struct {
	id, path, desc, seed string
	argv                 []string
	// modes restricts the run to these modes (default: every mode the gate
	// accepts for the path).
	modes []string
	env   map[string]string
	stdin string
	files []workFile
	rules []string
	// opaque lists tree path prefixes recorded by presence only.
	opaque []string
	// archives lists tree path prefixes whose files are decoded as .tar.gz and
	// recorded as their members.
	archives []string
	post     [][]string
}

func argv(args ...string) seedStep { return seedStep{Argv: args} }

const (
	// A valid age X25519 recipient (the public example key of the age tool).
	ageKey = "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p"

	auditLog = `{"ts":"2020-01-01T00:00:00.123456789Z","agent":"hermes","action":"get_entry","path":"work/example","transport":"cli","ok":true}
{"ts":"2020-01-02T00:00:00Z","agent":"hermes","action":"set_entry","path":"a/first","ok":false,"error":"denied"}
`

	sharesJSON = `{"version":1,"grants":[{"id":"grant-a","from_agent":"source","to_agent":"target","secret_path":"work/example","secret_field":"password","nonce":"n1","status":"approved","created_at":"2025-02-03T04:05:06Z","expires_at":"2099-01-01T00:00:00Z"}]}`

	// A second valid age recipient (the public example key of the age spec).
	otherAgeKey = "age1lggyhqrw2nlhcxprm67z43rta597azn8gknawjehu9d9dl0jq3yqqvfafg"

	devicesJSON = `[{"name":"laptop","public_key":"` + otherAgeKey + `","added_at":"2026-09-14T12:34:56.123+02:00"},{"name":"phone","public_key":"` + ageKey + `","added_at":"2026-01-01T00:00:00Z","last_seen":"2026-09-14T10:11:12.9Z"}]`
)

// seedPlans are the frozen starting vaults. Their commands are recorded in the
// fixture; --check refuses a generator whose commands differ.
func seedPlans() []seedPlan {
	globalConfig := seedStep{CopyFrom: "home/vault/config.yaml", CopyTo: "home/.symvault/config.yaml"}
	entries := []seedStep{
		argv("init"),
		argv("add", "a/first", "--value", "Val-Alpha-000"),
		argv("add", "work/example", "--value", "Val-Alpha-001", "--username", "alice", "--url", "https://example.test", "--notes", "a,b"),
		argv("add", "work/two", "--value", "Val-Alpha-002", "--username", "bob"),
		// A fresh vault's first open rewrites config.yaml and creates .lock and
		// manifest.age; settle them so scenarios start from a settled vault.
		argv("list"),
		// The `config` commands read ~/.symvault/config.yaml; the vault's own
		// config is a valid global config.
		globalConfig,
	}
	with := func(extra ...seedStep) []seedStep { return append(append([]seedStep(nil), entries...), extra...) }
	return []seedPlan{
		{name: "empty", steps: []seedStep{argv("init"), argv("list"), globalConfig}},
		{name: "entries", steps: entries},
		{name: "audited", steps: with(seedStep{WriteTo: "home/.symvault/audit-hermes.log", Text: auditLog})},
		{name: "recipients", steps: with(argv("recipients", "add", ageKey, "--reencrypt"))},
		{name: "shared", steps: with(seedStep{WriteTo: "home/vault/mcp-shares.json", Text: sharesJSON})},
		{name: "devices", steps: with(argv("recipients", "add", ageKey), seedStep{WriteTo: "home/vault/.symvault/devices.json", Text: devicesJSON})},
	}
}

func allResiduals() []residual {
	return []residual{
		{Path: "update apply", Reason: "the update apply flow downloads a release from the update server and replaces the running executable; a dev build never reaches that branch", Partial: "update-apply: the dev-build 'already up to date' branch in every accepted mode"},
		{Path: "update check", Reason: "a real check queries the release API over the network; only the dev-build branch ('not checkable') is offline", Partial: "update-check: the dev-build branch in every accepted mode"},
		{Path: "update info", Reason: "install-method detection reads the running executable's location, not a network", Partial: "update-info: direct-download install of a non-release binary in every accepted mode"},
		{Path: "intake watch", Reason: "the always-on watcher polls forever and needs a signal to stop; only the --once single scan and the missing-directory refusal are deterministic", Partial: "intake-watch-once and intake-watch-missing-dir in the accepted modes"},
		{Path: "approval list", Reason: "needs a running `symvault serve` approval queue (TCP peer)", Partial: "approval-list-offline: the 'could not find the running server' refusal in every accepted mode; the live queue is byte-compared by approval_queue_differential"},
		{Path: "approval decide", Reason: "needs a running `symvault serve` approval queue (TCP peer)", Partial: "approval-decide-offline: the missing --approve/--deny refusal and the offline-server refusal; the live decision is byte-compared by approval_queue_differential"},
		{Path: "device approval-pair", Reason: "needs a running `symvault serve` and an interactive pairing peer", Partial: "approval-pair-offline: the 'could not find the running server's port' refusal; the live pairing is byte-compared by approval_pair_differential"},
		{Path: "device accept", Reason: "accepting needs the response artifact of a joining device (a second live vault)", Partial: "device-accept-missing: the 'no join request found' refusal"},
		{Path: "device join", Reason: "joining clones a git remote or consumes a pairing file produced by another device", Partial: "device-join-initialized: the 'vault already initialized' refusal; device-join-missing-file: the unreadable pairing file refusal"},
		{Path: "remote init", Reason: "the pinned Go oracle panics (nil pointer dereference in cmd.enableAutoPush, goroutine trace with host paths) when the vault has no sync config, so there is no stable Go byte stream to match; initializing a remote also needs an SSH peer", Partial: "remote-init-usage: the usage refusal before the panicking branch"},
	}
}

func allCaseSpecs() []caseSpec {
	var specs []caseSpec
	add := func(spec caseSpec) { specs = append(specs, spec) }
	flags := func(args ...string) []string { return args }

	// --- vault reads ---------------------------------------------------------
	add(caseSpec{id: "list", path: "list", desc: "list three entries", seed: "entries", argv: flags("list")})
	add(caseSpec{id: "list-empty", path: "list", desc: "list an empty vault", seed: "empty", argv: flags("list")})
	add(caseSpec{id: "get", path: "get", desc: "get one entry (values masked)", seed: "entries", argv: flags("get", "work/example")})
	add(caseSpec{id: "get-print", path: "get", desc: "get one entry with --print", seed: "entries", argv: flags("get", "work/example", "--print")})
	add(caseSpec{id: "get-field-print", path: "get", desc: "get one field with --print (the audit record names the field)", seed: "entries", argv: flags("get", "work/example.username", "--print")})
	add(caseSpec{id: "get-minimal", path: "get", desc: "get an entry with only a password", seed: "entries", argv: flags("get", "a/first", "--print")})
	add(caseSpec{id: "get-missing", path: "get", desc: "get a missing entry", seed: "entries", argv: flags("get", "nope/missing")})
	// `get <query>` falls back to the `find` substring search (paths first, then
	// decrypted fields) when no entry has exactly that path: one hit is shown as
	// if its path had been given, several hits are listed on stderr and refused.
	for _, search := range []struct{ id, query, desc string }{
		{"path-one", "first", "a query that is a substring of exactly one path"},
		// No upper-case spelling of a whole path: on a case-insensitive file system
		// (macOS) Go reads the entry directly, on Linux it searches.
		{"field-case", "ALICE", "an upper-case query (the search is case-insensitive)"},
		{"multi-case", "WORK", "an upper-case query that is a substring of two paths"},
		{"field-one", "alice", "a query that matches one entry only by a field value"},
		{"field-url", "example.test", "a query inside the url field of one entry"},
		{"field-comma", "a,b", "a query that matches one entry only by its notes field"},
		{"multi-path", "work", "a query that is a substring of two paths"},
		{"multi-dash", "-", "the lone - argument (matches field values of every entry)"},
		{"multi-mixed", "t", "path matches (a/first, work/two) listed before the field match (work/example)"},
		{"none", "zzz-no-match", "a query that matches nothing"},
		{"dotted-none", "work/example.pass", "path.field whose field does not exist and that matches nothing"},
		{"trailing-dot", "a/first.", "an exact path with an empty field after the dot (the whole entry)"},
		{"empty", "", "an empty query"},
		{"parent", "../x", "a path with a .. segment"},
	} {
		add(caseSpec{id: "get-search-" + search.id, path: "get", desc: "get with " + search.desc, seed: "entries", argv: flags("get", search.query)})
	}
	add(caseSpec{id: "get-search-field-print", path: "get", desc: "get --print of a single field match (the audit record names the resolved path)", seed: "entries", argv: flags("get", "alice", "--print")})
	add(caseSpec{id: "get-search-multi-print", path: "get", desc: "get --print of an ambiguous query (no audit record)", seed: "entries", argv: flags("get", "work", "--print")})
	add(caseSpec{id: "get-search-length", path: "get", desc: "get --length of a query that is not an exact path.field (refused before any search)", seed: "entries", argv: flags("get", "work", "--length")})
	add(caseSpec{id: "get-search-length-none", path: "get", desc: "get --digest of a query that matches nothing", seed: "entries", argv: flags("get", "zzz-no-match", "--digest")})
	add(caseSpec{id: "find", path: "find", desc: "find by username", seed: "entries", argv: flags("find", "alice")})
	add(caseSpec{id: "find-none", path: "find", desc: "find without a match", seed: "entries", argv: flags("find", "zzz-no-match")})
	add(caseSpec{id: "find-url", path: "find", desc: "find by url", seed: "entries", argv: flags("find", "--url", "example.test")})
	add(caseSpec{id: "export", path: "export", desc: "export to stdout as json", seed: "entries", argv: flags("export", "--format", "json", "--yes")})
	add(caseSpec{id: "export-csv", path: "export", desc: "export to stdout as csv", seed: "entries", argv: flags("export", "--format", "csv", "--yes")})

	// --- generation ----------------------------------------------------------
	add(caseSpec{id: "generate", path: "generate", desc: "generated password", seed: "empty", argv: flags("generate"), rules: []string{"gen-pw:20"}})
	add(caseSpec{id: "generate-length", path: "generate", desc: "generated password of length 12", seed: "empty", argv: flags("generate", "--length", "12"), rules: []string{"gen-pw:12"}})
	add(caseSpec{id: "generate-manpages", path: "generate manpages", desc: "generate manpages into a directory", seed: "empty", argv: flags("generate", "manpages", "$ROOT/work/man"), rules: []string{"man-date"}})
	add(caseSpec{id: "version", path: "version", desc: "version", seed: "empty", argv: flags("version")})

	// --- writes --------------------------------------------------------------
	add(caseSpec{id: "delete-yes", path: "delete", desc: "delete with --yes", seed: "entries", argv: flags("delete", "a/first", "--yes"), post: [][]string{{"list", "--json"}}})
	add(caseSpec{id: "delete-confirm", path: "delete", desc: "delete confirmed on stdin", seed: "entries", argv: flags("delete", "a/first"), stdin: "y\n", post: [][]string{{"list", "--json"}}})
	add(caseSpec{id: "delete-decline", path: "delete", desc: "delete declined on stdin", seed: "entries", argv: flags("delete", "a/first"), stdin: "n\n", post: [][]string{{"list", "--json"}}})
	add(caseSpec{id: "delete-missing", path: "delete", desc: "delete a missing entry", seed: "entries", argv: flags("delete", "nope/missing", "--yes")})

	// --- recipients ----------------------------------------------------------
	add(caseSpec{id: "recipients-list-empty", path: "recipients list", desc: "no recipients", seed: "entries", argv: flags("recipients", "list")})
	add(caseSpec{id: "recipients-list", path: "recipients list", desc: "one recipient", seed: "recipients", argv: flags("recipients", "list")})
	add(caseSpec{id: "recipients-add", path: "recipients add", desc: "add a recipient", seed: "entries", argv: flags("recipients", "add", ageKey), post: [][]string{{"recipients", "list", "--json"}}})
	add(caseSpec{id: "recipients-add-invalid", path: "recipients add", desc: "add an invalid recipient", seed: "entries", argv: flags("recipients", "add", "not-a-key")})
	add(caseSpec{id: "recipients-remove", path: "recipients remove", desc: "remove a recipient", seed: "recipients", argv: flags("recipients", "remove", ageKey, "--yes"), post: [][]string{{"recipients", "list", "--json"}}})
	add(caseSpec{id: "recipients-remove-missing", path: "recipients remove", desc: "remove an unknown recipient", seed: "entries", argv: flags("recipients", "remove", ageKey, "--yes")})

	// --- share ---------------------------------------------------------------
	add(caseSpec{id: "share-list-empty", path: "share list", desc: "no grants", seed: "entries", argv: flags("share", "list")})
	add(caseSpec{id: "share-list", path: "share list", desc: "one approved grant", seed: "shared", argv: flags("share", "list")})
	add(caseSpec{id: "share-revoke", path: "share revoke", desc: "revoke a grant", seed: "shared", argv: flags("share", "revoke", "grant-a"), rules: []string{"now-ts"}, post: [][]string{{"share", "list", "--json"}}})
	add(caseSpec{id: "share-revoke-missing", path: "share revoke", desc: "revoke an unknown grant", seed: "shared", argv: flags("share", "revoke", "grant-zzz")})

	// --- config --------------------------------------------------------------
	add(caseSpec{id: "config-get", path: "config get", desc: "get one key", seed: "entries", argv: flags("config", "get", "vault.authMethod")})
	add(caseSpec{id: "config-get-top", path: "config get", desc: "get a top-level key", seed: "entries", argv: flags("config", "get", "defaultAgent")})
	add(caseSpec{id: "config-get-unknown", path: "config get", desc: "get an unknown key", seed: "entries", argv: flags("config", "get", "no.such.key")})
	add(caseSpec{id: "config-list", path: "config list", desc: "list the global config", seed: "entries", argv: flags("config", "list")})
	add(caseSpec{id: "config-set", path: "config set", desc: "set a key", seed: "entries", argv: flags("config", "set", "sessionTimeout", "20m"), post: [][]string{{"config", "get", "sessionTimeout"}}})
	add(caseSpec{id: "config-set-invalid", path: "config set", desc: "set an invalid value", seed: "entries", argv: flags("config", "set", "sessionTimeout", "not-a-duration")})
	// yaml.v3 decodes into the typed config: a Duration field takes only a string
	// time.ParseDuration accepts, every other YAML type is a decode error.
	for _, bad := range []struct{ id, key, value, desc string }{
		{"int", "sessionTimeout", "12", "an int for a Duration key"},
		{"zero", "sessionTimeout", "0", "the int 0 for a Duration key"},
		{"float", "sessionTimeout", "1.5", "a float for a Duration key"},
		{"bool", "sessionTimeout", "true", "a bool for a Duration key"},
		{"seq", "sessionTimeout", "[1]", "a sequence for a Duration key"},
		{"map", "sessionTimeout", "{a: 1}", "a mapping for a Duration key"},
		{"long", "sessionTimeout", "abcdefghijkl", "a long string for a Duration key (cut to seven bytes)"},
		{"multibyte", "sessionTimeout", "ééééééééééé", "a long multibyte string for a Duration key (cut inside a character)"},
		{"max-lifetime", "sessionMaxLifetime", "5", "an int for the other root Duration key"},
		{"nested", "mcp.read_timeout", "30", "an int for a nested Duration key"},
		{"profile", "agents.cli.approvalTimeout", "30", "an int for a Duration key of an agent profile"},
		{"bool-key", "useTouchID", "12", "an int for a bool key"},
		{"bool-word", "git.auto_push", "sure", "a non-boolean word for a bool key"},
		{"int-key", "mcp.port", "abc", "a string for an int key"},
		{"seq-key", "mcp.trusted_proxy_ips", "x", "a scalar for a sequence key"},
	} {
		add(caseSpec{id: "config-set-" + bad.id, path: "config set", desc: "set " + bad.desc, seed: "entries", argv: flags("config", "set", bad.key, bad.value)})
	}
	add(caseSpec{id: "config-set-yes-bool", path: "config set", desc: "set a YAML 1.1 boolean word (accepted for a bool key)", seed: "entries", argv: flags("config", "set", "git.auto_push", "yes"), post: [][]string{{"config", "get", "git.auto_push"}}})
	// yaml.v3 resolves these plain scalars to ints and writes the decimal value
	// (ADR 0034 item 4): a leading-zero octal, a 0b binary and underscore
	// separators. The post `config get` shows the stored number.
	for _, v := range []struct{ id, value, desc string }{
		{"octal", "010", "a leading-zero octal (stored as 8)"},
		{"octal-17", "017", "a second leading-zero octal (stored as 15)"},
		{"binary", "0b11", "a 0b binary (stored as 3)"},
		{"binary-5", "0b101", "a longer 0b binary (stored as 5)"},
		{"underscore", "1_000", "underscore digit separators (stored as 1000)"},
	} {
		add(caseSpec{id: "config-set-int-" + v.id, path: "config set", desc: "set " + v.desc + " for an int key", seed: "entries", argv: flags("config", "set", "mcp.port", v.value), post: [][]string{{"config", "get", "mcp.port"}}})
	}
	// The reload after `config set` decodes the whole file, so the value being set
	// is irrelevant: the file already on disk carries the offending node. yaml.v3
	// follows aliases (the error names the anchor's line), merge keys and
	// explicit tags, and a time.Time field takes a mapping or any RFC 3339 text.
	text := []string{"text"}
	for _, pre := range []struct{ id, config, desc string }{
		{"alias-scalar", "a: &x 12\nsessionTimeout: *x\n", "an aliased int for a Duration key"},
		{"alias-collection", "a: &a\n  p: 1\nsessionTimeout: *a\n", "an aliased mapping for a Duration key (the anchor's line)"},
		{"anchored-collection", "sessionTimeout: &a\n  p: 1\n", "an anchored mapping that sits on the next line"},
		{"alias-string-tag", "sessionTimeout: &t !!str 12\nsessionMaxLifetime: *t\n", "one anchored !!str 12 for two Duration keys"},
		{"alias-null", "n: &n ~\nmcp:\n  port: *n\n  read_timeout: *n\n", "an aliased null for int and Duration keys (zero value, no error)"},
		{"merge-int", "b: &b\n  port: abc\nmcp:\n  <<: *b\n", "a merged mapping holding a string for an int key"},
		{"merge-flow", "b: &b {port: abc}\nmcp: {<<: *b}\n", "a merge key in a flow mapping"},
		{"merge-own-key-wins", "b: &b\n  port: abc\nmcp:\n  port: 3\n  <<: *b\n", "the mapping's own key hides the merged one"},
		{"merge-sequence", "m: &m {port: abc}\nmcp:\n  <<: [*m, {port: x}]\n", "a sequence of mappings to merge"},
		{"merge-sequence-order", "p: &p {approvalTimeout: 5}\nq: &q {approvalTimeout: 6}\nagents:\n  a:\n    <<: [*p, *q]\n", "the first merged mapping wins"},
		{"merge-profiles", "p: &p\n  approvalTimeout: 5\nagents:\n  a:\n    <<: *p\n  b:\n    <<: *p\n    approvalTimeout: 7s\n", "a merged agent profile, overridden in one of two"},
		{"merge-scalar", "mcp:\n  <<: 5\n", "a merge key whose value is a scalar"},
		{"merge-sequence-scalar", "p: &p {port: 1}\nmcp:\n  <<: [*p, 5]\n", "a merge sequence holding a scalar"},
		{"merge-alias-sequence", "p: &p [1]\nmcp:\n  <<: *p\n", "a merge key aliasing a sequence"},
		{"tag-int", "sessionTimeout: !!int 12\n", "an explicitly tagged int for a Duration key"},
		{"tag-str-int", "sessionTimeout: !!str 12\n", "an explicitly tagged !!str 12 for a Duration key"},
		{"tag-str-ok", "sessionTimeout: !!str 5m\n", "an explicitly tagged !!str duration (accepted)"},
		{"tag-int-text", "sessionTimeout: !!int abc\n", "text its !!int tag cannot represent (aborts the decode)"},
		{"tag-int-float", "mcp:\n  port: !!int 1.5\n", "a float its !!int tag cannot represent"},
		{"tag-null-text", "sessionTimeout: !!null foo\n", "text its !!null tag cannot represent"},
		{"tag-binary", "sessionTimeout: !!binary MTI=\n", "a !!binary scalar for a Duration key"},
		{"tag-seq-on-map", "sessionTimeout: !!map [1]\n", "a sequence tagged as a mapping"},
		{"duplicate-key", "vaultDir: a\nvaultDir: b\n", "a key defined twice"},
		{"time-int", "vault:\n  last_rotated: 12\n", "an int for the time.Time key"},
		{"time-date-text", "vault:\n  last_rotated: \"2026-10-31\"\n", "a quoted date for the time.Time key"},
		{"time-plain-date", "vault:\n  last_rotated: 2026-10-31\n", "a plain date for the time.Time key (a timestamp, accepted)"},
		{"time-zone-hour", "vault:\n  last_rotated: \"2026-10-31T10:00:00+25:00\"\n", "an out-of-range zone hour"},
		{"time-month", "vault:\n  last_rotated: \"2026-13-01T00:00:00Z\"\n", "an out-of-range month"},
		{"time-day", "vault:\n  last_rotated: \"2026-02-30T00:00:00Z\"\n", "a day the month does not have"},
		{"time-extra", "vault:\n  last_rotated: \"2026-10-31T10:00:00Zjunk\"\n", "text after the zone"},
		{"time-no-zone", "vault:\n  last_rotated: \"2026-10-31T10:00:00\"\n", "a time without a zone"},
		{"time-short-hour", "vault:\n  last_rotated: \"2026-10-31T1:00:00Z\"\n", "a one-digit hour (Go accepts it)"},
		{"time-fraction", "vault:\n  last_rotated: \"2026-10-31T10:00:00,5+02:00\"\n", "a comma fraction (Go accepts it)"},
		{"time-multibyte", "vault:\n  last_rotated: \"é\"\n", "a non-ASCII value (quoted as \\\\x bytes)"},
		{"time-mapping", "vault:\n  last_rotated: {a: 1}\n", "a mapping for the time.Time key (accepted, every key ignored)"},
		{"time-empty-mapping", "vault:\n  last_rotated: {}\n", "an empty mapping for the time.Time key (accepted)"},
		{"time-sequence", "vault:\n  last_rotated: [1]\n", "a sequence for the time.Time key"},
		{"time-tag-str", "vault:\n  last_rotated: !!str 2026-10-31\n", "an explicit !!str date for the time.Time key"},
	} {
		add(caseSpec{id: "config-set-file-" + pre.id, path: "config set", desc: "set a key in a file with " + pre.desc, seed: "entries", modes: text, argv: flags("config", "set", "vaultDir", "/y"),
			files: []workFile{{Name: "../home/.symvault/config.yaml", Text: pre.config}}})
	}
	// A config file that cannot be read: Go names the failed syscall and repeats
	// the cause (text mode only; the wording does not depend on the mode flags).
	add(caseSpec{id: "config-get-missing-file", path: "config get", desc: "get from a config file that does not exist", seed: "entries", modes: text, argv: flags("config", "get", "x", "--file", "$ROOT/work/missing.yaml")})
	add(caseSpec{id: "config-list-missing-file", path: "config list", desc: "list a config file that does not exist", seed: "entries", modes: text, argv: flags("config", "list", "--file", "$ROOT/work/missing.yaml")})
	add(caseSpec{id: "config-set-missing-file", path: "config set", desc: "set in a config file that does not exist", seed: "entries", modes: text, argv: flags("config", "set", "x", "1", "--file", "$ROOT/work/missing.yaml")})
	add(caseSpec{id: "config-get-unreadable-file", path: "config get", desc: "get from a config file without read permission", seed: "entries", modes: text, argv: flags("config", "get", "x", "--file", "$ROOT/work/locked.yaml"),
		files: []workFile{{Name: "locked.yaml", Text: "x: 1\n", Mode: "000"}}})
	add(caseSpec{id: "config-get-directory-file", path: "config get", desc: "get from a config path that is a directory", seed: "entries", modes: text, argv: flags("config", "get", "x", "--file", "$ROOT/work/cfgdir"),
		files: []workFile{{Name: "cfgdir", Dir: true}}})
	add(caseSpec{id: "config-list-directory-file", path: "config list", desc: "list a config path that is a directory", seed: "entries", modes: text, argv: flags("config", "list", "--file", "$ROOT/work/cfgdir"),
		files: []workFile{{Name: "cfgdir", Dir: true}}})
	// Opening fails with other errnos too; Go prints each as `open <path>: <cause>`.
	plain := workFile{Name: "plain.txt", Text: "x: 1\n"}
	loops := []workFile{{Name: "loop-a", Link: "$ROOT/work/loop-b"}, {Name: "loop-b", Link: "$ROOT/work/loop-a"}}
	tooLong := "$ROOT/work/" + strings.Repeat("x", 300)
	for _, bad := range []struct {
		id, desc, file string
		files          []workFile
	}{
		{"notdir", "below a regular file", "$ROOT/work/plain.txt/sub.yaml", []workFile{plain}},
		{"toolong", "with a name longer than NAME_MAX", tooLong, nil},
		{"loop", "through a symbolic link loop", "$ROOT/work/loop-a", loops},
	} {
		add(caseSpec{id: "config-get-" + bad.id + "-file", path: "config get", desc: "get from a config path " + bad.desc, seed: "entries", modes: text, argv: flags("config", "get", "x", "--file", bad.file), files: bad.files})
		add(caseSpec{id: "config-list-" + bad.id + "-file", path: "config list", desc: "list a config path " + bad.desc, seed: "entries", modes: text, argv: flags("config", "list", "--file", bad.file), files: bad.files})
		add(caseSpec{id: "config-set-" + bad.id + "-file", path: "config set", desc: "set in a config path " + bad.desc, seed: "entries", modes: text, argv: flags("config", "set", "x", "1", "--file", bad.file), files: bad.files})
	}
	add(caseSpec{id: "config-validate", path: "config validate", desc: "validate a valid config", seed: "entries", argv: flags("config", "validate")})
	add(caseSpec{id: "config-validate-invalid", path: "config validate", desc: "validate a broken config", seed: "entries", argv: flags("config", "validate"),
		files: []workFile{{Name: "../home/.symvault/config.yaml", Text: "vault: [unterminated\n"}}})

	// --- auth ----------------------------------------------------------------
	add(caseSpec{id: "auth-status", path: "auth status", desc: "auth status", seed: "entries", argv: flags("auth", "status")})
	add(caseSpec{id: "auth-set", path: "auth set", desc: "set the auth method to passphrase", seed: "entries", argv: flags("auth", "set", "passphrase")})

	// --- audit ---------------------------------------------------------------
	add(caseSpec{id: "audit", path: "audit", desc: "audit log of one agent", seed: "audited", argv: flags("audit", "--agent", "hermes")})
	add(caseSpec{id: "audit-empty", path: "audit", desc: "no audit entries", seed: "entries", argv: flags("audit")})
	add(caseSpec{id: "audit-failed", path: "audit", desc: "failed entries only", seed: "audited", argv: flags("audit", "--agent", "hermes", "--failed")})
	add(caseSpec{id: "audit-export", path: "audit export", desc: "export the audit log", seed: "audited", argv: flags("audit", "export", "--agent", "hermes")})
	add(caseSpec{id: "audit-export-empty", path: "audit export", desc: "export an empty audit log", seed: "entries", argv: flags("audit", "export")})

	// --- doctor --------------------------------------------------------------
	add(caseSpec{id: "doctor", path: "doctor", desc: "doctor on a settled vault", seed: "entries", argv: flags("doctor", "--no-network"), opaque: []string{"home/vault/mcp-tokens.json"}})

	// --- agent ---------------------------------------------------------------
	add(caseSpec{id: "agent-list", path: "agent list", desc: "agents of the default config", seed: "entries", argv: flags("agent", "list")})
	add(caseSpec{id: "agent-install-missing", path: "agent install", desc: "install an agent that is not detected", seed: "entries", argv: flags("agent", "install", "hermes")})
	add(caseSpec{id: "agent-install-dry-run", path: "agent install", desc: "dry-run install of a detected agent", seed: "entries", argv: flags("agent", "install", "hermes", "--dry-run"),
		env:   map[string]string{"PATH": "$ROOT/work/bin:/usr/bin:/bin"},
		files: []workFile{{Name: "bin/hermes", Text: "#!/bin/sh\nexit 0\n", Mode: "755"}}})
	add(caseSpec{id: "agent-profile-show", path: "agent profile show", desc: "show a profile", seed: "entries", argv: flags("agent", "profile", "show", "hermes")})
	add(caseSpec{id: "agent-profile-show-missing", path: "agent profile show", desc: "show an unknown profile", seed: "entries", argv: flags("agent", "profile", "show", "nope")})
	add(caseSpec{id: "agent-profile-export", path: "agent profile export", desc: "export a profile to stdout", seed: "entries", argv: flags("agent", "profile", "export", "hermes")})
	add(caseSpec{id: "agent-profile-export-file", path: "agent profile export", desc: "export a profile to a file", seed: "entries", argv: flags("agent", "profile", "export", "hermes", "-o", "hermes.yaml"), modes: []string{"text", "quiet"}})
	// os.Create fails with `create output file: open <path>: <cause>`.
	for _, bad := range []struct {
		id, desc, out string
		files         []workFile
	}{
		{"directory", "a directory", "$ROOT/work/outdir", []workFile{{Name: "outdir", Dir: true}}},
		{"directory-slash", "a directory with a trailing slash", "$ROOT/work/outdir/", []workFile{{Name: "outdir", Dir: true}}},
		{"missing-dir", "a file below a missing directory", "$ROOT/work/nodir/out.yaml", nil},
		{"notdir", "a file below a regular file", "$ROOT/work/plain.txt/out.yaml", []workFile{plain}},
		{"readonly", "a read-only file", "$ROOT/work/ro.yaml", []workFile{{Name: "ro.yaml", Text: "old\n", Mode: "444"}}},
		{"toolong", "a name longer than NAME_MAX", tooLong, nil},
		{"loop", "a symbolic link loop", "$ROOT/work/loop-a", loops},
	} {
		add(caseSpec{id: "agent-profile-export-" + bad.id, path: "agent profile export", desc: "export a profile to " + bad.desc, seed: "entries", modes: text, argv: flags("agent", "profile", "export", "hermes", "-o", bad.out), files: bad.files})
	}
	add(caseSpec{id: "agent-skill-export", path: "agent skill export", desc: "export a skill archive", seed: "entries", argv: flags("agent", "skill", "export", "hermes"), archives: []string{"work/"}})
	add(caseSpec{id: "agent-whoami", path: "agent whoami", desc: "whoami with an agent context", seed: "entries", argv: flags("agent", "whoami"), env: map[string]string{"SYMVAULT_AGENT": "hermes"}})
	add(caseSpec{id: "agent-whoami-unset", path: "agent whoami", desc: "whoami without an agent context", seed: "entries", argv: flags("agent", "whoami")})

	// --- approval (needs a running server) -----------------------------------
	add(caseSpec{id: "approval-list-offline", path: "approval list", desc: "approval list with no running server", seed: "entries", argv: flags("approval", "list")})
	add(caseSpec{id: "approval-decide-flagless", path: "approval decide", desc: "decide without --approve/--deny", seed: "entries", argv: flags("approval", "decide", "req-1")})
	add(caseSpec{id: "approval-decide-offline", path: "approval decide", desc: "decide with no running server", seed: "entries", argv: flags("approval", "decide", "req-1", "--approve")})

	// --- device --------------------------------------------------------------
	add(caseSpec{id: "device-list-empty", path: "device list", desc: "no devices", seed: "entries", argv: flags("device", "list")})
	add(caseSpec{id: "device-list", path: "device list", desc: "two registered devices", seed: "devices", argv: flags("device", "list")})
	add(caseSpec{id: "device-add-usage", path: "device add", desc: "add without --pair", seed: "entries", argv: flags("device", "add")})
	add(caseSpec{id: "device-approval-list", path: "device approval-list", desc: "no approval devices", seed: "entries", argv: flags("device", "approval-list")})
	add(caseSpec{id: "approval-pair-offline", path: "device approval-pair", desc: "approval pairing with no running server", seed: "entries", argv: flags("device", "approval-pair")})
	add(caseSpec{id: "device-approval-revoke-missing", path: "device approval-revoke", desc: "revoke an unknown approval device", seed: "entries", argv: flags("device", "approval-revoke", "nope")})
	add(caseSpec{id: "device-revoke", path: "device revoke", desc: "revoke a registered device", seed: "devices", argv: flags("device", "revoke", "phone", "--yes"), post: [][]string{{"device", "list", "--json"}}})
	add(caseSpec{id: "device-revoke-missing", path: "device revoke", desc: "revoke an unknown device", seed: "entries", argv: flags("device", "revoke", "nope", "--yes")})
	add(caseSpec{id: "device-pair", path: "device pair", desc: "create a pairing invitation", seed: "entries", argv: flags("device", "pair"), rules: []string{"pair-token", "now-ts"}, opaque: []string{"home/vault/.symvault/pairing/"}})
	add(caseSpec{id: "device-accept-missing", path: "device accept", desc: "accept without a join request", seed: "entries", argv: flags("device", "accept", "TOKEN123")})
	add(caseSpec{id: "device-join-initialized", path: "device join", desc: "join into an already initialized vault", seed: "entries", argv: flags("device", "join", "git@example.invalid:x/y.git", "TOKEN123")})
	add(caseSpec{id: "device-join-missing-file", path: "device join", desc: "join with an unreadable pairing file", seed: "entries", argv: flags("device", "join", "--pairing-file", "$ROOT/work/none.json", "TOKEN123")})

	// --- intake --------------------------------------------------------------
	add(caseSpec{id: "intake-missing", path: "intake", desc: "intake of a missing file", seed: "entries", argv: flags("intake", "nope.txt"), rules: []string{"now-ts"}})
	add(caseSpec{id: "intake-dry-run", path: "intake", desc: "dry-run intake of a text file", seed: "entries", argv: flags("intake", "note.txt", "--dry-run"), rules: []string{"now-ts"},
		files: []workFile{{Name: "note.txt", Text: "token: abc123\n"}}})
	add(caseSpec{id: "intake-watch-missing-dir", path: "intake watch", desc: "watch a missing directory", seed: "entries", argv: flags("intake", "watch", "nope-dir")})
	add(caseSpec{id: "intake-watch-once", path: "intake watch", desc: "single scan of an empty directory", seed: "entries", argv: flags("intake", "watch", "--once", "inbox"),
		files: []workFile{{Name: "inbox", Dir: true}}})

	// --- remote --------------------------------------------------------------
	add(caseSpec{id: "remote-status", path: "remote status", desc: "no remote configured", seed: "entries", argv: flags("remote", "status")})
	add(caseSpec{id: "remote-init-usage", path: "remote init", desc: "remote init without a target", seed: "entries", argv: flags("remote", "init")})

	// --- template ------------------------------------------------------------
	add(caseSpec{id: "template-generate-dry-run", path: "template generate", desc: "env template of a prefix, masked", seed: "entries", argv: flags("template", "generate", "--type", "env", "--prefix", "work/", "--dry-run")})
	add(caseSpec{id: "template-generate-ref", path: "template generate", desc: "env template of an explicit reference", seed: "entries", argv: flags("template", "generate", "--type", "env", "DB_PASS=work/example.password")})
	add(caseSpec{id: "template-generate-missing-type", path: "template generate", desc: "template without --type", seed: "entries", argv: flags("template", "generate")})

	// --- update (dev build) --------------------------------------------------
	add(caseSpec{id: "update-apply", path: "update apply", desc: "update apply on a dev build", seed: "empty", argv: flags("update", "apply")})
	add(caseSpec{id: "update-check", path: "update check", desc: "update check on a dev build", seed: "empty", argv: flags("update", "check")})
	add(caseSpec{id: "update-info", path: "update info", desc: "update info of the running binary", seed: "empty", argv: flags("update", "info")})
	return specs
}
