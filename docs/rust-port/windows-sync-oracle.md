# Native sync observations and the frozen Windows archive exception

The seven-case `testdata/port/sync/sync.json` corpus still comes from Go
v0.22.1, commit `caadd5ef95e8f19fabd3ae3d2c04caa296f2fd44`. Its source inventory,
source digest, raw observations and archive vectors remain unchanged. Splitting
the executable observations changes the generator digest, which is refreshed
only through genuine execution of the complete original corpus on Unix.

The additional `testdata/port/sync/portable.json` fixture is genuinely generated
with `syncgen --portable --output testdata/port/sync/portable.json`, using exactly six production observations from the
same immutable source. Its native freshness check compares every observed input
and output to that committed six-case fixture. The default generator and original
seven-case corpus keep their complete contract and do not accept a reduced corpus.
The explicit portable mode excludes only the historical archive case.

`TestPinnedSyncOracleIsRepeatable` executes six independent production cases
twice on each native OS, without invoking the historical archive case:
`GIT-001-local`, `GIT-002-local-bare`, `GIT-003-conflict`, `IO-001-imports`,
`IO-002-export` and `IO-003-portable-intake`. Selection is validated before
opening a checkout; cardinality and identities must match and every input and
expected observation must repeat exactly. The complete generator still defaults
to all seven cases. A selected native run is not a substitute for full fixture
freshness verification or Rust behavioral replay.

## sync-windows-archive-exception-v1

This separately named historical exception applies only to `IO-002-archive`
on native Windows with the exact source above. The old writer sets tar member
names to `filepath.Rel` output, so its nested member is `entries\item.age`.
The old restore validator rejects that backslash. The native test runs the
actual detached writer and reader and requires the exact failure
`panic: archive contains unsafe path: entries\item.age`; build, extraction,
Git or other failures do not satisfy it. Unexpected success also fails and
requires an explicit review of the historical exception. On Unix the same test
executes and compares two complete archive observations.

This is evidence of the historical limitation, not successful Windows archive
parity. It replaces the broad Windows self-test skip while retaining the frozen
pin; it neither changes expected historical archive results nor patches the
historical source. Any future new source or exception behavior needs a new
reviewed corpus or exception version. Unix permission modes, Windows ACLs and
native watcher acceptance remain separate contracts.

## Current backup behavior

`TestCreateBackup_NormalizesTarMemberSeparators` exercises current production
`CreateBackup` and `RestoreBackup` with real nested synthetic files. It inspects
actual tar headers before restore, requires slash-separated names, checks every
file/content and verifies the restored bytes. Thus an observer-side path
normalization cannot conceal a writer that still emits backslashes. Current
production backup already uses `filepath.ToSlash`; this change restores the
missing regression rather than changing the writer.

The dedicated three-OS workflow requires both native historical tests and the
current backup regression to execute and pass, rejecting missing or skipped
required tests. Full Unix freshness and Rust replay remain in the existing port
contract. No GIT-002/003, IO-002 or IO-003 row is promoted by these observations.

The same native workflow also executes `gitio --check`, comparing all five real
production Go Git-I/O observations (offline, authentication, SSH/known_hosts,
askpass/prompt and timeout/descendant cleanup) to their retained source-bound
fixture. The CI Rust Sync/Git suites run at that same candidate SHA. This is the
native evidence gate for #1246; its GIT-002/003 status still requires completed
three-OS results and the prerequisite fixes, not merely the presence of this step.
