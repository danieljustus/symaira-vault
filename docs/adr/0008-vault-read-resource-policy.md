# ADR 0008: Complete vault read and traversal resource policy

## Status

Accepted product decision, 2026-10-03, under the maintainer's delegation of
long-term choices. Implementation and issue #1006 acceptance remain pending.
This document records the selected boundary; it does not claim a verified fix.

## Context

Main already shares `entry-read-v1` size and data-shape ceilings between Go and
Rust. Per-file limits alone do not bound simultaneous reads, retained batches,
large listing caches or search-index construction. Metadata and unknown JSON
fields must not bypass the shape limits that apply to the data section.
Several list/manifest paths must enforce traversal before collecting or sorting
an entire directory. Writers must not publish entries that their readers reject.

## Decision

Extend the host resource contract as `vault-read-resources-v2`. Preserve the
existing cryptographic format and entry ciphertext/plaintext limits. Keep the
old individual data-shape limits, then additionally preflight the entire JSON
envelope before materializing typed metadata or unknown fields.

| Boundary | Selected ceiling |
| --- | --- |
| Entry ciphertext/plaintext | Existing 24 MiB / 16 MiB |
| Data shape | Existing depth 32, 1,024 top-level and 1,024 nested fields, 1 MiB keys/string values, 1,024 items per array |
| Whole entry envelope | Depth 34, 4,096 object keys in total, 65,536 JSON values, existing 1 MiB string and 1,024 per-array item limits |
| Filesystem descendants | Existing 100,000 items; existing logical path depth 64 |
| Directory enumeration | Read bounded chunks, stopping on count/depth excess instead of collecting a directory before checking |
| Transient entry/manifest/index reads | Four admitted operations per process; 32 pending admissions, at most ten seconds of waiting |
| Payload accounting | 64 MiB reserved per admitted read; excludes runtime overhead, caller-owned return values and other services |
| Multi-entry operation | At most 256 MiB of reserved ciphertext, 256 MiB of conservative decoded-data cost, and 8 MiB of retained path bytes |
| Pseudonymized listing cache | At most 16 MiB of retained data per cache instance, with bounded cache entries and paths |
| Recovery journal | 16 MiB raw JSON and 16 MiB conservative node/string cost; 100,000 entries and 8 MiB total target/artifact path bytes, checked before typed collection |
| Search-index optimization | At most 8 MiB of serialized plaintext, with bounded collection before serialization and bounded persisted reads |

Requested search worker counts remain readable in configuration, but actual
read concurrency follows the four-operation process cap. Excessive input returns
a typed, fixed resource-limit error; overloaded admission returns resource-busy.
Neither exposes entry values. Admission is acquired before file buffers,
decryption and decoding, and released on every outcome. Batch accounting is
shared by its workers; an individual read cap cannot substitute for it.

The envelope depth allows the existing data depth plus its enclosing entry/data
objects. The whole-envelope fields and value count bound structures containing
many small objects/arrays; a byte ceiling by itself does not bound decoded-node
memory. Count duplicate raw keys before normalization. Keep valid unknown fields
below these ceilings for forward compatibility; do not silently drop an excess
field or reinterpret it into an accepted form.

## Compatibility and retained state

These are intentional security corrections from the frozen `caadd5e` behavior.
Vaults below the documented ceilings keep their keys, values, layouts and
interoperability. Over-limit data must fail explicitly, without partial writes
or misleading complete-list results. Size/shape protections apply to shared
recipient writers and ordinary writers alike.

The encrypted search index is an optimization. If building it would exceed its
budget, preserve any existing valid index and use the bounded ordinary search
path. An oversized optimization does not make an otherwise readable entry
unreadable. Avoid publishing an index or cache that is larger than its own load
boundary. Unknown root-file hashing and manifest verification should stream
bytes rather than allocating a whole large file solely to calculate a digest.

Bound retained cache data before inserting or copying it. Cache eviction affects
performance, not search results; a cache miss must still use the bounded reader.
Do not claim total process RSS is bounded by serialized-payload reservations:
allocator overhead, returned objects and independent processes remain outside
that particular accounting boundary.

## Rationale

Four readers allow useful concurrency while preventing a configured worker count
from multiplying 24 MiB ciphertext and 16 MiB plaintext buffers across scores of
workers. The pending queue tolerates ordinary bursts but bounds backlog. Existing
per-file ceilings remain generous enough for attachments and exported entries.
A 256 MiB batch budget supports many ordinary small entries while rejecting
expensive repeated maximum-size reads. Listing-path and cache budgets bound
retention without treating optimizations as authoritative vault data.

An 8 MiB index ceiling leaves room for encryption framing beneath existing
16 MiB generic root-file reads. Fallback preserves correct search when a large
vault cannot use this optimization. Streaming file digests preserve manifest
integrity without requiring file-sized allocation. Applying the same contract
in Go and Rust avoids unilateral Rust incompatibility.

## Verification before closure

Use exact/over-limit cases, whole-envelope metadata/unknown-field cases, raw
aliases/duplicates, deep and wide trees, shared-recipient writer controls, real
concurrent reads, retained-cache/index and batch accounting tests. Exercise
ordinary search fallback and unchanged valid vault reads. Generate genuine Go
observations in disposable HOME/XDG roots, distinguish the security correction
from the historical oracle, and require native supported-platform execution.
An unavailable native or relevant package check remains an acceptance gap.

## Recorded implementation choices

Retained cache and index data use conservative accounting: 256 bytes per value
or key plus up to six times string bytes for escaped copies. This is an
allocation guard, not an allocator measurement. Index token bindings reserve
their temporary dedup set and forward/reverse map entries before insertion.
The eight-MiB serialized ceiling still applies separately. Earlier rejection
of an optional optimization preserves bounded ordinary search results.

Stream Go index construction one entry at a time. A parallel queue holding
every entry's decrypted strings defeats a post-serialization ceiling. Search
and metadata listing retain their four-reader worker pools; index building
does not need to monopolize those readers. Bound raw index JSON nodes before
typed map decoding in both implementations, including unknown fields.

An unsuccessful index build preserves the previous encrypted file. After a
primary entry mutation, an old index is stale; if its incremental update
cannot fit, invalidate it so subsequent searches use ordinary reads. Retaining
a stale index as authoritative would produce false negative search results.

Read directory chunks before collection, then sort validated re-encryption
candidates to preserve the original stable transaction order. Integrity reads
stream through the same no-follow descriptor as their metadata. They count
toward the batch budget and retain the existing generic root-file ceiling;
entry ciphertexts use the shared 24-MiB ceiling rather than the generic 16-MiB
ceiling. Path replacement must not pair one file's metadata with another's hash.

Legacy string-backed backup codes must not expand beyond the existing 1,024
array-item limit. Count nonempty lines before normalization and use streaming
line iteration, including blank lines, so a string budget cannot hide a much
larger decoded list. This is an explicit security correction for oversized
legacy values, with ordinary historical recovery-code strings preserved.

Reserve the opened descriptor's declared size before allocating a ciphertext
buffer. Reads under a batch consume at most that reservation plus one byte to
detect concurrent growth; reject growth and make exhaustion sticky. At most
four admitted readers can perform that bounded excess probe. A failed budget
never admits later queued file reads. Do not refund reservations on shrinkage.
Hashing follows the same descriptor/reservation rule.

Count a second 256-MiB allowance for conservative decoded-node/string cost
before typed materialization. Ciphertext alone does not bound JSON expansion
retained by multi-entry MCP or export responses. This accounting also includes
unknown fields and raw duplicates; it is deliberately conservative and is not
a total-RSS claim. Repeated reads charge again, even if callers drop old values.

A Rust read session carries one allowance across listing and subsequent entry
reads. CLI search, metadata lists, export, template expansion and MCP lists use
this session. Go index warm-up and ordinary fallback share their calling search
operation's allowance. Resource failures abort instead of returning empty or
partial success; an index-retention failure can fall back while read budget
remains available.


Each CLI command and MCP request creates its own read session. Prefix discovery,
field/dotted-path probing, actual value reads, environment/file injection,
template generation, export and quarantine promotion share that session. A busy
or over-limit probe terminates resolution before a dotted entry fallback can
change which secret is selected. Long-lived servers do not share one allowance
across unrelated requests. Trusted injected test backends retain their existing
service contract; the physical default backend always uses the bounded session.

Metadata uses the same admitted, whole-envelope reader as normal entries.
Go TUI metadata/type caches additionally apply the fixed 16 MiB retention limit;
resource errors are displayed and terminate cache filling. Pseudonym migration
uses bounded physical-file enumeration, then one session for its read loop.
Sync reconciliation enumerates through the same bounded path and reads each
actual conflict file's metadata. This also corrects the existing comparison that
read the canonical stem for every candidate and missed the second candidate when
selecting the winner; higher version/update/path comparisons now see each file.
Conflict preservation remains lossless and shares the reconciliation allowance.

A cached incremental index update must invalidate the index and remove its old
file when an entry read fails with busy/limit. Publishing a path without its
previous searchable values would make negative index answers incorrect.

Recovery journals and manifest snapshots are admitted, descriptor-based reads
before allocation. Journal node expansion is bounded before typed entry arrays;
writer preflight bounds path strings and escaped output conservatively before
serialization. This intentionally makes very large rotation journals fail
explicitly, even when individual small entries remain readable. Digests stream
24 MiB entry artifacts through the same no-follow capability and never use the
16 MiB generic-file cap for an entry. Normal rotation/recovery shares its forward
allowance with manifest rebuilding; strict Go rebuilding streams files rather
than retaining a second copy of all candidate ciphertext.

Rollback has one fresh, fixed 256 MiB verification allowance. An exhausted
forward allowance must not disable compensation. Go recovery also retains
original backups until successful manifest publication, matching Rust. Recovery
may complete earlier per-file steps before a later resource or I/O error; its
journal and remaining originals stay available for a later recovery attempt.
This is not a cross-file atomicity claim. Backup cleanup after publication has
one separate bounded verification pass; a failure retains the journal. No loop
resets an allowance to continue past a resource failure.


The shared preflight also reserves the extra array nodes and strings introduced
by Go's legacy backup-code migration. This prevents a small newline-separated
string from escaping decoded-data accounting through post-decode normalization.
Rust reserves that same conservative cost; its existing value representation
is covered by the separate value-compatibility work in issue #1254.

The new policy corpus records actual resource outcomes, successful read counts,
and Go diagnostic field/code counts from an immutable checkout. Rust replays
the resource outcomes and read counts from the same deterministic byte recipes.
The diagnostic Go field representation is retained as observed; this corpus does
not promote the broader value-normalization migration row. Filesystem recipes
hash their kind marker and derive the complete synthetic tree/file state from
the recorded count; byte recipes hash their generated plaintext. Existing
import-review CLI cases must re-execute with identical output and side effects
before the source-bound fixture provenance advances.


Corpus processes explicitly select Go's existing `SYMVAULT_TEST_KEYRING=memory`
test backend as well as disposable HOME/XDG roots. Environment isolation alone
does not disable a native OS credential service. This keeps these resource and
CLI observations independent of credential-service availability and prevents a
fallback warning from masquerading as a resource-policy semantic difference.

## Local evidence and pending native acceptance

The immutable Go capture at `b13189220519de245d8972d7af2e2d81618f0432`
executed all 19 resource cases and re-executed all 17 import-review cases with
unchanged output and side effects. Rust replayed all 19 resource outcomes and
successful read counts. Source hashes bind all 520 tracked production Go files
and module files; generator hashes bind both capture programs. The Rust replay
checks every recipe kind and count before constructing potentially large input.

Owning Go race checks passed, including the real four-reader/32-waiter admission
case, templates and MCP command references. The old full CRUD race run reached
its ten-minute timeout in legitimate scrypt computation; the complete normal
CRUD package and the focused changed worker race test passed. This does not
claim a passing full CRUD race run. Native policy acceptance on all three
supported hosts and the final combined repository gates remain pending.

The first native Windows policy job correctly failed its named-test receipt:
MCP's separate historical `TestMain` also returned without executing tests.
Use the existing cross-language opt-in for that package as well, retaining
the required named-pass assertions. A zero package exit code is not native
command-reference coverage. Linux's actual policy job passed on `f95fae88`.

SAST findings retain their original failure status and SARIF artifact, and also
print rule, path, line and diagnostic in the CI log. This makes a red scanner
gate directly reviewable without printing source snippets or entry values.
Local installation of the pinned scanner was blocked by its uncached Google
API dependency; native CI remains the authority for that required gate.
