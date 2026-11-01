# ADR 0030: Approved restore and import divergences from the Go oracle

Status: accepted by the owner, 2026-10-30 (items 1-3) and 2026-11-01 (item 4).
Affects contract rows IO-001 and IO-002. Before this ADR these were recorded as unapproved divergences.

## Decisions

1. **Restore writes are atomic (IO-002 (1), (3)).** Rust stages each restored
   file next to its target and renames it. A member cut short leaves no
   partial file and does not destroy an existing one, which Go does by
   truncating and writing in place. Accepted consequences: an overwritten file
   gets a new inode (owner, hard links and xattrs are not preserved), and new
   files get the clamped archive mode set explicitly instead of through the
   process umask. The existing fallback to Go's in-place rewrite stays when
   the directory is not writable but the target is an existing writable
   regular file. The corpus keeps pinning Go's partial files
   (`GO_PARTIAL_FILES`) as the documented difference.
2. **Safety limits stay (IO-002 (5), IO-001).** Restore refuses archives with
   more than `MAX_ARCHIVE_ENTRIES = 100_000` members
   (`restore failed: archive exceeds safety limits`, nothing written), and the
   generic import dispatch keeps its 100 MiB input cap. Go has neither limit.
3. **Error class and resulting tree are the parity measure where Go's text
   cannot be reproduced (IO-002 (2), (6)).** A corrupt deflate body reports
   `flate: corrupt input` without Go's decoder-internal `before offset N`, and
   invalid bytes in member names appear as U+FFFD in Rust messages where Go
   prints raw bytes. Writing an own inflater to match the offset is rejected.
4. **Entry paths that are not valid UTF-8 are refused where the file system
   would accept them (IO-001).** Accepted by the owner on 2026-11-01. Go keeps an imported path as raw bytes. Observed
   with the pinned oracle (`bf7f687b`, corpus `invalid-bytes-*`): the progress
   lines, `--skip-existing`, `--prefix`/`--quarantine` joins and every error
   text carry the raw bytes; two titles that differ only in an invalid byte are
   two paths; `Imported: <raw>` is printed only when the write succeeds. On
   macOS the write fails because APFS refuses the name (`EILSEQ`):
   `cannot write entry: cannot create entry <raw>: open <root>/entries/<raw>.age.tmp-N: illegal byte sequence`
   (`mkdir …` for an invalid directory segment). Rust reproduces this byte for
   byte by making the same `mkdir`/`open` calls, undoing the probe. On Linux
   (ext4/overlayfs, same Go binary in a `linux/arm64` container) Go instead
   succeeds: it writes `entries/<raw>.age`, but the manifest and listing keys
   are JSON-encoded, so `\xff`, `\xfe` and `x\xc3` list as `\uFFFD` and
   `x\uFFFD` (two entries for three files) and `get`/`export` then fail with
   `entry not found` for the entries just imported. Rust holds entry paths as
   text (`Store::{get,write_*,delete}` take `&str`); persisting that state
   needs byte-path variants through the store, manifest, Git and audit layers,
   an API break for a state that is unreadable afterwards. Rust therefore
   stops before writing that entry with
   `cannot write entry: cannot create entry <raw>: entry path is not valid UTF-8 and this file system accepts such a name; the native store only persists UTF-8 entry paths`
   (exit 1; entries before it stay, as in Go; nothing is created for it).
   With `pseudonymize_paths` Go hashes the raw bytes into a hex name that every
   file system accepts and succeeds; Rust refuses with a pseudonymize-specific
   message. Not divergent: dry-run, skip-existing, joins, de-duplication,
   value re-encoding and the raw-byte field limit match Go on every host.
   Recorded 2026-10-31; accepted by the owner 2026-11-01.

## Rationale

Each item makes Rust stricter or safer than Go without changing what a valid
backup or import produces. Matching Go here would mean reintroducing data loss
on interrupted restores, unbounded resource use, or a hand-written
decompressor for an error message.

## Not covered

IO-002 (4), the Windows `SafeMkdirAll` variant, left the supported scope with
#1550/#1551. Any other divergence still needs its own decision.
