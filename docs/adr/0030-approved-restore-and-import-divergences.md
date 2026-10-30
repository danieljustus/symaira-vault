# ADR 0030: Approved restore and import divergences from the Go oracle

Status: accepted by the owner, 2026-10-30. Affects contract rows IO-001 and
IO-002. Before this ADR these were recorded as unapproved divergences.

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

## Rationale

Each item makes Rust stricter or safer than Go without changing what a valid
backup or import produces. Matching Go here would mean reintroducing data loss
on interrupted restores, unbounded resource use, or a hand-written
decompressor for an error message.

## Not covered

IO-002 (4), the Windows `SafeMkdirAll` variant, left the supported scope with
#1550/#1551. Any other divergence still needs its own decision.
