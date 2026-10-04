# ADR 0012: Windows materialized attachment ownership

## Status

Accepted maintainer-delegated decision, 2026-10-04. Implementation and actual
Windows x64 / Windows 11 ARM acceptance are in progress; #1145 remains open.

## Decision and rationale

Retain the original materialized file object while the authorized child runs,
but retain only FILE_READ_ATTRIBUTES access on Windows. Ordinary Windows/.NET
readers use FileShare.Read; they reject an already-open WRITE_DATA handle even
when that writer itself allows sharing. Increasing the writer's share mode
cannot fix that conflict. Acquire the minimal identity guard with ReOpenFile
before closing the creation writer, so there is never an unowned interval.

After the child and its owned process tree finish, ReOpenFile reopens that same
object with write/delete access. Overwrite only the original payload length in
bounded 8 KiB chunks and flush. SetFileInformationByHandle marks that object for
deletion before closing both handles. Cleanup never opens or unlinks the
child-controlled file pathname: a replacement file, renamed parent or junction
cannot redirect the overwrite/deletion to another file.

If secure Windows cleanup fails, report the failure. A successful child must
not conceal that failure; if the child already failed, preserve its error and
add a generic cleanup warning. No pathname-based fallback is allowed. A still
open reader may prevent the cleanup handle from opening, and filesystem ACL or
storage errors may prevent overwriting/deletion. This does not promise physical
erasure on SSD/COW storage. Unix retains its established descriptor cleanup.

## Acceptance

Mandatory Windows tests execute an ordinary read-only sharing reader, replace
the path and its parent while retaining the original object, and prove that a
retained reader produces a cleanup error without an unsafe fallback. Native
Go/Rust CLI comparisons must additionally use real .NET ReadAllBytes, verify
exact bytes and payload redaction, ordinary/error/timeout cleanup, and execute
on windows-latest and windows-11-arm. Cross-compilation or a skipped test does
not establish either native platform. The pinned Go source and every candidate
binary/source digest must accompany the native receipt.
