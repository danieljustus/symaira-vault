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

The CLI retains its deny(unsafe_code) boundary. The Windows FFI lives only in
symvault-platform::windows_attachment, with a module-local exception for three
calls. Each call borrows an owned live File; ReOpenFile returns a new owned
handle that is checked before constructing File, and the disposition pointer
has the exact Windows structure size and outlives its synchronous API call.
No raw handle or pointer escapes the safe adapter. Native x64/ARM64 tests cover
sharing, original-object deletion after replacement, and cleanup failure. Miri
cannot execute these Windows kernel APIs; real native execution is required.

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
