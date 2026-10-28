#!/usr/bin/env python3
"""Linux/x86_64 consumption capture for the one deadline compiler route.

Trace only the command we fork and its descendants. At a file-consuming syscall
entry, the tracee is stopped. Newly generated regular inputs get a kernel read
lease BEFORE their bytes are copied from the actual descriptor. Keep the lease
and descriptor until every tracee exits, including mmap users and unlinked
intermediates. A conflicting writer, unsupported lease/filesystem/ABI or lost
trace is an incomplete capture, never an after-only admission.

This is not a sandbox or a native-test runner. No privileges, installs, mounts,
compiler wrappers, build warm-up, or changes to libtest scheduling are needed.
"""
import ctypes
import hashlib
from itertools import islice
import json
import os
from pathlib import Path
import platform
import re
import signal
import stat
import struct
import sys


def require(condition, message):
    if not condition:
        raise ValueError(message)


def identity(fd):
    st = os.fstat(fd)
    require(stat.S_ISREG(st.st_mode), 'consumed input is not a regular file')
    # Unlink/rename changes ctime/nlink, not the held file's content identity.
    return {'device':st.st_dev, 'inode':st.st_ino, 'size':st.st_size,
            'mtime_ns':st.st_mtime_ns, 'mode':stat.S_IMODE(st.st_mode)}


def retain_fd(fd, destination):
    """Copy the held descriptor, never reopen its possibly replaced pathname.

    The native caller holds a read lease. File-only controls exercise this
    function without a lease and do NOT create a native capture verdict.
    """
    before = identity(fd)
    require(before['size'] <= 2*1024**3, 'generated input size bound exceeded')
    size, sha = 0, hashlib.sha256()
    position = os.lseek(fd,0,os.SEEK_CUR)
    try:
        os.lseek(fd,0,os.SEEK_SET)
        with destination.open('xb') as output:
            while chunk := os.read(fd,1024**2):
                size += len(chunk)
                require(size <= before['size'], 'generated input grew during capture')
                sha.update(chunk)
                output.write(chunk)
    finally:
        os.lseek(fd,position,os.SEEK_SET)
    require(before == identity(fd) and size == before['size'], 'generated input changed during capture')
    return {**before, 'sha256':sha.hexdigest(), 'blob':destination.name}


def verify_fd(fd, row):
    require(identity(fd) == {k:row[k] for k in identity(fd)}, 'held generated input changed')
    sha, offset = hashlib.sha256(), 0
    position = os.lseek(fd,0,os.SEEK_CUR)
    try:
        os.lseek(fd,0,os.SEEK_SET)
        while chunk := os.read(fd,1024**2):
            sha.update(chunk)
            offset += len(chunk)
            require(offset <= row['size'], 'held generated input grew')
    finally:
        os.lseek(fd,position,os.SEEK_SET)
    require(offset == row['size'] and sha.hexdigest() == row['sha256'], 'held generated input bytes changed')


def verify_blob(directory, row):
    name = row['blob']
    require(Path(name).name == name and name.endswith('.input'), 'invalid captured blob name')
    path = directory/name
    require(not path.is_symlink(), 'symlink captured blob')
    with path.open('rb') as stream:
        require(os.fstat(stream.fileno()).st_size == row['size'] and
                hashlib.file_digest(stream,'sha256').hexdigest() == row['sha256'], 'captured blob changed')


def read_syscall(raw, count):
    # Linux struct ptrace_syscall_info, fixed-width UAPI, not host C longs.
    require(count >= 24 and struct.unpack_from('=I',raw,4)[0] == 0xc000003e,
            'unsupported compiler syscall ABI')
    op = raw[0]
    if op == 1:
        require(count >= 80, 'truncated syscall entry')
        return op, struct.unpack_from('=7Q',raw,24)
    require(op == 2 and count >= 33, 'unrecognized compiler syscall stop')
    return op, struct.unpack_from('=qB',raw,24)


FICLONE = 0x40049409
# Descriptor-metadata requests: terminal attributes/size, pending-byte count,
# close-on-exec flags and FIONBIO. FIONBIO's argument is an int* mode value the
# kernel reads to toggle O_NONBLOCK (fs/ioctl.c); it moves no file data, so
# there is no payload to capture and the request consumes no input bytes.
FIONBIO = 0x5421
DESCRIPTOR_METADATA_IOCTLS = frozenset((0x5401,0x5413,0x541b,FIONBIO,0x5451,0x5450))


def input_fd(number, args, pid=None):
    require(0 <= number < 512, 'unsupported compiler syscall number/ABI')
    if number == 56:  # clone: no untraced or foreign-namespace descendants.
        require(not args[0] & 0x7e820000, 'untraced/namespaced compiler child')
    # x86_64 read/pread/readv/preadv/preadv2, sendfile, splice, copy_file_range.
    if number in (0,17,19,295,327,275,326):
        return args[0]
    if number == 40:
        return args[1]
    if number == 16:  # ioctl: reflink consumes a source descriptor too.
        if args[1] == FICLONE:
            return args[2]
        # Exact allow-list; every other request, including unknown ones, fails
        # closed. None of these reads file contents through the descriptor.
        require(args[1] in DESCRIPTOR_METADATA_IOCTLS, 'unsupported compiler ioctl input')
    if number == 9:  # mmap: shared buffers survive fork without CLONE_VM.
        if args[3] & 1:
            require(not args[3] & 0x20 and not args[2] & 2 and pid is not None,
                    'shared mapping lacks a read-only file descriptor')
            # PROT_READ alone is insufficient. Linux clears VM_MAYWRITE for a
            # shared map of an O_RDONLY descriptor, preventing mprotect upgrades.
            info = Path(f'/proc/{pid}/fdinfo/{args[4]}').read_text()
            flags = re.findall(r'^flags:[ \t]+([0-7]+)$',info,re.M)
            require(len(flags) == 1 and int(flags[0],8) & 3 == 0,
                    'shared mapping descriptor is not verified O_RDONLY')
        if not args[3] & 0x20:  # not MAP_ANONYMOUS
            return args[4]
    # Async input, remote memory, namespace changes and trace manipulation cannot
    # be silently omitted. None is needed for ordinary native Rust compilation.
    # SysV shmget/shmat and remote process_madvise are outside this evidence model.
    require(number not in (29,30,101,165,161,206,209,246,272,298,304,308,310,311,323,425,426,427,440),
            'unsupported compiler input/namespace syscall: '+str(number))
    return None


def observe_rejected_fd(record, pid, values, event, active, sharers, reason):
    """Failure-only metadata, never a pinned descriptor or ownership proof."""
    row = {'class':'rejected_fd_observation', 'version':1, 'event':event,
           'pid':pid, 'fd':values[5], 'values':list(values), 'reason':reason,
           'evidence_role':'diagnostic_only', 'ownership_proven':False,
           'snapshot_consistency':'incomplete', 'errors':[], 'truncated':[]}
    # Retain the original rejection even if a signal interrupts observation.
    record['rejected_fd_observation'] = row
    base = dict(row)
    operand = f'/proc/{pid}/fd/{row["fd"]}'

    def attempt(operation, read):
        try:
            return read()
        except OSError as error:
            row['errors'].append({'operation':operation, 'errno':error.errno})
            return None

    def snapshot(label):
        raw = attempt(label+'.readlink', lambda: os.readlink(os.fsencode(operand)))
        st = attempt(label+'.stat', lambda: os.stat(operand))
        if raw is not None and len(raw) > 8192:
            row['truncated'].append(label+'.path')
        return {'path_hex':None if raw is None else raw[:8192].hex(),
                'stat':None if st is None else {
                    key:getattr(st,attr) for key,attr in (
                        ('device','st_dev'),('inode','st_ino'),('mode','st_mode'),
                        ('nlink','st_nlink'),('size','st_size'),
                        ('mtime_ns','st_mtime_ns'),('ctime_ns','st_ctime_ns'))}}

    def fields(path, patterns):
        def read():
            with Path(path).open('rb') as stream:
                return stream.read(16385)
        data = attempt(path,read)
        result = {}
        if data is None:
            return result
        if len(data) > 16384:
            row['truncated'].append(path)
            return result  # No parsing a potentially partial field as complete.
        for key,pattern in patterns:
            matches = re.findall(pattern,data,re.M)
            field = b'Tgid' if key == 'tgid' else key.encode('ascii')
            occurrences = re.findall(rb'^'+field+rb':',data,re.M)
            if len(matches) == len(occurrences) == 1:
                result[key] = matches[0].decode('ascii')
            else:
                row['errors'].append({'operation':path+':'+key, 'errno':None,
                                      'error':'missing_or_ambiguous_field'})
        return result

    row['snapshot_a'] = snapshot('a')
    row['fdinfo'] = fields(f'/proc/{pid}/fdinfo/{row["fd"]}', (
        ('flags',rb'^flags:[ \t]+([0-7]+)$'),
        ('mnt_id',rb'^mnt_id:[ \t]+([0-9]+)$'),
        ('ino',rb'^ino:[ \t]+([0-9]+)$')))
    row['task'] = fields(f'/proc/{pid}/status', (('tgid',rb'^Tgid:[ \t]+([0-9]+)$'),))
    for name,ids in (('active',active),('sharers',sharers)):
        row[name] = sorted(islice(ids,256))
        if len(ids) > 256:
            row['truncated'].append(name)
    row['snapshot_b'] = snapshot('b')
    # ponytail: equal samples cannot exclude ABA or FD-table races; a future
    # ownership design needs separate proof, never promotion of this record.
    if not row['errors'] and not row['truncated']:
        row['snapshot_consistency'] = ('equal' if row['snapshot_a'] == row['snapshot_b'] else 'changed')
    if len(json.dumps(row,indent=2).encode('ascii')) > 65536:
        record['rejected_fd_observation'] = {
            **base, 'errors':[], 'truncated':['record'], 'record_overflow':True}


SELF_MAPS = re.compile(r'/proc/([1-9][0-9]*)/maps')
# Typed runtime class self_maps_runtime, version 1: bytes copied from the reader's
# own buffer at syscall exit. They are never reopened, snapshotted, compared with
# before/after inventories, or treated as generated lease-protected inputs.
SELF_MAPS_KEYS = {'class','version','pid','tgid','path','fd','buffer','requested',
                  'entry_event','exit_event','returned','size','sha256','blob'}
CLONE_VM, CLONE_FILES, CLONE_THREAD, CLONE_VFORK = 0x100, 0x400, 0x10000, 0x4000
MAX_SELF_MAPS_READ = 8*1024**2
MAX_SELF_MAPS_TOTAL = 1024**3  # retained runtime bytes per capture; exceeding fails closed
MAX_SELF_MAPS_RECORDS = 1 << 18  # typed records per capture; exceeding fails closed


def self_maps_target(raw):
    # Exact pathname only: /proc/self, task subpaths and other proc files do not match.
    return raw if SELF_MAPS.fullmatch(raw) else None


def task_state(pid):
    # Thread-group id and task list of one stopped tracee.
    status = Path(f'/proc/{pid}/status').read_text()
    return int(re.search(r'^Tgid:\s*([0-9]+)$', status, re.M)[1]), sorted(os.listdir(f'/proc/{pid}/task'))


def self_maps_entry(number, pid, tgid, tasks, target, sharers):
    # Only the exact own read(0), by a single-task reader, with no live CLONE_VM/CLONE_FILES sharer.
    match = SELF_MAPS.fullmatch(target)
    require(match is not None, 'not a self-maps descriptor: '+target)
    require(number == 0, 'unsupported self-maps read syscall: '+str(number))
    require(int(match[1]) == tgid == pid and tasks == [str(pid)], 'foreign or multi-task self-maps read')
    require(not sharers, 'self-maps read while a CLONE_VM/CLONE_FILES sharer is live')


def tracee_bytes(pid, address, count):
    # Exactly count bytes from the stopped reader's buffer, or fail.
    require(0 <= count <= MAX_SELF_MAPS_READ, 'self-maps read bound exceeded')
    if count == 0:
        return b''
    with Path(f'/proc/{pid}/mem').open('rb',buffering=0) as memory:
        data = os.pread(memory.fileno(),count,address)
    require(len(data) == count, 'unreadable self-maps bytes')
    return data


def verify_runtime_blob(directory, row):
    name = row['blob']
    require(Path(name).name == name and name.endswith('.runtime'), 'invalid self-maps blob name')
    path = directory/'blobs'/name
    require(path.is_file() and not path.is_symlink(), 'missing or symlink self-maps blob')
    with path.open('rb') as stream:
        require(os.fstat(stream.fileno()).st_size == row['size'] and
                hashlib.file_digest(stream,'sha256').hexdigest() == row['sha256'], 'self-maps blob changed')


def verify_self_maps(directory, data, transcript):
    """Bind each typed runtime record to its own raw entry and exit events.

    transcript is this capture's syscalls.jsonl, consumed once. Records are checked
    one-to-one against the raw self_maps_entry markers, the raw syscall lines, and
    the reader's stops between entry and exit.
    """
    rows, entries = data.get('self_maps'), data.get('self_maps_entries')
    require(isinstance(rows, list) and isinstance(entries, list) and len(rows) <= MAX_SELF_MAPS_RECORDS,
            'self-maps records absent or over bound')
    for row in rows:
        require(isinstance(row, dict) and set(row) == SELF_MAPS_KEYS and row['class'] == 'self_maps_runtime'
                and row['version'] == 1, 'untyped self-maps record')
    require(len(set(entries)) == len(entries) and sorted(entries) == sorted(row['entry_event'] for row in rows),
            'self-maps entries and records are not one-to-one')
    names = [row['blob'] for row in rows]
    require(len(set(names)) == len(names), 'duplicate self-maps blob name')
    readers = {row['pid'] for row in rows}
    wanted = {row[key] for row in rows for key in ('entry_event', 'exit_event')}
    stops, syscalls, marked = {pid: set() for pid in readers}, {}, {}
    for item in transcript:
        if 'self_maps_entry' in item:
            require(item['event'] not in marked, 'self-maps raw entries are not one-to-one')
            marked[item['event']] = (item['pid'],item['self_maps_entry'])
        if item.get('pid') in stops:
            stops[item['pid']].add(item['event'])
        if 'op' in item and item['event'] in wanted:
            require(item['event'] not in syscalls, 'duplicate syscall event identity')
            syscalls[item['event']] = item
    require(sorted(marked) == sorted(entries), 'self-maps raw entries and records are not one-to-one')
    total = 0
    for row in rows:
        entry, done = syscalls.get(row['entry_event']), syscalls.get(row['exit_event'])
        require(entry is not None and done is not None and entry['op'] == 1 and done['op'] == 2
                and row['entry_event'] < row['exit_event'], 'unmatched self-maps event')
        require(entry['pid'] == done['pid'] == row['pid'] == row['tgid']
                and row['path'] == f"/proc/{row['pid']}/maps", 'self-maps event identity mismatch')
        require(marked[row['entry_event']] == (row['pid'],row['path']), 'self-maps raw marker mismatch')
        require(entry['values'][:4] == [0, row['fd'], row['buffer'], row['requested']],
                'self-maps entry is not the recorded read(0)')
        require(done['values'] == [row['returned'], 0] and 0 <= row['returned'] <= row['requested'],
                'self-maps exit mismatch')
        require(row['size'] == row['returned'] <= MAX_SELF_MAPS_READ, 'self-maps length invalid')
        between = [e for e in stops[row['pid']] if row['entry_event'] <= e <= row['exit_event']]
        require(sorted(between) == [row['entry_event'], row['exit_event']], 'intervening stop of self-maps reader')
        # Event IDs count all traced stops, not just stops of this reader.
        require(row['exit_event'] == row['entry_event'] + 1, 'intervening stop during self-maps read')
        total += row['size']
        require(total <= MAX_SELF_MAPS_TOTAL, 'self-maps byte bound exceeded')
        verify_runtime_blob(directory, row)
    return {row['path'] for row in rows}


def intervention(pending, pid, status):
    # Any stop or exit other than the pending reader's own syscall-exit stop.
    if not pending:
        return False
    return not (pid in pending and os.WIFSTOPPED(status)
                and os.WSTOPSIG(status) == signal.SIGTRAP | 0x80 and status >> 16 == 0)


def trace(command, private, output):
    require(platform.system() == 'Linux' and platform.machine() == 'x86_64',
            'consumption capture requires native Linux/x86_64')
    require(not sys.flags.optimize, 'unoptimized Python required')
    import fcntl
    require(hasattr(fcntl,'F_SETLEASE'), 'kernel read leases unavailable')
    private = private.resolve(strict=True)
    output.mkdir(mode=0o700)
    blobs = output/'blobs'
    blobs.mkdir(mode=0o700)
    generated_roots = (private/'build',private/'compiler-tmp')
    leases, consumed, active, newborn = {}, set(), set(), set()
    early_stops, pending, exec_inputs = set(), {}, {}
    sharers, clone_intent, self_pending = set(), {}, {}
    self_bytes = 0
    record = {'complete':False, 'command':command, 'command_exit':None,
              'errors':[], 'generated':[], 'observed':[], 'acceptance':False,
              'self_maps':[], 'self_maps_entries':[]}
    libc = ctypes.CDLL(None, use_errno=True)
    libc.ptrace.restype = ctypes.c_long
    libc.ptrace.argtypes = [ctypes.c_uint,ctypes.c_int,ctypes.c_void_p,ctypes.c_void_p]

    def ptrace(request, pid, addr=0, data=0):
        ctypes.set_errno(0)
        value = libc.ptrace(request,pid,addr,data)
        if value == -1 and ctypes.get_errno():
            raise OSError(ctypes.get_errno(), 'ptrace failed')
        return value

    def interrupted(signum, frame):
        raise ValueError('capture interrupted or generated input lease broken: '+str(signum))

    def capture(pid, operand, executable=False):
        """operand is /proc/TID/fd/N or a resolved pre-exec filename."""
        try:
            st = operand.stat()
        except FileNotFoundError:
            # An unbound descriptor may not later be treated as a successful
            # input. Refuse instead of guessing that the syscall will fail.
            raise ValueError('missing consumed input: '+str(operand)) from None
        if stat.S_ISFIFO(st.st_mode) or stat.S_ISSOCK(st.st_mode):
            return  # IPC inside the traced compiler tree, not filesystem bytes.
        raw = os.readlink(operand) if operand.is_symlink() else str(operand)
        path = Path(raw.removesuffix(' (deleted)'))
        require(path.is_absolute(), 'unresolved consumed file descriptor')
        if str(path) in ('/dev/null','/dev/urandom','/dev/random'):
            return
        require(stat.S_ISREG(st.st_mode), 'unsupported consumed input: '+raw)
        consumed.add(str(path))
        if not any(path.is_relative_to(p) for p in generated_roots):
            return  # Existing real before/after inventory must bind it.
        fd = os.open(operand, os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK)
        held = False
        try:
            info = identity(fd)
            require((info['device'],info['inode']) == (st.st_dev,st.st_ino), 'consumed descriptor changed')
            key = (info['device'],info['inode'])
            if key in leases:
                previous_fd, row = leases[key]
                require(fcntl.fcntl(previous_fd,fcntl.F_GETLEASE) == fcntl.F_RDLCK, 'lost input lease')
                require(info == {k:row[k] for k in info}, 'leased input changed')
            else:
                require(len(leases) < 16384, 'generated descriptor bound exceeded')
                # Existing writers/writable mappings make this fail. No privileged
                # fallback and no successful record before the lease is acquired.
                fcntl.fcntl(fd,fcntl.F_SETOWN,os.getpid())
                fcntl.fcntl(fd,fcntl.F_SETLEASE,fcntl.F_RDLCK)
                row = retain_fd(fd,blobs/(str(len(leases))+'.input'))
                require(sum(r['size'] for _,r in leases.values()) + row['size'] <= 32*1024**3,
                        'generated capture byte bound exceeded')
                leases[key] = (fd,row)
                held = True
            if executable:
                require(os.pread(fd,4,0) == b'\x7fELF', 'generated non-ELF exec unsupported')
            # One binding per path/inode, including renamed and unlinked inputs.
            binding = {'path':str(path), 'pid':pid, **row}
            if not any(r['path'] == binding['path'] and r['inode'] == binding['inode']
                       and r['device'] == binding['device'] for r in record['generated']):
                record['generated'].append(binding)
            return row
        finally:
            if not held:
                os.close(fd)

    def exec_path(pid, number, args):
        pointer = args[0] if number == 59 else args[1]
        with Path(f'/proc/{pid}/mem').open('rb',buffering=0) as memory:
            # Read at most a page fragment at a time; a short pathname may end
            # immediately before an unmapped page.
            raw = bytearray()
            while len(raw) < 4096:
                part = os.pread(memory.fileno(), min(4096-len(raw),4096-pointer%4096),pointer)
                require(part, 'unreadable exec pathname')
                raw.extend(part.split(b'\0',1)[0])
                if b'\0' in part:
                    break
                pointer += len(part)
            else:
                raise ValueError('unterminated exec pathname')
        name = os.fsdecode(bytes(raw))
        if number == 322 and not name and args[4] & 0x1000:
            return Path(f'/proc/{pid}/fd/{args[0]}')
        if Path(name).is_absolute():
            return Path(name).resolve()
        base = Path(f'/proc/{pid}/cwd')
        if number == 322 and ctypes.c_int(args[0]).value != -100:
            base = Path(f'/proc/{pid}/fd/{args[0]}')
        return (base/name).resolve()

    for sig in (signal.SIGIO,signal.SIGTERM,signal.SIGINT,signal.SIGALRM):
        signal.signal(sig,interrupted)
    signal.alarm(880)  # Parent retains its existing 900-second compiler bound.
    # TRACESYSGOOD|TRACEFORK|TRACEVFORK|TRACECLONE|TRACEEXEC|EXITKILL.
    options = 1|2|4|8|16|0x100000
    child = None
    try:
        with (output/'syscalls.jsonl').open('x',buffering=1) as raw:
            child = os.fork()
            if child == 0:
                try:
                    signal.alarm(0)
                    for sig in (signal.SIGIO,signal.SIGTERM,signal.SIGINT,signal.SIGALRM):
                        signal.signal(sig,signal.SIG_DFL)
                    ptrace(0,0)  # TRACEME, no attach to an operator process.
                    os.kill(os.getpid(),signal.SIGSTOP)
                    os.execvpe(command[0],command,os.environ)
                except BaseException:
                    os._exit(127)
            active.add(child)
            pid,status = os.waitpid(child,0)
            require(os.WIFSTOPPED(status) and os.WSTOPSIG(status) == signal.SIGSTOP,
                    'tracee did not stop before exec')
            ptrace(0x4200,pid,0,options)
            ptrace(24,pid)  # SYSCALL
            events = 0
            while active:
                pid,status = os.waitpid(-1,0x40000000)  # __WALL: all owned tracee threads
                require(not intervention(self_pending,pid,status),
                        'intervening event, signal or exit during self-maps read')
                if pid not in active:
                    # A newborn SIGSTOP can arrive before its parent's FORK
                    # event. Leave it stopped until that kernel event binds it.
                    require(os.WIFSTOPPED(status) and os.WSTOPSIG(status) == signal.SIGSTOP,
                            'unknown compiler tracee')
                    early_stops.add(pid)
                    continue
                events += 1
                require(events <= 10000000, 'compiler syscall bound exceeded')
                raw.write(json.dumps({'event':events,'pid':pid,'wait_status':status})+'\n')
                if os.WIFEXITED(status) or os.WIFSIGNALED(status):
                    active.remove(pid)
                    sharers.discard(pid)
                    require(pid not in self_pending, 'self-maps read interrupted by exit')
                    if pid == child:
                        result = os.waitstatus_to_exitcode(status)
                        record['command_exit'] = result if result >= 0 else 128-result
                    continue
                require(os.WIFSTOPPED(status), 'unknown compiler wait status')
                sig, event = os.WSTOPSIG(status), status >> 16
                if event in (1,2,3):
                    message = ctypes.c_ulong()
                    ptrace(0x4201,pid,0,ctypes.addressof(message))
                    flags = clone_intent.get(pid,(0,0))[1]
                    if flags & (CLONE_VM|CLONE_FILES) and not flags & CLONE_THREAD:
                        sharers.add(message.value)  # shares memory or descriptors until exec or exit
                    active.add(message.value)
                    if message.value in early_stops:
                        early_stops.remove(message.value)
                        ptrace(24,message.value)
                    else:
                        newborn.add(message.value)
                elif event == 4:
                    message = ctypes.c_ulong()
                    ptrace(0x4201,pid,0,ctypes.addressof(message))
                    sharers.discard(pid)  # exec gives the image its own memory and descriptor table
                    require(exec_inputs.pop(message.value,False), 'successful exec lacked a captured input')
                    # The kernel may select an interpreter for a static script.
                    # Bind its actual installed image, not just the script name.
                    capture(pid,Path(f'/proc/{pid}/exe'))
                    previous = pending.pop(message.value,None)
                    if previous is not None:
                        operand,row = previous
                        actual = Path(f'/proc/{pid}/exe').stat()
                        require((actual.st_dev,actual.st_ino) == (row['device'],row['inode']),
                                'generated exec identity changed')
                    active.discard(message.value)
                    active.add(pid)
                elif sig == signal.SIGTRAP | 0x80:
                    buffer = ctypes.create_string_buffer(88)
                    count = ptrace(0x420e,pid,88,ctypes.addressof(buffer))
                    op, values = read_syscall(buffer.raw,count)
                    marker = events
                    raw.write(json.dumps({'event':marker,'pid':pid,'op':op,'values':values})+'\n')
                    if op == 1:
                        number,*args = values
                        require(pid not in self_pending, 'overlapping self-maps read')
                        if number == 435:  # clone3 struct starts with u64 flags.
                            require(args[1] >= 8, 'short clone3 arguments')
                            with Path(f'/proc/{pid}/mem').open('rb',buffering=0) as memory:
                                flags = os.pread(memory.fileno(),8,args[0])
                            require(len(flags) == 8 and not struct.unpack('=Q',flags)[0] & 0x7e820080,
                                    'untraced/namespaced compiler child')
                            clone_intent[pid] = (number, struct.unpack('=Q',flags)[0])
                        elif number in (56,57,58):
                            clone_intent[pid] = (number, {56:args[0],57:0,58:CLONE_VM|CLONE_VFORK}[number])
                        try:
                            fd = input_fd(number,args,pid)
                        except (ValueError,OSError) as error:
                            if number == 9 and args[3] & 1 and not args[3] & 0x20:
                                observe_rejected_fd(record,pid,values,marker,active,sharers,str(error))
                            raise
                        if fd is not None:
                            operand = Path(f'/proc/{pid}/fd/{fd}')
                            target = self_maps_target(os.readlink(operand)) if operand.is_symlink() else None
                            if target is not None:
                                consumed.add(target)  # observed before any rejection
                                raw.write(json.dumps({'event':marker,'pid':pid,'self_maps_entry':target})+'\n')
                                record['self_maps_entries'].append(marker)
                                tgid, tasks = task_state(pid)
                                self_maps_entry(number,pid,tgid,tasks,target,sharers)
                                self_pending[pid] = {'path':target,'fd':fd,'tgid':tgid,'buffer':args[1],
                                                     'requested':args[2],'entry_event':marker}
                            else:
                                row = capture(pid,operand)
                                if row is not None:
                                    pending[pid] = (operand,row)
                        elif number in (59,322):
                            operand = exec_path(pid,number,args)
                            exec_inputs[pid] = operand.exists()
                            if operand.exists():  # A failed PATH candidate reads no bytes.
                                row = capture(pid,operand,executable=True)
                                if row is not None:
                                    pending[pid] = (operand,row)
                    elif pid in self_pending:
                        entry = self_pending.pop(pid)
                        returned, is_error = values
                        require(is_error == 0 and 0 <= returned <= entry['requested'],
                                'self-maps read failed or returned out of bounds')
                        tgid, tasks = task_state(pid)
                        require(tgid == entry['tgid'], 'self-maps reader changed at exit')
                        self_maps_entry(0,pid,tgid,tasks,entry['path'],sharers)
                        require(os.readlink(f"/proc/{pid}/fd/{entry['fd']}") == entry['path'],
                                'self-maps descriptor changed at exit')
                        data = tracee_bytes(pid,entry['buffer'],returned)
                        require(len(record['self_maps']) < MAX_SELF_MAPS_RECORDS and
                                self_bytes + len(data) <= MAX_SELF_MAPS_TOTAL,
                                'self-maps record or byte bound exceeded')
                        self_bytes += len(data)
                        name = str(len(record['self_maps']))+'.runtime'
                        with (blobs/name).open('xb') as stream:
                            stream.write(data)
                        record['self_maps'].append({'class':'self_maps_runtime','version':1,'pid':pid,'tgid':tgid,
                            'path':entry['path'],'fd':entry['fd'],'buffer':entry['buffer'],'requested':entry['requested'],
                            'entry_event':entry['entry_event'],'exit_event':marker,'returned':returned,'size':len(data),
                            'sha256':hashlib.sha256(data).hexdigest(),'blob':name})
                    elif pid in pending:
                        operand,row = pending.pop(pid)
                        actual = operand.stat()
                        require((actual.st_dev,actual.st_ino) == (row['device'],row['inode']),
                                'consumed descriptor identity changed')
                    if op == 2:
                        exec_inputs.pop(pid,None)
                        clone_intent.pop(pid,None)
                elif sig == signal.SIGSTOP and pid in newborn:
                    newborn.remove(pid)
                else:
                    require(event == 0 and sig not in (signal.SIGSTOP,signal.SIGTSTP,signal.SIGTTIN,signal.SIGTTOU),
                            'unsupported compiler group/event stop')
                    ptrace(24,pid,0,sig)
                    continue
                ptrace(24,pid)
            require(not early_stops and record['command_exit'] is not None and consumed,
                    'missing command exit, child ownership or consumption')
            require(not self_pending, 'self-maps read pending at termination')
            for fd,row in leases.values():
                require(fcntl.fcntl(fd,fcntl.F_GETLEASE) == fcntl.F_RDLCK, 'lost generated input lease')
                verify_fd(fd,row)
                verify_blob(blobs,row)
            record['complete'] = True
            record['events'] = events
    except BaseException as error:
        record['complete'] = False
        # Exception context survives an interrupt even before the observer has
        # stored its row. Keep the initiating rejection, not only the interrupt.
        problems, seen = [], set()
        while error is not None and id(error) not in seen:
            seen.add(id(error))
            problems.append(str(error))
            error = error.__context__
        record['errors'].extend(reversed(problems))
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGIO,signal.SIG_IGN)
        # EXITKILL also covers tracer termination. On an orderly error, signal
        # only unreaped ptrace-owned IDs; these cannot be recycled yet.
        for pid in active:
            try:
                os.kill(pid,signal.SIGKILL)
            except ProcessLookupError:
                pass
        for fd,_ in leases.values():
            os.close(fd)
        record['observed'] = sorted(consumed)
        with (output/'capture.json').open('x') as stream:
            json.dump(record,stream,indent=2,sort_keys=True)
    # Preserve actual nonzero compiler exits, separately from capture failure.
    return record['command_exit'] or (0 if record['complete'] else 1)


if __name__ == '__main__':
    require(len(sys.argv) >= 5 and sys.argv[3] == '--', 'expected PRIVATE OUTPUT -- COMMAND')
    sys.exit(trace(sys.argv[4:],Path(sys.argv[1]),Path(sys.argv[2])))
