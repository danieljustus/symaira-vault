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
import json
import os
from pathlib import Path
import platform
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


def input_fd(number, args):
    require(0 <= number < 512, 'unsupported compiler syscall number/ABI')
    if number == 56:  # clone: no untraced or foreign-namespace descendants.
        require(not args[0] & 0x7e820000, 'untraced/namespaced compiler child')
    # x86_64 read/pread/readv/preadv/preadv2, sendfile, splice, copy_file_range.
    if number in (0,17,19,295,327,275,326):
        return args[0]
    if number == 40:
        return args[1]
    if number == 16:  # ioctl: reflink consumes a source descriptor too.
        if args[1] == 0x40049409:  # FICLONE
            return args[2]
        # FIONBIO changes descriptor flags, without consuming file bytes.
        require(args[1] in (0x5401,0x5413,0x541b,0x5421,0x5451,0x5450),
                'unsupported compiler ioctl input')
    if number == 9 and not args[3] & 0x20:  # mmap, not MAP_ANONYMOUS
        require(not (args[2] & 2 and args[3] & 1), 'writable shared file mapping unsupported')
        return args[4]
    # Async input, remote memory, namespace changes and trace manipulation cannot
    # be silently omitted. None is needed for ordinary native Rust compilation.
    require(number not in (101,165,161,206,209,246,272,298,304,308,310,311,323,425,426,427),
            'unsupported compiler input/namespace syscall: '+str(number))
    return None


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
    record = {'complete':False, 'command':command, 'command_exit':None,
              'errors':[], 'generated':[], 'observed':[], 'acceptance':False}
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
                if pid not in active:
                    # A newborn SIGSTOP can arrive before its parent's FORK
                    # event. Leave it stopped until that kernel event binds it.
                    require(os.WIFSTOPPED(status) and os.WSTOPSIG(status) == signal.SIGSTOP,
                            'unknown compiler tracee')
                    early_stops.add(pid)
                    continue
                events += 1
                require(events <= 10000000, 'compiler syscall bound exceeded')
                raw.write(json.dumps({'pid':pid,'wait_status':status})+'\n')
                if os.WIFEXITED(status) or os.WIFSIGNALED(status):
                    active.remove(pid)
                    if pid == child:
                        result = os.waitstatus_to_exitcode(status)
                        record['command_exit'] = result if result >= 0 else 128-result
                    continue
                require(os.WIFSTOPPED(status), 'unknown compiler wait status')
                sig, event = os.WSTOPSIG(status), status >> 16
                if event in (1,2,3):
                    message = ctypes.c_ulong()
                    ptrace(0x4201,pid,0,ctypes.addressof(message))
                    active.add(message.value)
                    if message.value in early_stops:
                        early_stops.remove(message.value)
                        ptrace(24,message.value)
                    else:
                        newborn.add(message.value)
                elif event == 4:
                    message = ctypes.c_ulong()
                    ptrace(0x4201,pid,0,ctypes.addressof(message))
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
                    raw.write(json.dumps({'pid':pid,'op':op,'values':values})+'\n')
                    if op == 1:
                        number,*args = values
                        if number == 435:  # clone3 struct starts with u64 flags.
                            require(args[1] >= 8, 'short clone3 arguments')
                            with Path(f'/proc/{pid}/mem').open('rb',buffering=0) as memory:
                                flags = os.pread(memory.fileno(),8,args[0])
                            require(len(flags) == 8 and not struct.unpack('=Q',flags)[0] & 0x7e820080,
                                    'untraced/namespaced compiler child')
                        fd = input_fd(number,args)
                        if fd is not None:
                            operand = Path(f'/proc/{pid}/fd/{fd}')
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
                    elif pid in pending:
                        operand,row = pending.pop(pid)
                        actual = operand.stat()
                        require((actual.st_dev,actual.st_ino) == (row['device'],row['inode']),
                                'consumed descriptor identity changed')
                    if op == 2:
                        exec_inputs.pop(pid,None)
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
            for fd,row in leases.values():
                require(fcntl.fcntl(fd,fcntl.F_GETLEASE) == fcntl.F_RDLCK, 'lost generated input lease')
                verify_fd(fd,row)
                verify_blob(blobs,row)
            record['complete'] = True
            record['events'] = events
    except BaseException as error:
        record['complete'] = False
        record['errors'].append(str(error))
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
