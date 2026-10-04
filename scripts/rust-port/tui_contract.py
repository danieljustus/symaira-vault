#!/usr/bin/env python3
"""Actual immutable Go/Rust browser processes, private terminals and providers.

pyte decodes real terminal output; it never supplies browser behavior. Windows
uses native ConPTY. macOS/Windows clipboard tests require disposable CI hosts;
Linux owns an authenticated, private X server and never uses the user's display.
"""
import argparse
import codecs
import contextlib
import hashlib
import json
import os
from pathlib import Path
import platform
import queue
import re
import secrets
import select
import shutil
import signal
import struct
import subprocess
import sys
import tempfile
import threading
import time

import pyte

ROOT = Path(__file__).resolve().parents[2]
ORACLE = 'd1cd0f97ac550bc3020bc86b0514989f8d28d95c'
PHRASE = 'public-tui-passphrase-782a'
CANARIES = ['public-tui-secret-alpha-782a', 'public-tui-secret-beta-782a',
            'public-tui-secret-gamma-782a', 'public-tui-edited-secret-782a']
PATHS = ['alpha/login', 'beta/api', 'gamma/control']
CASES = ['browser-navigation-filter-sort-help', 'native-copy-expiry-quit',
         'generated-password-not-persisted', 'editor-valid-and-expiry',
         'editor-invalid', 'editor-empty', 'editor-failure', 'add-valid',
         'add-invalid-no-initial-write', 'delete-confirmation',
         'zero-ttl-quit-cleanup', 'ctrl-c-filter-cleanup', 'locked-wrong-passphrase',
         'uninitialized', 'public-keybinding-table']
COMMAND_OUTPUT = None
COMMAND_NUMBER = 0
CAPTURE_OUTPUT = None


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def inventory(root, names):
    return {name: digest(root / name) for name in names}


def checked(argv, cwd=ROOT, env=None, timeout=240):
    global COMMAND_NUMBER
    COMMAND_NUMBER += 1
    prefix = None
    if COMMAND_OUTPUT is not None:
        COMMAND_OUTPUT.mkdir(parents=True, exist_ok=True)
        prefix = COMMAND_OUTPUT/str(COMMAND_NUMBER)
    try:
        result = subprocess.run([str(x) for x in argv], cwd=cwd, env=env,
                                capture_output=True, timeout=timeout)
    except subprocess.TimeoutExpired as error:
        if prefix is not None:
            prefix.with_suffix('.stdout').write_bytes(error.stdout or b'')
            prefix.with_suffix('.stderr').write_bytes(error.stderr or b'')
            prefix.with_suffix('.json').write_text(json.dumps({'argv': [str(x) for x in argv], 'timed_out': True}))
        raise
    if prefix is not None:
        prefix.with_suffix('.stdout').write_bytes(result.stdout)
        prefix.with_suffix('.stderr').write_bytes(result.stderr)
        prefix.with_suffix('.json').write_text(json.dumps({'argv': [str(x) for x in argv], 'exit_code': result.returncode, 'timed_out': False}))
    assert result.returncode == 0, (Path(argv[0]).name, result.returncode,
                                  scrub(result.stderr.decode(errors='replace')[-1800:]))
    return result.stdout


def scrub(text):
    for value in [PHRASE, *CANARIES]:
        text = text.replace(value, '__PUBLIC_CANARY__')
    return text


def fixture_env(home, provider):
    home.mkdir(parents=True)
    temporary = home / 'tmp'
    temporary.mkdir()
    env = {k: v for k, v in os.environ.items()
           if not k.startswith(('SYMVAULT_', 'SYMAIRA_'))
           and k not in {'DISPLAY', 'WAYLAND_DISPLAY', 'DBUS_SESSION_BUS_ADDRESS',
                         'XAUTHORITY', 'EDITOR', 'VISUAL'} }
    env.update(HOME=str(home), USERPROFILE=str(home), XDG_CONFIG_HOME=str(home/'config'),
               XDG_DATA_HOME=str(home/'data'), XDG_CACHE_HOME=str(home/'cache'),
               TMPDIR=str(temporary), TEMP=str(temporary), TMP=str(temporary),
               SYMVAULT_TEST_KEYRING='memory', SYMVAULT_NO_NOTIFY='1',
               # pyte is a screen decoder, not an xterm OSC color-query peer.
               # Advertising xterm makes Go's lazy termenv query reader compete
               # with Bubble Tea for confirmation keys. screen-256color is the
               # actual emulated capability set (no OSC 10/11 reports).
               TERM='screen-256color', TZ='UTC', NO_COLOR='1',
               TUI_PRIVATE_ENV='public-environment-filter-canary')
    env.update(provider)
    return env


@contextlib.contextmanager
def private_provider(base, xvfb, xclip):
    if platform.system() != 'Linux':
        assert platform.system() in {'Darwin', 'Windows'}
        assert os.environ.get('GITHUB_ACTIONS') == 'true'
        assert os.environ.get('SYMVAULT_DISPOSABLE_NATIVE_RUNNER') == '1', \
            'native shared clipboard proof requires a disposable CI host'
        yield {}
        return
    xvfb, xclip = Path(xvfb).resolve(), Path(xclip).resolve()
    assert xvfb.is_file() and xclip.is_file()
    auth = base / 'Xauthority'
    cookie = secrets.token_bytes(16)

    def authority(number):
        values = [b'', str(number).encode(), b'MIT-MAGIC-COOKIE-1', cookie]
        auth.write_bytes(struct.pack('>H', 65535) + b''.join(
            struct.pack('>H', len(value)) + value for value in values))
        auth.chmod(0o600)

    authority(0)
    with (base/'xvfb.log').open('wb') as log:
        server = subprocess.Popen([xvfb, '-displayfd', '1', '-screen', '0',
                                   '1280x800x24', '-nolisten', 'tcp', '-noreset',
                                   '-auth', auth, '-fp', 'built-ins'],
                                  stdout=subprocess.PIPE, stderr=log)
        lines = queue.Queue()
        reader = threading.Thread(target=lambda: lines.put(server.stdout.readline()))
        reader.start()
        try:
            number = lines.get(timeout=15).decode().strip()
            assert number.isdecimal(), 'private authenticated X server failed'
            authority(number)
            yield {'DISPLAY': ':'+number, 'XAUTHORITY': str(auth),
                   'PATH': str(xclip.parent)+os.pathsep+os.environ['PATH']}
        finally:
            if server.poll() is None:
                server.terminate()
            server.wait(timeout=10)
            reader.join(timeout=5)
            server.stdout.close()
            assert not reader.is_alive(), 'private display reader did not join'


def clipboard(env):
    if platform.system() == 'Darwin':
        return checked(['/usr/bin/pbpaste'], env=env, timeout=5)
    if platform.system() == 'Windows':
        import ctypes
        from ctypes import wintypes
        user = ctypes.WinDLL('user32', use_last_error=True)
        kernel = ctypes.WinDLL('kernel32', use_last_error=True)
        user.OpenClipboard.argtypes = [wintypes.HWND]
        user.OpenClipboard.restype = wintypes.BOOL
        user.GetClipboardData.argtypes = [wintypes.UINT]
        user.GetClipboardData.restype = wintypes.HANDLE
        kernel.GlobalLock.argtypes = [wintypes.HGLOBAL]
        kernel.GlobalLock.restype = ctypes.c_void_p
        kernel.GlobalUnlock.argtypes = [wintypes.HGLOBAL]
        until = time.monotonic()+2
        while not user.OpenClipboard(None):
            assert time.monotonic() < until, 'native clipboard remained locked'
            time.sleep(0.02)
        try:
            handle = user.GetClipboardData(13)  # actual CF_UNICODETEXT
            if not handle:
                return b''
            pointer = kernel.GlobalLock(handle)
            assert pointer, 'native clipboard handle did not lock'
            try:
                return ctypes.wstring_at(pointer).encode('utf-8')
            finally:
                kernel.GlobalUnlock(handle)
        finally:
            assert user.CloseClipboard(), 'native clipboard did not close'
    executable = shutil.which('xclip', path=env['PATH'])
    assert executable
    result = subprocess.run([executable, '-selection', 'clipboard', '-out'],
                            env=env, capture_output=True, timeout=5)
    assert result.returncode == 0 or (result.returncode == 1 and
           re.search(rb'target (?:STRING|UTF8_STRING) not available', result.stderr)), \
        ('private clipboard query failed', result.returncode, scrub(result.stderr.decode(errors='replace')))
    return result.stdout


def terminal_modes(state):
    state = list(state)
    if platform.system() == 'Darwin':
        # Same documented kernel-only PENDIN exclusion as the Go observer.
        state[3] &= ~0x20000000
    return state


class Browser:
    def __init__(self, binary, helper, home, root, env):
        self.home, self.env = home, env
        self.capture = bytearray()
        self.screen = pyte.Screen(120, 32)
        self.stream = pyte.Stream(self.screen)
        self.decoder = codecs.getincrementaldecoder('utf-8')(errors='replace')
        self.escape_tail = b''
        self.console_receipt = home/'console.json'
        argv = [str(helper), '--root', str(root), '--console-binary', str(binary),
                '--console-receipt', str(self.console_receipt)]
        if os.name == 'nt':
            from winpty import Backend, PtyProcess
            # Explicit ConPTY backend, never a pipe or Wine emulation.
            self.child = PtyProcess.spawn(argv, cwd=str(home), env=env,
                                          dimensions=(32, 120), backend=str(Backend.ConPTY))
            self.master = None
        else:
            import fcntl
            import pty
            import termios
            self.master, self.slave = pty.openpty()
            fcntl.ioctl(self.slave, termios.TIOCSWINSZ, struct.pack('HHHH', 32, 120, 0, 0))
            self.original = termios.tcgetattr(self.slave)

            def setup():
                os.setsid()
                fcntl.ioctl(self.slave, termios.TIOCSCTTY, 0)

            self.child = subprocess.Popen(argv, cwd=home, env=env, stdin=self.slave,
                                          stdout=self.slave, stderr=self.slave,
                                          preexec_fn=setup)

    def alive(self):
        return self.child.isalive() if os.name == 'nt' else self.child.poll() is None

    def write(self, value):
        if os.name == 'nt':
            self.child.write(value)
        else:
            os.write(self.master, value.encode())

    def pump(self, seconds=0.12):
        end = time.monotonic()+seconds
        while time.monotonic() < end:
            descriptor = self.child.fileobj if os.name == 'nt' else self.master
            ready, _, _ = select.select([descriptor], [], [], min(0.05, max(0, end-time.monotonic())))
            if not ready:
                continue
            try:
                data = self.child.read(65536).encode() if os.name == 'nt' else os.read(self.master, 65536)
            except (EOFError, OSError):
                if not self.alive():
                    return
                raise
            if not data:
                return
            self.capture.extend(data)
            query = self.escape_tail+data
            # Crossterm requests cursor position during clear/resize; answer the
            # actual terminal query, including when it spans reads.
            for _ in range(query.count(b'\x1b[6n')):
                self.write('\x1b[1;1R')
            self.escape_tail = query[-3:]
            self.stream.feed(self.decoder.decode(data))

    def view(self):
        return '\n'.join(self.rows())

    def detail(self):
        return '\n'.join(self.rows(42))

    def deletion_visible(self):
        # A legitimate "Deleted alpha/login" status is not an entry.
        return PATHS[0] not in self.detail() and '[1/2]' in self.view()

    def rows(self, first=0):
        # Read actual cell positions. pyte 0.8.2's display accessor indexes an
        # empty wide-character stub after an ANSI partial overwrite and raises
        # IndexError. A stub carries no text; retain its cell as a blank instead
        # of modifying the stream or supplying any application behavior.
        return [''.join(self.screen.buffer[y][x].data or ' '
                        for x in range(first, self.screen.columns))
                for y in range(self.screen.lines)]

    def wait(self, predicate, description, timeout=15):
        end = time.monotonic()+timeout
        while time.monotonic() < end:
            self.pump()
            if predicate():
                return
            if not self.alive():
                break
        # Exit can occur between the predicate and alive() observations. A
        # receipt/exit predicate must be checked after that final transition.
        if predicate():
            return
        raise AssertionError(description+'; screen='+scrub(self.view())[-2000:])

    def keys(self, text):
        for character in text:
            self.write(character)
            self.pump(0.09)  # individual keys, not Bubble Tea paste messages

    def select(self, path):
        self.write('\x1b[H')
        self.wait(lambda: PATHS[0] in self.detail(), 'home selection')
        for _ in range(PATHS.index(path)):
            self.write('j')
            self.pump(0.2)
        self.wait(lambda: path in self.detail(), 'selected encrypted entry '+path)

    def unlock(self):
        self.wait(lambda: 'passphrase' in self.view().lower(), 'actual hidden unlock prompt')
        self.write(PHRASE+'\n')
        self.wait(lambda: 'Entries' in self.view() and 'public-tui-user' in self.view(),
                  'actual encrypted browser')
        assert all(c.encode() not in self.capture for c in CANARIES), 'implicit canary reveal'
        assert PHRASE.encode() not in self.capture, 'unlock passphrase echoed'

    def copy(self, value=CANARIES[0]):
        self.write('\r')
        self.wait(lambda: clipboard(self.env) == value.encode(), 'actual native clipboard delivery')
        assert value not in self.view(), 'copy implicitly revealed a secret'

    def expiry(self, started=None):
        started = time.monotonic() if started is None else started
        self.wait(lambda: not clipboard(self.env), 'actual native clipboard expiry', timeout=6)
        elapsed = time.monotonic()-started
        assert 1.3 <= elapsed <= 6, ('unexpected configured clipboard expiry', elapsed)
        return elapsed

    def finish(self, expected_exit):
        # Keep the console wrapper alive until mode checks finish. Darwin
        # revokes slave ioctls when the controlling session leader exits.
        self.wait(self.console_receipt.is_file, 'actual CLI exit and native console receipt', timeout=10)
        receipt = json.loads(self.console_receipt.read_bytes())
        assert receipt == {'exit_code': expected_exit, 'input_restored': True, 'output_restored': True}, receipt
        if os.name != 'nt':
            import termios
            assert terminal_modes(termios.tcgetattr(self.slave)) == terminal_modes(self.original), 'controlling PTY was not restored'
        Path(str(self.console_receipt)+'.release').write_text('release\n')
        self.wait(lambda: not self.alive(), 'native console wrapper exit', timeout=10)
        self.pump(0.1)
        return receipt

    def quit(self, key='q', clipboard_owned=False):
        started = time.monotonic()
        self.write(key)
        observed = self.finish(0)
        if clipboard_owned:
            assert time.monotonic()-started < 1.3, 'quit was measured only after timer expiry'
            assert not clipboard(self.env), 'copied secret survived quit'
        assert PHRASE.encode() not in self.capture
        return {'exit_code': 0, 'terminal_restored': True,
                'input_restored': True, 'output_restored': True,
                'console': observed,
                'capture_sha256': hashlib.sha256(self.capture).hexdigest()}

    def editor_terminal_restored(self):
        if os.name == 'nt':
            return None  # post-exit native input/output modes are independently checked
        import termios
        return terminal_modes(termios.tcgetattr(self.slave)) == terminal_modes(self.original)

    def resize(self):
        if os.name == 'nt':
            self.child.setwinsize(28, 100)
        else:
            import fcntl
            import termios
            fcntl.ioctl(self.slave, termios.TIOCSWINSZ, struct.pack('HHHH', 28, 100, 0, 0))
            os.killpg(self.child.pid, signal.SIGWINCH)
        self.screen.resize(28, 100)
        self.pump(0.3)
        assert 'Entries' in self.view() and self.alive()

    def close(self):
        if os.name == 'nt':
            # Close both PtyProcess sockets even after isalive marks it closed.
            if self.alive():
                self.child.terminate(force=True)
            self.child.fileobj.close()
            self.child._server.close()
            self.child.pty.cancel_io()
        else:
            if self.alive():
                os.killpg(self.child.pid, signal.SIGKILL)
            self.child.wait(timeout=10)
            os.close(self.master)
            os.close(self.slave)


def snapshot(helper, root, home, env):
    return json.loads(checked([helper, '--root', root, '--snapshot'], cwd=home, env=env))


def run_case(case, label, binary, helper, seed, base, provider):
    home = base/(case+'-'+label+'-home')
    env = fixture_env(home, provider)
    root = home/'vault'
    shutil.copytree(seed, root)
    seeded = inventory(seed, sorted(str(p.relative_to(seed)) for p in seed.rglob('*') if p.is_file()))
    assert inventory(root, list(seeded)) == seeded
    before = snapshot(helper, root, home, env)
    row = {'case': case, 'seeded_files': seeded, 'before': before, 'passed': False}
    if case == 'uninitialized':
        root = home/'nonexistent'
    ready, release = home/'editor-ready.json', home/'editor-release'
    mode = 'invalid' if 'invalid' in case else 'empty' if case == 'editor-empty' else \
           'failure' if case == 'editor-failure' else 'valid'
    if case.startswith(('editor-', 'add-')):
        # Real editor environments correctly strip arbitrary fixture variables.
        # Configure this copied fixture executable through a private sidecar;
        # production environment filtering is exercised without an exception.
        editor = home/('fixture-editor.exe' if os.name == 'nt' else 'fixture-editor')
        shutil.copy2(helper, editor)
        with os.fdopen(os.open(str(editor)+'.editor.json', os.O_WRONLY|os.O_CREAT|os.O_EXCL, 0o600), 'w') as sidecar:
            json.dump({'Mode': mode, 'Ready': str(ready), 'Release': str(release),
                       'Console': str(home/'console.json.before')}, sidecar)
        env.update(EDITOR=str(editor))
    browser = Browser(binary, helper, home, root, env)
    try:
        if case in {'uninitialized', 'locked-wrong-passphrase'}:
            if case == 'locked-wrong-passphrase':
                browser.wait(lambda: 'passphrase' in browser.view().lower(), 'hidden locked prompt')
                browser.write('public-wrong-passphrase-782a\n')
            observed = browser.finish(6 if label == 'go' else 1)
            assert all(c.encode() not in browser.capture for c in [PHRASE, *CANARIES])
            row.update(exit_code=observed['exit_code'], terminal_restored=True, console=observed,
                       diagnostic=scrub(browser.capture.decode(errors='replace')),
                       capture_sha256=hashlib.sha256(browser.capture).hexdigest())
            row.update(input_restored=True, output_restored=True,
                       after=snapshot(helper, home/'vault', home, env), canary_disclosure=False)
            assert row['after'] == before
            row['passed'] = True
            return row
        browser.unlock()
        if case == 'browser-navigation-filter-sort-help':
            browser.write('r')
            browser.wait(lambda: CANARIES[0] in browser.view(), 'explicit reveal')
            browser.write('r')
            browser.wait(lambda: CANARIES[0] not in browser.view(), 'explicit redact')
            browser.select(PATHS[-1])
            browser.select(PATHS[0])
            sorts = [PATHS[2], PATHS[0], PATHS[2], PATHS[1], PATHS[0], PATHS[0]]
            for selected in sorts:
                browser.write('s')
                browser.wait(lambda: selected in browser.detail(), 'actual selected sort order')
            browser.write('?')
            browser.wait(lambda: 'Help' in browser.view() and 'Ctrl+C' in browser.view(), 'actual help')
            browser.write('?'); browser.pump()
            browser.write('t'); browser.pump(); browser.keys('wo'); browser.write('\r')
            browser.wait(lambda: '[1/2]' in browser.view() and PATHS[1] not in browser.view(), 'tag prefix filter')
            browser.write('t'); browser.pump(); browser.write('\x1b')
            browser.wait(lambda: '[1/3]' in browser.view(), 'tag escape clears query')
            browser.write('/'); browser.pump(); browser.keys('alp'); browser.write('\x1b')
            browser.wait(lambda: '[1/1]' in browser.view() and PATHS[1] not in browser.view(), 'name escape retains query')
            browser.resize()
            row['explicit_reveal_observed'] = True
            row.update(browser.quit())
        elif case == 'native-copy-expiry-quit':
            browser.copy(); row['expiry_seconds'] = browser.expiry()
            browser.copy(); row.update(browser.quit(clipboard_owned=True))
        elif case == 'generated-password-not-persisted':
            browser.write('g'); browser.pump(); browser.keys('0'); browser.write('\r')
            browser.wait(lambda: 'Invalid length' in browser.view(), 'invalid generator length')
            browser.write('\x7f'); browser.pump(); browser.keys('8'); browser.write('s'); browser.pump()
            browser.write('\r')
            browser.wait(lambda: len(clipboard(env)) == 8, 'actual generated native clipboard delivery')
            generated = clipboard(env)
            assert re.fullmatch(rb'[A-Za-z0-9]{8}', generated), 'symbol toggle ignored'
            assert generated not in browser.capture, 'generated password implicitly revealed'
            row['generated_length'] = 8
            row.update(browser.quit(clipboard_owned=True))
        elif case.startswith(('editor-', 'add-')):
            if case == 'editor-valid-and-expiry':
                browser.copy()
                copied = time.monotonic()
            if case.startswith('add-'):
                browser.write('a'); browser.pump(); browser.keys('delta/new'); browser.write('\r')
            else:
                browser.write('e')
                browser.wait(lambda: 'y/N' in browser.view(), 'edit confirmation')
                browser.write('y')
            browser.wait(ready.is_file, 'actual foreground editor opened real document')
            editor = json.loads(ready.read_bytes())
            assert editor['input_is_terminal'] and editor['output_is_terminal'] and editor['document_bytes'] > 0
            assert editor['environment_filtered'] is True, 'editor environment filtering weakened'
            assert editor['foreground_terminal_restored'] is (label == 'rust'), 'foreground terminal decision changed'
            if os.name != 'nt':
                assert editor['mode'] == 0o600, 'editor document permissions'
            row['editor'] = editor
            row['editor_terminal_restored'] = browser.editor_terminal_restored()
            if os.name != 'nt':
                assert row['editor_terminal_restored'] == (label == 'rust'), 'versioned foreground-terminal decision changed'
            if case == 'editor-valid-and-expiry':
                row['expiry_seconds'] = browser.expiry(copied)
                assert not release.exists() and browser.alive(), 'editor finished before expiry observation'
            release.write_text('release\n')
            expected = {'valid': 'public-tui-edited-user', 'invalid': 'invalid JSON',
                        'empty': 'empty file', 'failure': 'editor failed'}[mode]
            browser.wait(lambda: expected in browser.view(), 'actual editor result returned to browser')
            assert CANARIES[-1] not in browser.view(), 'editor result was implicitly revealed'
            assert not list((home/'tmp').glob('symvault-edit-*')), 'plaintext editor document survived completion'
            row.update(browser.quit())
        elif case == 'delete-confirmation':
            browser.write('d'); browser.wait(lambda: 'y/N' in browser.view(), 'delete confirmation')
            browser.write('n'); browser.pump()
            assert snapshot(helper, root, home, env) == before, 'cancelled deletion mutated vault'
            browser.write('d'); browser.wait(lambda: 'y/N' in browser.view(), 'second delete confirmation')
            browser.write('y')
            browser.wait(browser.deletion_visible, 'confirmed deletion')
            row.update(browser.quit())
        elif case == 'zero-ttl-quit-cleanup':
            browser.copy()
            row.update(browser.quit())
            row['clipboard_survived_quit'] = clipboard(env) == CANARIES[0].encode()
            assert row['clipboard_survived_quit'] == (label == 'go'), 'versioned zero-TTL cleanup decision changed'
            # Explicitly clear the disposable native clipboard after recording
            # Go's retained copy; never leave a fixture canary in the provider.
            if label == 'go':
                if platform.system() == 'Darwin':
                    subprocess.run(['/usr/bin/pbcopy'], input=b'', env=env, check=True, timeout=5)
                elif platform.system() == 'Windows':
                    import ctypes
                    user = ctypes.WinDLL('user32')
                    assert user.OpenClipboard(None)
                    try:
                        assert user.EmptyClipboard()
                    finally:
                        user.CloseClipboard()
                else:
                    subprocess.run([shutil.which('xclip', path=env['PATH']), '-selection', 'clipboard'],
                                   input=b'', env=env, check=True, timeout=5)
        elif case == 'ctrl-c-filter-cleanup':
            browser.copy()
            browser.write('/'); browser.pump()
            row.update(browser.quit('\x03', clipboard_owned=True))
        else:
            raise AssertionError('unhandled browser case '+case)
        after = snapshot(helper, root, home, env)
        row['after'] = after
        if case == 'delete-confirmation':
            assert after == before[1:], 'confirmed deletion changed other encrypted entries'
        elif case in {'editor-valid-and-expiry', 'add-valid'}:
            changed = PATHS[0] if case.startswith('editor-') else 'delta/new'
            before_map = {r['path']: r for r in before}
            after_map = {r['path']: r for r in after}
            assert set(after_map) == set(before_map) | {changed}
            assert all(after_map[p] == r for p, r in before_map.items() if p != changed)
            data = {'password': CANARIES[-1], 'username': 'public-tui-edited-user'}
            expected_hash = hashlib.sha256(json.dumps(data, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
            assert after_map[changed]['data_sha256'] == expected_hash, 'editor changes did not reach actual encrypted store'
        else:
            assert after == before, 'non-writing browser action mutated encrypted data'
        assert PHRASE.encode() not in browser.capture
        if case != 'browser-navigation-filter-sort-help':
            assert all(c.encode() not in browser.capture for c in CANARIES), 'implicit canary output'
        row.update(passed=True, canary_disclosure=False)
        return row
    except Exception as error:
        row.update(failure=scrub(type(error).__name__+': '+str(error)),
                   diagnostic=scrub(browser.capture.decode(errors='replace')),
                   capture_sha256=hashlib.sha256(browser.capture).hexdigest())
        raise CaseFailure(row) from error
    finally:
        if CAPTURE_OUTPUT is not None:
            CAPTURE_OUTPUT.mkdir(parents=True, exist_ok=True)
            artifact = CAPTURE_OUTPUT/(case+'-'+label+'.terminal')
            artifact.write_bytes(browser.capture)
            row.update(capture_artifact=str(artifact.relative_to(CAPTURE_OUTPUT.parent)),
                       capture_bytes=len(browser.capture), capture_sha256=digest(artifact))
        browser.close()


class CaseFailure(AssertionError):
    def __init__(self, row):
        self.row = row
        super().__init__(row['failure'])


def source_inventory():
    names = checked(['git', 'ls-files', '--cached', '--others', '--exclude-standard']).decode().splitlines()
    names = sorted(x for x in names if x.startswith(('crates/', 'third_party/', 'testdata/', '.cargo/'))
                   or x in {'Cargo.toml', 'Cargo.lock', 'rust-toolchain.toml', '.gitattributes', 'deny.toml',
                            'scripts/rust-port/tui_contract.py', 'scripts/rust-port/tui_fixture.go.txt',
                            'scripts/rust-port/tui_harness_test.py', 'scripts/rust-port/tui_mutation_test.py',
                            'scripts/rust-port/tui_delete_status_fixture.json',
                            'scripts/rust-port/tui-validation-requirements.txt',
                            '.github/workflows/rust-tui.yml', 'docs/adr/0029-native-vault-browser.md'})
    assert all((ROOT/name).resolve().is_relative_to(ROOT) for name in names), 'source escaped checkout'
    return inventory(ROOT, names)


def clean_source():
    return not checked(['git', 'status', '--porcelain=v1', '--untracked-files=all']).strip()


def evidence_artifact(root, name, size, sha256):
    assert isinstance(name, str), 'invalid artifact path'
    name = Path(name)
    assert not name.is_absolute() and '..' not in name.parts, 'artifact path escaped evidence root'
    path = (root/name).resolve()
    assert path.is_relative_to(root.resolve()) and path.is_file(), 'artifact path escaped evidence root'
    raw = path.read_bytes()
    assert type(size) is int and len(raw) == size, 'artifact size mismatch'
    assert isinstance(sha256, str) and re.fullmatch(r'[0-9a-f]{64}', sha256), 'invalid artifact digest'
    assert hashlib.sha256(raw).hexdigest() == sha256, 'artifact digest mismatch'
    return raw


def build_source_bound_rust(rust, base, receipt):
    manifest = ROOT/'Cargo.toml'
    metadata = json.loads(checked(['cargo', 'metadata', '--manifest-path', manifest,
                                   '--no-deps', '--format-version', '1', '--locked']))
    assert Path(metadata['workspace_root']).resolve() == ROOT, 'wrong Cargo workspace'
    for package in metadata['packages']:
        assert Path(package['manifest_path']).resolve().is_relative_to(ROOT), 'dependency source escaped checkout'
        assert all(Path(t['src_path']).resolve().is_relative_to(ROOT) for t in package['targets'])
    # Cargo freshness alone does not prove an externally supplied binary's
    # contents. Rebuild into a new run-owned target and compare actual bytes.
    env = os.environ.copy()
    env.update(CARGO_TARGET_DIR=str(base/'rust-source-build'), CARGO_INCREMENTAL='0',
               CARGO_PROFILE_DEV_DEBUG='0', CARGO_PROFILE_TEST_DEBUG='0')
    checked(['cargo', 'build', '--manifest-path', manifest, '-p', 'symvault-cli',
             '--bin', 'symvault', '--locked'], env=env, timeout=900)
    rebuilt = base/'rust-source-build/debug'/('symvault.exe' if os.name == 'nt' else 'symvault')
    receipt['rebuilt_rust_executable_sha256'] = digest(rebuilt)
    if COMMAND_OUTPUT is not None:
        retained = COMMAND_OUTPUT/('source-rebuild.exe' if os.name == 'nt' else 'source-rebuild')
        shutil.copy2(rebuilt, retained)
        receipt['rebuilt_binary_artifact'] = str(retained.relative_to(COMMAND_OUTPUT.parent))
        receipt['rebuilt_binary_bytes'] = retained.stat().st_size
    assert receipt['rebuilt_rust_executable_sha256'] == digest(rust), 'source/binary mismatch'
    receipt['binary_source_verified'] = True


def validate_receipt(receipt, candidate, native_os, architecture, sources, binary_sha256, evidence_root=None):
    assert isinstance(candidate, str) and re.fullmatch(r'[0-9a-f]{40}', candidate), 'invalid candidate commit'
    assert receipt['schema_version'] == 2 and type(receipt['schema_version']) is int
    assert receipt['candidate_commit'] == candidate, 'candidate identity mismatch'
    assert receipt['oracle_commit'] == ORACLE, 'oracle identity mismatch'
    assert receipt['native_os'] == native_os and receipt['architecture'] == architecture, 'native target mismatch'
    for key in ['passed', 'candidate_worktree_clean', 'candidate_worktree_clean_at_end', 'binary_source_verified']:
        assert receipt[key] is True, 'missing/false '+key
    assert receipt['candidate_sources'] == sources and receipt['candidate_sources_at_end'] == sources, 'source inventory mismatch'
    for key in ['rust_executable_sha256', 'rebuilt_rust_executable_sha256']:
        value = receipt[key]
        assert isinstance(value, str) and re.fullmatch(r'[0-9a-f]{64}', value)
        assert value == binary_sha256, 'source/binary mismatch'
    if evidence_root is not None:
        evidence_artifact(evidence_root, receipt['rebuilt_binary_artifact'],
                          receipt['rebuilt_binary_bytes'], receipt['rebuilt_rust_executable_sha256'])
    for label in ['go', 'rust']:
        rows = receipt[label]
        assert [row['case'] for row in rows] == CASES, 'incomplete/duplicate case set'
        for row in rows:
            assert row['passed'] is True, 'missing/false case success'
            assert type(row['exit_code']) is int, 'invalid exit code type'
            expected_exit = (6 if label == 'go' else 1) if row['case'] in {'locked-wrong-passphrase', 'uninitialized'} else 0
            assert row['exit_code'] == expected_exit, 'exit class mismatch'
            if row['case'] != CASES[-1]:
                for key in ['terminal_restored', 'input_restored', 'output_restored']:
                    assert row[key] is True, 'un-restored terminal modes'
                assert row['canary_disclosure'] is False, 'canary disclosure'
                console = row['console']
                assert type(console['exit_code']) is int and console['exit_code'] == expected_exit
                assert console['input_restored'] is True and console['output_restored'] is True, 'un-restored native console'
                if evidence_root is not None:
                    raw = evidence_artifact(evidence_root, row['capture_artifact'], row['capture_bytes'], row['capture_sha256'])
                    assert PHRASE.encode() not in raw, 'passphrase disclosure'
                    if row['case'] != CASES[0]:
                        assert all(c.encode() not in raw for c in CANARIES), 'canary disclosure'
                assert isinstance(row['before'], list) and isinstance(row['after'], list)
                for state in ['before', 'after']:
                    for entry in row[state]:
                        assert set(entry) == {'path', 'tags', 'version', 'data_sha256'}, 'incomplete snapshot fields'
                        assert isinstance(entry['path'], str) and entry['path'], 'invalid snapshot path'
                        assert type(entry['version']) is int and entry['version'] > 0, 'invalid snapshot version'
                        assert entry['tags'] is None or (isinstance(entry['tags'], list) and all(isinstance(t, str) for t in entry['tags'])), 'invalid snapshot tags'
                        assert isinstance(entry['data_sha256'], str) and re.fullmatch(r'[0-9a-f]{64}', entry['data_sha256']), 'invalid snapshot digest'
                if row['case'].startswith(('editor-', 'add-')):
                    editor = row['editor']
                    assert editor['environment_filtered'] is True, 'editor environment filtering weakened'
                    assert editor['input_is_terminal'] is True and editor['output_is_terminal'] is True
                    assert editor['foreground_terminal_restored'] is (label == 'rust')
                    assert type(editor['document_bytes']) is int and editor['document_bytes'] > 0
    for go_row, rust_row in zip(receipt['go'], receipt['rust']):
        if go_row['case'] != CASES[-1]:
            for field in ['before', 'after']:
                assert json.dumps(go_row[field], sort_keys=True) == json.dumps(rust_row[field], sort_keys=True), 'encrypted-store differential mismatch'
        else:
            assert go_row['stdout_sha256'] == rust_row['stdout_sha256'], 'keybinding byte mismatch'


def execute(args, receipt):
    rust = args.rust_cli.resolve()
    commit = checked(['git', 'rev-parse', 'HEAD']).decode().strip()
    clean = clean_source()
    receipt.update(candidate_commit=commit, candidate_worktree_clean=clean)
    assert clean or args.allow_dirty_for_development, 'native acceptance requires clean source'
    before = source_inventory()
    receipt.update(candidate_sources=before, rust_executable_sha256=digest(rust))
    assert sys.version_info[:2] == (3, 13), 'pinned Python 3.13 required'
    receipt['rustc'] = checked(['rustc', '--version']).decode().strip()
    receipt['rustflags'] = os.environ.get('RUSTFLAGS', '')
    receipt['go_version'] = checked(['go', 'version']).decode().strip()
    assert receipt['rustc'].startswith('rustc 1.98.0 '), 'pinned Rust required'
    assert receipt['go_version'].startswith('go version go1.26.6 '), 'pinned Go required'
    with tempfile.TemporaryDirectory(prefix='symvault-tui-native-') as raw:
        base = Path(raw)
        build_source_bound_rust(rust, base, receipt)
        assert source_inventory() == before, 'source changed during Rust build'
        if args.source_only:
            receipt['candidate_sources_at_end'] = source_inventory()
            receipt['candidate_worktree_clean_at_end'] = clean_source()
            assert receipt['candidate_sources_at_end'] == before
            assert receipt['candidate_worktree_clean_at_end'] == clean
            assert checked(['git', 'rev-parse', 'HEAD']).decode().strip() == commit
            assert digest(rust) == receipt['rust_executable_sha256']
            receipt['source_only_verified'] = True
            return
        tree = base/'oracle'
        checked(['git', 'worktree', 'add', '--detach', tree, ORACLE])
        try:
            oracle_names = sorted(x for x in checked(['git', 'ls-tree', '-r', '--name-only', ORACLE]).decode().splitlines()
                                  if x in {'go.mod', 'go.sum'} or x.endswith('.go'))
            receipt['oracle_sources'] = inventory(tree, oracle_names)
            helper_source = ROOT/'scripts/rust-port/tui_fixture.go.txt'
            helper_dir = tree/'scripts/rust-port/cmd/tuifixture'
            helper_dir.mkdir(parents=True)
            (helper_dir/'main.go').write_bytes(helper_source.read_bytes())
            suffix = '.exe' if os.name == 'nt' else ''
            go, helper = base/('go-cli'+suffix), base/('go-fixture'+suffix)
            checked(['go', 'build', '-trimpath', '-buildvcs=false', '-o', go, '.'], cwd=tree)
            checked(['go', 'build', '-trimpath', '-buildvcs=false', '-o', helper, './scripts/rust-port/cmd/tuifixture'], cwd=tree)
            receipt.update(go_executable_sha256=digest(go), go_fixture_executable_sha256=digest(helper),
                           go_fixture_source_sha256=digest(helper_source),
                           terminal_driver='native-ConPTY' if os.name == 'nt' else 'controlling-Unix-PTY')
            with private_provider(base, args.xvfb, args.xclip) as provider:
                seeds = {}
                for ttl in [2, 0]:
                    home = base/('seed-home-'+str(ttl))
                    env = fixture_env(home, provider)
                    seed = base/('seed-'+str(ttl))
                    result = json.loads(checked([helper, '--root', seed, '--clipboard-seconds', str(ttl)], cwd=home, env=env))
                    assert result['seeded_entries'] == 3 and len(result['keybindings']) == 12
                    receipt['keybindings'] = result['keybindings']
                    seeds[ttl] = seed
                for case in CASES[:-1]:
                    for label, binary in [('go', go), ('rust', rust)]:
                        try:
                            row = run_case(case, label, binary, helper,
                                           seeds[0 if case == 'zero-ttl-quit-cleanup' else 2], base, provider)
                        except CaseFailure as error:
                            receipt[label].append(error.row)
                            raise
                        receipt[label].append(row)
                        print(json.dumps({'case': case, 'implementation': label, 'passed': True}), flush=True)
                    go_row, rust_row = receipt['go'][-1], receipt['rust'][-1]
                    if case.startswith(('editor-', 'add-')):
                        receipt['declared_differences'].append({'case': case, 'field': 'foreground_terminal_restored',
                                                              'go': False, 'rust': True, 'decision': 'ADR-0029'})
                    if case == 'zero-ttl-quit-cleanup':
                        receipt['declared_differences'].append({'case': case, 'field': 'clipboard_survived_quit',
                                                              'go': True, 'rust': False, 'decision': 'ADR-0029'})
                    if case in {'locked-wrong-passphrase', 'uninitialized'}:
                        assert go_row['exit_code'] == 6 and rust_row['exit_code'] == 1
                        receipt['declared_differences'].append({'case': case, 'field': 'exit_code',
                                                              'go': 6, 'rust': 1, 'tracking_issue': 1241})
                outputs = []
                for label, binary in [('go', go), ('rust', rust)]:
                    home = base/('keybindings-'+label)
                    env = fixture_env(home, provider)
                    output = checked([binary, 'ui', '--print-keybindings'], cwd=home, env=env)
                    outputs.append(output)
                    receipt[label].append({'case': CASES[-1], 'exit_code': 0, 'passed': True,
                                           'stdout_sha256': hashlib.sha256(output).hexdigest()})
                assert outputs[0] == outputs[1], 'actual public keybinding table bytes differ'
            assert checked(['git', 'rev-parse', 'HEAD']).decode().strip() == commit
            receipt['candidate_sources_at_end'] = source_inventory()
            assert receipt['candidate_sources_at_end'] == before and digest(rust) == receipt['rust_executable_sha256']
            assert inventory(tree, oracle_names) == receipt['oracle_sources']
            receipt['candidate_worktree_clean_at_end'] = clean_source()
            assert receipt['candidate_worktree_clean_at_end'] == clean
            assert all(len(receipt[label]) == len(CASES) for label in ['go', 'rust'])
            receipt['passed'] = clean
            if clean:
                validate_receipt(receipt, commit, platform.system(), platform.machine(), before, digest(rust), args.receipt.parent)
        except Exception as error:
            receipt['failure'] = scrub(type(error).__name__+': '+str(error))
            raise
        finally:
            checked(['git', 'worktree', 'remove', '--force', tree])
    print(('PASS' if clean else 'DEVELOPMENT ONLY')+': fifteen actual Go/Rust browser cases on '+platform.system())


def main():
    global COMMAND_OUTPUT, CAPTURE_OUTPUT
    parser = argparse.ArgumentParser()
    parser.add_argument('--rust-cli', type=Path, required=True)
    parser.add_argument('--receipt', type=Path, required=True)
    parser.add_argument('--xvfb', default=shutil.which('Xvfb'))
    parser.add_argument('--xclip', default=shutil.which('xclip'))
    parser.add_argument('--allow-dirty-for-development', action='store_true')
    parser.add_argument('--source-only', action='store_true', help='build/binary proof only; never uses clipboard')
    parser.add_argument('--validate-receipt', action='store_true')
    parser.add_argument('--candidate')
    parser.add_argument('--expected-receipt-sha256')
    args = parser.parse_args()
    args.receipt.parent.mkdir(parents=True, exist_ok=True)
    if args.validate_receipt:
        COMMAND_OUTPUT = Path(tempfile.mkdtemp(prefix=args.receipt.stem+'-replay-commands-', dir=args.receipt.parent))
    else:
        assert not args.receipt.exists(), 'existing execution receipt must be preserved'
        COMMAND_OUTPUT = args.receipt.parent/(args.receipt.stem+'-commands')
        COMMAND_OUTPUT.mkdir(exist_ok=False)
    CAPTURE_OUTPUT = args.receipt.parent/(args.receipt.stem+'-captures')
    if args.validate_receipt:
        raw = args.receipt.read_bytes()
        expected = args.expected_receipt_sha256
        assert isinstance(expected, str) and re.fullmatch(r'[0-9a-f]{64}', expected), 'trusted receipt digest required'
        assert hashlib.sha256(raw).hexdigest() == expected, 'receipt integrity mismatch'
        assert clean_source(), 'native replay requires clean source'
        assert checked(['git', 'rev-parse', 'HEAD']).decode().strip() == args.candidate
        validate_receipt(json.loads(raw), args.candidate, platform.system(), platform.machine(),
                         source_inventory(), digest(args.rust_cli), args.receipt.parent)
        print('PASS: source-bound native receipt replay')
        return
    receipt = {'schema_version': 2, 'native_os': platform.system(), 'architecture': platform.machine(),
               'oracle_commit': ORACLE, 'go': [], 'rust': [], 'passed': False, 'declared_differences': []}
    try:
        execute(args, receipt)
    except Exception as error:
        receipt.update(passed=False, failure=scrub(type(error).__name__+': '+str(error)))
        raise
    finally:
        args.receipt.parent.mkdir(parents=True, exist_ok=True)
        args.receipt.write_text(json.dumps(receipt, indent=2)+'\n')


if __name__ == '__main__':
    main()
