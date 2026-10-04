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


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def inventory(root, names):
    return {name: digest(root / name) for name in names}


def checked(argv, cwd=ROOT, env=None, timeout=240):
    result = subprocess.run([str(x) for x in argv], cwd=cwd, env=env,
                            capture_output=True, timeout=timeout)
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
               TERM='xterm-256color', TZ='UTC', NO_COLOR='1')
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

    def quit(self, key='q', clipboard_owned=False):
        started = time.monotonic()
        self.write(key)
        self.wait(lambda: not self.alive(), 'actual browser quit', timeout=10)
        self.pump(0.1)
        receipt = json.loads(self.console_receipt.read_bytes())
        assert receipt == {'exit_code': 0, 'input_restored': True, 'output_restored': True}, receipt
        if os.name != 'nt':
            import termios
            assert termios.tcgetattr(self.slave) == self.original, 'controlling PTY was not restored'
        if clipboard_owned:
            assert time.monotonic()-started < 1.3, 'quit was measured only after timer expiry'
            assert not clipboard(self.env), 'copied secret survived quit'
        assert PHRASE.encode() not in self.capture
        return {'exit_code': 0, 'terminal_restored': True,
                'capture_sha256': hashlib.sha256(self.capture).hexdigest()}

    def editor_terminal_restored(self):
        if os.name == 'nt':
            return None  # post-exit native input/output modes are independently checked
        import termios
        return termios.tcgetattr(self.slave) == self.original

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
    row = {'case': case, 'seeded_files': seeded, 'before': before}
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
        Path(str(editor)+'.editor.json').write_text(json.dumps(
            {'Mode': mode, 'Ready': str(ready), 'Release': str(release)}))
        env.update(EDITOR=str(editor))
    browser = Browser(binary, helper, home, root, env)
    try:
        if case in {'uninitialized', 'locked-wrong-passphrase'}:
            if case == 'locked-wrong-passphrase':
                browser.wait(lambda: 'passphrase' in browser.view().lower(), 'hidden locked prompt')
                browser.write('public-wrong-passphrase-782a\n')
            browser.wait(lambda: not browser.alive(), 'locked/uninitialized process exit')
            browser.pump(0.1)
            observed = json.loads(browser.console_receipt.read_bytes())
            assert observed['exit_code'] != 0 and observed['input_restored'] and observed['output_restored']
            assert all(c.encode() not in browser.capture for c in [PHRASE, *CANARIES])
            row.update(exit_code=observed['exit_code'], terminal_restored=True,
                       diagnostic=scrub(browser.capture.decode(errors='replace')),
                       capture_sha256=hashlib.sha256(browser.capture).hexdigest())
            assert snapshot(helper, home/'vault', home, env) == before
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
            browser.wait(lambda: PATHS[0] not in browser.view() and '[1/2]' in browser.view(), 'confirmed deletion')
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
        return row
    finally:
        browser.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--rust-cli', type=Path, required=True)
    parser.add_argument('--receipt', type=Path, required=True)
    parser.add_argument('--xvfb', default=shutil.which('Xvfb'))
    parser.add_argument('--xclip', default=shutil.which('xclip'))
    parser.add_argument('--allow-dirty-for-development', action='store_true')
    args = parser.parse_args()
    rust = args.rust_cli.resolve()
    commit = checked(['git', 'rev-parse', 'HEAD']).decode().strip()
    clean = not checked(['git', 'status', '--porcelain=v1', '--untracked-files=normal']).strip()
    assert clean or args.allow_dirty_for_development, 'native acceptance requires clean source'
    names = sorted(x for x in checked(['git', 'ls-files', '--cached', '--others', '--exclude-standard']).decode().splitlines()
                   if x.startswith(('crates/', 'third_party/', 'testdata/'))
                   or x in {'Cargo.toml', 'Cargo.lock', '.gitattributes', 'deny.toml',
                            'scripts/rust-port/tui_contract.py', 'scripts/rust-port/tui_fixture.go.txt',
                            'scripts/rust-port/tui-validation-requirements.txt',
                            '.github/workflows/rust-tui.yml', 'docs/adr/0029-native-vault-browser.md'})
    before = inventory(ROOT, names)
    receipt = {'schema_version': 1, 'candidate_commit': commit, 'candidate_worktree_clean': clean,
               'native_os': platform.system(), 'architecture': platform.machine(),
               'candidate_sources': before, 'rust_executable_sha256': digest(rust),
               'oracle_commit': ORACLE, 'go': [], 'rust': [], 'passed': False,
               'declared_differences': []}
    with tempfile.TemporaryDirectory(prefix='symvault-tui-native-') as raw:
        base = Path(raw)
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
                        row = run_case(case, label, binary, helper,
                                       seeds[0 if case == 'zero-ttl-quit-cleanup' else 2], base, provider)
                        receipt[label].append(row)
                        print(json.dumps({'case': case, 'implementation': label, 'passed': True}), flush=True)
                    go_row, rust_row = receipt['go'][-1], receipt['rust'][-1]
                    if case.startswith(('editor-', 'add-')) and os.name != 'nt':
                        receipt['declared_differences'].append({'case': case, 'field': 'editor_terminal_restored',
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
                    receipt[label].append({'case': CASES[-1], 'exit_code': 0,
                                           'stdout_sha256': hashlib.sha256(output).hexdigest()})
                assert outputs[0] == outputs[1], 'actual public keybinding table bytes differ'
            assert checked(['git', 'rev-parse', 'HEAD']).decode().strip() == commit
            assert inventory(ROOT, names) == before and digest(rust) == receipt['rust_executable_sha256']
            assert inventory(tree, oracle_names) == receipt['oracle_sources']
            receipt['candidate_worktree_clean_at_end'] = not checked(['git', 'status', '--porcelain=v1', '--untracked-files=normal']).strip()
            assert receipt['candidate_worktree_clean_at_end'] == clean
            assert all(len(receipt[label]) == len(CASES) for label in ['go', 'rust'])
            receipt['passed'] = True
        except Exception as error:
            receipt['failure'] = scrub(type(error).__name__+': '+str(error))
            raise
        finally:
            args.receipt.parent.mkdir(parents=True, exist_ok=True)
            args.receipt.write_text(json.dumps(receipt, indent=2)+'\n')
            checked(['git', 'worktree', 'remove', '--force', tree])
    print('PASS: fifteen actual Go/Rust browser cases on '+platform.system())


if __name__ == '__main__':
    main()
