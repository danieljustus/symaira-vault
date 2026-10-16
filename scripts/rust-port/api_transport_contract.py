#!/usr/bin/env python3
"""Run actual immutable Go/Rust encrypted API handlers with owned DNS/TLS fixtures."""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import socket
import ssl
import struct
import subprocess
import tempfile
import threading
import time

ROOT = Path(__file__).resolve().parents[2]
ORACLE = 'd1cd0f97ac550bc3020bc86b0514989f8d28d95c'
CANARY = b'public-api-native-secret'
PROBE_RUNS = []
CASES = ['verified-dns-https', 'wrong-hostname', 'untrusted-root', 'private-answer',
         'mixed-family-answer', 'pending-headers-cancel', 'progressing-body-deadline', 'pending-dns-cancel']


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def inventory(root, names):
    return {name: digest(root / name) for name in names}


def checked(args, cwd=ROOT, env=None):
    result = subprocess.run([str(x) for x in args], cwd=cwd, env=env, capture_output=True, timeout=240)
    assert result.returncode == 0, (str(args[0]), result.stderr.decode(errors='replace')[-1800:])
    return result.stdout


def fixture_env(home, spec):
    home.mkdir(exist_ok=True)
    temporary = home / 'tmp'
    temporary.mkdir(exist_ok=True)
    env = {k: v for k, v in os.environ.items() if not k.startswith(('SYMVAULT_', 'SYMAIRA_'))}
    env.update(HOME=str(home), USERPROFILE=str(home), XDG_CONFIG_HOME=str(home / 'config'),
               XDG_DATA_HOME=str(home / 'data'), XDG_CACHE_HOME=str(home / 'cache'),
               TMPDIR=str(temporary), TEMP=str(temporary), TMP=str(temporary), TZ='UTC',
               SYMVAULT_TEST_KEYRING='memory', SYMVAULT_NO_NOTIFY='1',
               SYMAIRA_API_NATIVE_SPEC=str(spec))
    return env


class DNS:
    def __init__(self, addresses, stall=False):
        self.addresses, self.stall = addresses, stall
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind(('127.0.0.1', 0))
        self.socket.settimeout(0.1)
        self.address = '{}:{}'.format(*self.socket.getsockname())
        self.stop = threading.Event()
        self.observed = threading.Event()
        self.records, self.errors = [], []
        self.worker = threading.Thread(target=self.run)
        self.worker.start()

    def run(self):
        try:
            while not self.stop.is_set():
                try:
                    data, peer = self.socket.recvfrom(4096)
                except socket.timeout:
                    continue
                offset, labels = 12, []
                while data[offset]:
                    count = data[offset]
                    labels.append(data[offset + 1:offset + 1 + count].decode('ascii'))
                    offset += count + 1
                offset += 1
                qtype, qclass = struct.unpack('!HH', data[offset:offset + 4])
                assert qclass == 1 and '.'.join(labels) in {'dns-api.example.test', 'wrong-api.example.test'}
                answer = b''
                count = 0
                for ip in self.addresses:
                    family = socket.AF_INET6 if ':' in ip else socket.AF_INET
                    if qtype != (28 if family == socket.AF_INET6 else 1):
                        continue
                    raw = socket.inet_pton(family, ip)
                    answer += b'\xc0\x0c' + struct.pack('!HHIH', qtype, 1, 0, len(raw)) + raw
                    count += 1
                response = data[:2] + struct.pack('!HHHHH', 0x8180, 1, count, 0, 0) + data[12:offset + 4] + answer
                self.records.append({'query_base64': base64.b64encode(data).decode(),
                                     'response_base64': None if self.stall else base64.b64encode(response).decode(),
                                     'qtype': qtype, 'peer': list(peer)})
                self.observed.set()
                if not self.stall:
                    self.socket.sendto(response, peer)
        except Exception as error:
            self.errors.append(type(error).__name__ + ': ' + str(error))

    def close(self):
        self.stop.set()
        self.worker.join(timeout=2)
        self.socket.close()
        assert not self.worker.is_alive() and not self.errors, 'owned DNS fixture failed or did not join'


class Upstream:
    def __init__(self, certs, mode):
        self.mode = mode
        self.socket = socket.socket()
        self.socket.bind(('127.0.0.1', 0))
        self.socket.listen(4)
        self.socket.settimeout(0.1)
        self.port = self.socket.getsockname()[1]
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.load_cert_chain(certs / 'leaf.pem', certs / 'leaf-key.pem')
        self.stop = threading.Event()
        self.request = threading.Event()
        self.eof = threading.Event()
        self.records, self.errors = [], []
        self.worker = threading.Thread(target=self.run)
        self.worker.start()

    def run(self):
        try:
            while not self.stop.is_set():
                try:
                    raw, _ = self.socket.accept()
                except socket.timeout:
                    continue
                raw.setblocking(True)
                raw.settimeout(3)
                try:
                    stream = self.context.wrap_socket(raw, server_side=True)
                except (ssl.SSLError, ConnectionError) as error:
                    self.records.append({'tls_rejection': str(error)})
                    raw.close()
                    continue
                with stream:
                    request = b''
                    while not request.endswith(b'\r\n\r\n'):
                        part = stream.recv(1)
                        assert part and len(request) < 16384
                        request += part
                    assert request.startswith(b'GET /v1/status HTTP/1.1\r\n')
                    assert b'authorization: bearer ' + CANARY in request.lower()
                    record = {'request_base64': base64.b64encode(request).decode(), 'progress_bytes': 0, 'upstream_eof': False}
                    self.records.append(record)
                    self.request.set()
                    if self.mode == 'pending-headers-cancel':
                        try:
                            assert stream.recv(1) == b'', 'cancelled upstream sent unexpected bytes'
                        except (ConnectionResetError, ConnectionAbortedError):
                            pass
                        record['upstream_eof'] = True
                        self.eof.set()
                    elif self.mode == 'progressing-body-deadline':
                        stream.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 100000\r\nContent-Type: text/plain\r\n\r\n')
                        stream.settimeout(0.02)
                        deadline = time.monotonic() + 3
                        while time.monotonic() < deadline:
                            try:
                                stream.sendall(b'x')
                                record['progress_bytes'] += 1
                                part = stream.recv(1)
                                assert part == b''
                                record['upstream_eof'] = True
                                self.eof.set()
                                break
                            except socket.timeout:
                                continue
                            except (ssl.SSLError, ConnectionError):
                                record['upstream_eof'] = True
                                self.eof.set()
                                break
                        assert record['upstream_eof'] and record['progress_bytes'] >= 2
                    else:
                        stream.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: ' + str(len(CANARY)).encode() +
                                       b'\r\nContent-Type: text/plain\r\nX-Echo: ' + CANARY + b'\r\nConnection: close\r\n\r\n' + CANARY)
        except Exception as error:
            self.errors.append(type(error).__name__ + ': ' + str(error))

    def close(self):
        self.stop.set()
        self.worker.join(timeout=4)
        self.socket.close()
        assert not self.worker.is_alive() and not self.errors, 'owned upstream fixture failed or did not join'


def execute(binary, spec, home, is_go, cancel_event=None):
    spec_path = home.parent / (home.name + '-spec.json')
    spec_path.write_text(json.dumps(spec))
    env = fixture_env(home, spec_path)
    if is_go:
        # The immutable server package's TestMain requires explicit native
        # Windows cross-language opt-in; otherwise it exits without m.Run.
        env['SYMVAULT_RUN_WINDOWS_CROSSLANG'] = '1'
    argv = [str(binary), '-test.run=^TestAPITransportNativeProbe$'] if is_go else [str(binary), str(spec_path)]
    process = subprocess.Popen(argv, cwd=home, env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    started = time.monotonic()
    stdout, stderr = b'', b''
    record = {'implementation': 'go' if is_go else 'rust', 'mode': spec.get('mode', 'call'), 'spec': spec, 'forced_cleanup': False}
    PROBE_RUNS.append(record)
    try:
        if cancel_event is not None:
            assert cancel_event.wait(8), 'actual pending DNS/upstream request was not observed'
            stopped = time.monotonic()
            stdout, stderr = process.communicate(b'cancel\n', timeout=5)
            cancel_elapsed = time.monotonic() - stopped
            assert cancel_elapsed < 2, 'owned API cancellation exceeded two seconds'
        else:
            stdout, stderr = process.communicate(b'', timeout=12)
            cancel_elapsed = None
        assert process.returncode == 0, 'actual probe process failed'
        assert stderr == b'', 'unexpected probe stderr'
        assert stdout == (b'PASS\n' if is_go else b'completed one actual encrypted API call\n'), 'unexpected probe stdout'
        assert CANARY not in stdout and CANARY not in stderr, 'canary disclosed by process'
        result = json.loads(Path(spec['output']).read_bytes())
        assert CANARY.decode() not in result.get('text', ''), 'canary disclosed by API result'
        return {'result': result, 'stdout_base64': base64.b64encode(stdout).decode(),
                'stderr_base64': base64.b64encode(stderr).decode(), 'exit_code': process.returncode,
                'elapsed_seconds': time.monotonic() - started, 'cancel_elapsed_seconds': cancel_elapsed}
    finally:
        if process.poll() is None:
            record['forced_cleanup'] = True
            process.kill()
            stdout, stderr = process.communicate(timeout=5)
        record.update(stdout_base64=base64.b64encode(stdout).decode(), stderr_base64=base64.b64encode(stderr).decode(),
                      exit_code=process.returncode, elapsed_seconds=time.monotonic()-started)


def assert_pair(case, go, rust, host, native_os):
    left, right = go['result'], rust['result']
    assert left['handler_error'] is False and right['handler_error'] is False, case
    if case == 'verified-dns-https':
        assert left['is_error'] is False and right['is_error'] is False
        a, b = json.loads(left['text']), json.loads(right['text'])
        assert a == b and a['status_code'] == 200 and a['body'] == '***' and a['headers']['X-Echo'] == '***'
        return None
    assert left['is_error'] is True and right['is_error'] is True, case
    if case in {'private-answer', 'mixed-family-answer'}:
        assert left['text'] == f'blocked request target "{host}": resolves to private or local network address'
        assert right['text'] == 'blocked private or local upstream host'
    elif case == 'wrong-hostname':
        assert left['text'].startswith('request failed: ') and 'certificate is valid for dns-api.example.test, not wrong-api.example.test' in left['text']
        assert right['text'] == 'request failed: upstream request failed'
    elif case == 'untrusted-root':
        generic = 'tls: failed to verify certificate: x509: certificate signed by unknown authority'
        darwin = f'tls: failed to verify certificate: x509: “{host}” certificate is not trusted'
        assert left['text'].startswith('request failed: ')
        assert left['text'].endswith(generic) or (native_os == 'Darwin' and left['text'].endswith(darwin))
        assert right['text'] == 'request failed: upstream request failed'
    elif case == 'pending-headers-cancel':
        assert left['text'].startswith('request failed: ') and left['text'].endswith(': context canceled')
        assert right['text'] == 'request failed: upstream request cancelled'
    elif case == 'progressing-body-deadline':
        assert left['text'] == 'cannot read response: context deadline exceeded'
        assert right['text'] == 'request failed: upstream request timed out'
    elif case == 'pending-dns-cancel':
        assert left['text'] == f'cannot resolve request target "{host}": lookup {host}: operation was canceled'
        assert right['text'] == 'upstream request cancelled'
    return {'case': case, 'decision': 'opaque-transport-diagnostic', 'go': left, 'rust': right}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--rust-probe', type=Path, required=True)
    parser.add_argument('--receipt', type=Path, required=True)
    parser.add_argument('--allow-dirty-for-development', action='store_true')
    args = parser.parse_args()
    rust = args.rust_probe.resolve()
    commit = checked(['git', 'rev-parse', 'HEAD']).decode().strip()
    clean = not checked(['git', 'status', '--porcelain=v1', '--untracked-files=normal']).strip()
    assert clean or args.allow_dirty_for_development
    names = sorted(x for x in checked(['git', 'ls-files', '--cached', '--others', '--exclude-standard']).decode().splitlines()
                   if x.startswith(('crates/', 'third_party/', 'testdata/', 'internal/mcp/apitemplates/builtin/'))
                   or x in {'Cargo.toml', 'Cargo.lock', '.gitattributes', 'scripts/rust-port/api_transport_contract.py',
                            'scripts/rust-port/api_transport_probe.go.txt', 'scripts/rust-port/test_api_transport_contract.py',
                            '.github/workflows/rust-api-transport.yml'})
    before = inventory(ROOT, names)
    receipt = {'schema_version': 1, 'candidate_commit': commit, 'candidate_worktree_clean': clean,
               'native_os': platform.system(), 'candidate_sources': before, 'rust_executable_sha256': digest(rust),
               'oracle_commit': ORACLE, 'go': [], 'rust': [], 'processes': PROBE_RUNS, 'declared_differences': [], 'passed': False}
    with tempfile.TemporaryDirectory(prefix='symvault-api-native-') as raw:
        base = Path(raw)
        tree = base / 'oracle'
        checked(['git', 'worktree', 'add', '--detach', tree, ORACLE])
        try:
            oracle_names = sorted(x for x in checked(['git', 'ls-tree', '-r', '--name-only', ORACLE]).decode().splitlines()
                                  if x in {'go.mod', 'go.sum'} or x.endswith('.go') or x.startswith('internal/mcp/apitemplates/builtin/'))
            receipt['oracle_sources'] = inventory(tree, oracle_names)
            helper = ROOT / 'scripts/rust-port/api_transport_probe.go.txt'
            receipt['go_probe_sha256'] = digest(helper)
            (tree / 'internal/mcp/server/api_native_probe_test.go').write_bytes(helper.read_bytes())
            go = base / ('go-api-native.exe' if os.name == 'nt' else 'go-api-native')
            checked(['go', 'test', '-c', '-trimpath', '-buildvcs=false', '-o', go, './internal/mcp/server'], cwd=tree)
            receipt['go_executable_sha256'] = digest(go)
            certs = base / 'certs'
            certs.mkdir()
            execute(go, {'mode': 'cert', 'root': str(certs), 'output': str(base/'cert-result.json')}, base/'cert-home', True)
            receipt['fixture_certificates'] = {x.name: digest(x) for x in certs.iterdir() if x.suffix == '.pem' and 'key' not in x.name}
            for case in CASES:
                upstream = Upstream(certs, case)
                try:
                    host = 'wrong-api.example.test' if case == 'wrong-hostname' else 'dns-api.example.test'
                    base_url = f'https://{host}:{upstream.port}'
                    private = case not in {'private-answer', 'mixed-family-answer', 'pending-dns-cancel'}
                    seed = base / ('seed-' + case)
                    seed.mkdir()
                    execute(go, {'mode': 'seed', 'root': str(seed), 'output': str(base/(case+'-seed.json')),
                                 'base_url': base_url, 'allow_private': private}, base/(case+'-seed-home'), True)
                    seed_inventory = inventory(seed, sorted(str(p.relative_to(seed)) for p in seed.rglob('*') if p.is_file()))
                    results = []
                    for is_go, binary, label in [(True, go, 'go'), (False, rust, 'rust')]:
                        root = base / (case+'-'+label+'-vault')
                        shutil.copytree(seed, root)
                        assert inventory(root, list(seed_inventory)) == seed_inventory
                        addresses = ['192.0.2.7', '::1'] if case == 'mixed-family-answer' else ['127.0.0.1']
                        dns = DNS(addresses, stall=case == 'pending-dns-cancel')
                        upstream.request.clear()
                        upstream.eof.clear()
                        first = len(upstream.records)
                        spec = {'mode': 'call', 'root': str(root), 'output': str(base/(case+'-'+label+'.json')),
                                'dns_server': dns.address, 'ca_file': None if case == 'untrusted-root' else str(certs/'ca.pem'),
                                'timeout_ms': 350 if case == 'progressing-body-deadline' else 5000}
                        event = dns.observed if case == 'pending-dns-cancel' else upstream.request if case == 'pending-headers-cancel' else None
                        try:
                            observation = execute(binary, spec, base/(case+'-'+label+'-home'), is_go, event)
                            if case in {'pending-headers-cancel', 'progressing-body-deadline'}:
                                assert upstream.eof.wait(2), 'real upstream closure missing'
                            observation.update(case=case, seeded_files=seed_inventory, dns=dns.records,
                                               upstream=upstream.records[first:])
                            receipt[label].append(observation)
                            requests = [r for r in observation['upstream'] if 'request_base64' in r]
                            expected = case in {'verified-dns-https', 'pending-headers-cancel', 'progressing-body-deadline'}
                            assert len(requests) == int(expected), 'real upstream request count differs'
                            assert observation['dns'] and {r['qtype'] for r in observation['dns']} <= {1,28}
                            results.append(observation)
                        finally:
                            dns.close()
                    difference = assert_pair(case, results[0], results[1], host, receipt['native_os'])
                    if difference:
                        receipt['declared_differences'].append(difference)
                finally:
                    upstream.close()
            assert checked(['git', 'rev-parse', 'HEAD']).decode().strip() == commit
            assert inventory(ROOT, names) == before and digest(rust) == receipt['rust_executable_sha256']
            receipt['candidate_worktree_clean_at_end'] = not checked(['git', 'status', '--porcelain=v1', '--untracked-files=normal']).strip()
            assert receipt['candidate_worktree_clean_at_end'] == clean
            receipt['passed'] = True
        except Exception as error:
            receipt['failure'] = type(error).__name__ + ': ' + str(error)
            raise
        finally:
            args.receipt.parent.mkdir(parents=True, exist_ok=True)
            args.receipt.write_text(json.dumps(receipt, indent=2) + '\n')
            checked(['git', 'worktree', 'remove', '--force', tree])
    print('PASS: eight actual Go/Rust encrypted API DNS/TLS/cancellation cases on ' + platform.system())


if __name__ == '__main__':
    main()
