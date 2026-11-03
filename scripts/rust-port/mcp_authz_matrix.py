#!/usr/bin/env python3
"""Go-recorded MCP tools/call authorization matrix (MCP-002/MCP-003).

Builds the pinned corrected Go oracle out of tree, seeds one disposable vault per
agent profile (22 profiles, same set as mcp_process_contract.py) and records the
JSON-RPC response of a minimal `tools/call` for every registered tool plus one
unknown name, with no token, with a token scope excluding the tool and with a
token scope naming exactly the tool. Arguments are inert (`{}`), so no tool
reaches a clipboard, autotype, payment, Perplexity, network or child process.

The matrix is recorded per host GOOS (the capability decisions depend on the
platform: Touch ID, clipboard and autotype backends, secure-input UI):

  testdata/port/mcp/authz-matrix.json          darwin
  testdata/port/mcp/authz-matrix-linux.json    linux

  --generate   write only the host's fixture
  --check      replay, no Go: the host's frozen fixture must be the bytes the Go
               capture accepted (scripts/rust-port/fixtures/go-observations/
               mcp-authz-matrix.<goos>.json), its oracle pin must resolve in git
               with the recorded source digest; a host without a recorded fixture
               is a failure, never a skip
  --capture-go regenerate from the Go oracle, require equality with the frozen
               fixture (generator stamp aside) and record it for --check
"""
import argparse
import hashlib
import json
import os
import platform
from pathlib import Path
import re
import shutil
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parent))
import go_observations_common as observations
from build_timeout import oracle_build_timeout, remove_worktree
from mcp_oracle import CONTRACT, ORDERED, pinned_go, validate_reference
import mcp_process_contract as process

ROOT = process.ROOT
FIXTURES = {
    'darwin': ROOT / 'testdata/port/mcp/authz-matrix.json',
    'linux': ROOT / 'testdata/port/mcp/authz-matrix-linux.json',
}
PROBE = ROOT / 'scripts/rust-port/mcp_authz_probe.go.txt'
SEED = process.PROBE
CATALOG = ROOT / 'testdata/port/mcp/tool-list.json'
UNKNOWN_TOOL = 'mcp_authz_unknown_tool'
TOKEN_MODES = ['none', 'excluding', 'including']
# Successful results that are random or depend on the whole prior audit trail
# (timestamps, earlier denials) cannot be frozen byte for byte. Their frozen
# value is the mask below; the replay applies the identical mask to Rust.
MASKS = {
    'generate_password': ('random_password', lambda text: {'masked': 'random_password', 'length': len(undo_mcp_sanitizer(text))}),
    # normalize() already turned the JSON array text into {'json_text': [...]}.
    'symaira_audit_self': ('audit_rows', lambda text: {'masked': 'audit_rows', 'json_array': isinstance(text, dict) and isinstance(text.get('json_text'), list)}),
}


def undo_mcp_sanitizer(text):
    """Inverts the only rewrites the MCP output sanitizer can apply to a
    generated password (internal/mcp/server/render.go sanitizeBytes, mirrored by
    crates/symvault-mcp/src/render.rs): `</name...>` -> `</ name... >` and
    `-->` -> `-- >`. The password charset has neither a space nor a control or
    non-ASCII character, so every space comes from the sanitizer and the original
    length is recoverable exactly. Without this, about 1 password in 8,700
    (`-->` or `</x...>` among 16 characters of an 82-character alphabet) is
    longer than 16 and the masked length differs between two otherwise identical
    observations. Any other space or character stays in the measured text, so a
    wrong-length password is still a visible difference."""
    if not isinstance(text, str):
        return text
    return re.sub(r'</ ([^ >]+) >', r'</\1>', text).replace('-- >', '-->')


def host_goos():
    """Go spelling of the host OS; an unrecorded host fails visibly."""
    goos = {'Darwin': 'darwin', 'Linux': 'linux'}.get(platform.system())
    if goos not in FIXTURES:
        raise SystemExit(f'MCP authz matrix has no fixture for host OS {platform.system()!r}; recorded: {sorted(FIXTURES)}')
    return goos


def fixture_path(goos):
    return FIXTURES[goos]


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def tool_names():
    names = [tool['name'] for tool in json.loads(CATALOG.read_text())['catalog']]
    assert len(names) == 35 and len(set(names)) == 35
    return names + [UNKNOWN_TOOL]


def normalize(value, home):
    """Rewrites only the disposable HOME prefix, nested JSON text (compared as
    JSON, as the process contract does) and the host's Touch ID capability
    (macOS hardware vs Linux CI)."""
    if isinstance(value, str):
        value = value.replace(str(home), '__HOME__')
        try:
            nested = json.loads(value)
        except ValueError:
            return value
        if isinstance(nested, (dict, list)):
            return {'json_text': normalize(nested, home)}
        return value
    if isinstance(value, list):
        return [normalize(v, home) for v in value]
    if isinstance(value, dict):
        return {k: ('<host-dependent>' if k == 'touchIDAvailable' else normalize(v, home)) for k, v in value.items()}
    return value


def mask(tool, response):
    """Mask only an isError=false text result of the two documented tools."""
    result = response.get('result') if isinstance(response, dict) else None
    if tool in MASKS and result and not result.get('isError') and result.get('content'):
        content = dict(result['content'][0])
        content['text'] = MASKS[tool][1](content['text'])
        return dict(response, result=dict(result, content=[content]))
    return response


def differing_rows(first, second, limit=600):
    """The rows two observations of one profile disagree on, as readable text,
    so a nondeterminism failure names the tool, the token mode and both values
    instead of only the tool/mode pair."""
    return [{'tool': a['tool'], 'token': a['token'],
             'first': json.dumps(a['response'], ensure_ascii=False)[:limit],
             'second': json.dumps(b['response'], ensure_ascii=False)[:limit]}
            for a, b in zip(first, second) if a != b]


def record(go, seed, base, tools, receipt):
    profiles, cases = [], []
    for name, profile in process.profiles():
        profile = dict(profile)
        builtin = profile.pop('__builtin', '')
        agent = builtin or 'fixture'
        seed_home = base / (name + '-seed')
        seed_home.mkdir()
        profile_file = seed_home / 'profile.json'
        profile_file.write_text(json.dumps(profile), encoding='utf-8')
        loaded = process.checked([seed, '--root', seed_home / 'vault', '--profile', profile_file,
                                  '--builtin', builtin, '--agent', agent], seed_home, process.isolated(seed_home))
        config_yaml = (seed_home / 'vault/config.yaml').read_text(encoding='utf-8').replace(str(seed_home), '__HOME__')
        observed = []
        for attempt in range(2):
            home = base / f'{name}-run{attempt}'
            home.mkdir()
            shutil.copytree(seed_home / 'vault', home / 'vault')
            out = process.checked([go, '--root', home / 'vault', '--agent', agent, '--tools', ','.join(tools)],
                                  home, process.isolated(home), timeout=300)
            rows = normalize(json.loads(out), home)
            for row in rows:
                if isinstance(row['response'], str):
                    row['response'] = json.loads(row['response'])
                row['response'] = mask(row['tool'], row['response'])
            assert len(rows) == len(tools) * len(TOKEN_MODES), (name, 'every tool x token mode executed')
            observed.append(rows)
        if observed[0] != observed[1]:
            receipt.setdefault('nondeterministic', {})[name] = differing_rows(*observed)
        profiles.append({'name': name, 'agent': agent, 'builtin': builtin or None,
                         'overlay': profile, 'config_yaml': config_yaml,
                         'loaded_go_profile': json.loads(loaded)})
        for row in observed[0]:
            cases.append({'profile': name, 'tool': row['tool'], 'token': row['token'], 'response': row['response']})
    return profiles, cases


def build_fixture(goos):
    validate_reference(ROOT)
    receipt = {}
    go_compiler, build_env, compiler = pinned_go(os.environ.copy(), ROOT)
    assert compiler['build_settings']['GOOS'] == goos, ('compiler GOOS differs from the host fixture', compiler['build_settings']['GOOS'], goos)
    tools = tool_names()
    with tempfile.TemporaryDirectory(prefix='symvault-mcp-authz-') as raw:
        base = Path(raw)
        tree = base / 'oracle'
        process.checked(['git', 'worktree', 'add', '--detach', tree, ORDERED])
        try:
            sources = sorted(p for p in process.checked(['git', 'ls-tree', '-r', '--name-only', ORDERED], tree).decode().splitlines()
                             if p in {'go.mod', 'go.sum'} or p.endswith('.go') and not p.endswith('_test.go'))
            source_digest = process.inventory(sources, tree)
            for rel, src in [('scripts/rust-port/cmd/mcpprocessseed/main.go', SEED), ('scripts/rust-port/cmd/mcpauthzprobe/main.go', PROBE)]:
                target = tree / rel
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(src.read_bytes())
            suffix = '.exe' if os.name == 'nt' else ''
            go, seed = base / ('go-authz' + suffix), base / ('go-seed' + suffix)
            for out, package in [(go, './scripts/rust-port/cmd/mcpauthzprobe'), (seed, './scripts/rust-port/cmd/mcpprocessseed')]:
                process.checked([go_compiler, 'build', '-trimpath', '-buildvcs=false', '-o', out, package],
                                tree, build_env, timeout=oracle_build_timeout())
            assert process.inventory(sources, tree) == source_digest, 'oracle source changed during build'
            profiles, cases = record(go, seed, base, tools, receipt)
            assert process.inventory(sources, tree) == source_digest, 'oracle source changed during observation'
        finally:
            remove_worktree(lambda: process.checked(['git', 'worktree', 'remove', '--force', tree]), 'MCP authz oracle worktree')
    assert not receipt.get('nondeterministic'), receipt.get('nondeterministic')
    return {
        'schema_version': 1,
        'oracle': {
            'commit': ORDERED[:8], 'commit_sha': ORDERED, 'reference_contract': CONTRACT,
            'source_files': 'every non-test .go file plus go.mod/go.sum at commit_sha (%d files)' % len(sources),
            'source_digest': source_digest,
            'probe': 'scripts/rust-port/mcp_authz_probe.go.txt', 'probe_sha256': sha256(PROBE),
            'seed': 'scripts/rust-port/mcp_process_seed.go.txt', 'seed_sha256': sha256(SEED),
            'generator': 'scripts/rust-port/mcp_authz_matrix.py', 'generator_sha256': sha256(__file__),
            # GOARCH is deliberately not pinned: the recorded outcomes carry no
            # architecture-dependent value, and a pinned arm64 would turn the
            # x86-64 CI runners into a false 'stale'.
            'compiler': {'version': compiler['version'], 'goos': compiler['build_settings']['GOOS']},
        },
        'inert_arguments': {},
        'token_modes': {
            'none': 'no token in the call context (stdio)',
            'excluding': 'token scope [health] (symaira_whoami when the called tool is health)',
            'including': 'token scope names exactly the called tool',
        },
        'unknown_tool': UNKNOWN_TOOL,
        'tools': tools,
        'masks': {tool: name for tool, (name, _) in MASKS.items()},
        'profiles': profiles,
        'cases': cases,
    }


def frozen_source_digest(commit):
    """The oracle source digest recomputed from git blobs (no checkout, no Go): same algorithm as inventory()."""
    names = sorted(p for p in process.checked(['git', 'ls-tree', '-r', '--name-only', commit]).decode().splitlines()
                   if p in {'go.mod', 'go.sum'} or p.endswith('.go') and not p.endswith('_test.go'))
    digest = hashlib.sha256()
    for name in names:
        digest.update(name.encode() + b'\0' + process.checked(['git', 'show', f'{commit}:{name}']) + b'\0')
    return digest.hexdigest(), len(names)


def without_generator_stamp(fixture):
    """The recorded fixture minus the generator digest: that field stamps the script that froze it, which
    now also carries the replay logic and must not make an unchanged Go observation look stale."""
    fixture = json.loads(json.dumps(fixture))
    fixture['oracle'].pop('generator_sha256', None)
    return fixture


def capture(goos, fixture_file):
    """Capture mode: regenerate the matrix from the pinned Go oracle and require it to equal the frozen fixture."""
    assert fixture_file.is_file(), f'MCP authz matrix fixture missing for {goos}: {fixture_file.relative_to(ROOT)}'
    generated = build_fixture(goos)
    frozen = json.loads(fixture_file.read_text(encoding='utf-8'))
    assert without_generator_stamp(generated) == without_generator_stamp(frozen), \
        f'MCP authz matrix fixture stale for {goos}; run --generate on a {goos} host and review the diff'
    recorded = {'fixture': str(fixture_file.relative_to(ROOT)), 'fixture_sha256': sha256(fixture_file),
                'source_digest': generated['oracle']['source_digest'], 'probe_sha256': generated['oracle']['probe_sha256'],
                'seed_sha256': generated['oracle']['seed_sha256'], 'cases': len(generated['cases'])}
    target = observations.save('mcp-authz-matrix', recorded, oracle_commit=ORDERED, version=generated['oracle']['compiler']['version'],
                               args=['mcp_authz_matrix.py', '--capture-go'])
    print(f"captured {observations.rel(target)}: {recorded['cases']} Go-recorded cases ({goos})")


def replay_check(goos, fixture_file):
    """Replay: the frozen per-OS fixture is the recorded Go observation. It must be the bytes the Go capture
    accepted, its oracle pin must resolve in git with the recorded source digest, and the probes must be unchanged."""
    if not fixture_file.is_file():
        raise SystemExit(f'MCP authz matrix fixture missing for {goos}: {fixture_file.relative_to(ROOT)}; run --generate on a {goos} host')
    recorded = observations.load('mcp-authz-matrix', oracle_commit=ORDERED)['observations']
    assert recorded['fixture'] == str(fixture_file.relative_to(ROOT)), 'recorded Go observation covers another fixture'
    if sha256(fixture_file) != recorded['fixture_sha256']:
        raise SystemExit(f'MCP authz matrix fixture changed for {goos}: it is not the bytes the Go oracle produced')
    fixture = json.loads(fixture_file.read_text(encoding='utf-8'))
    oracle = fixture['oracle']
    assert oracle['commit_sha'] == ORDERED and oracle['reference_contract'] == CONTRACT, 'fixture oracle pin drifted'
    digest, count = frozen_source_digest(ORDERED)
    assert digest == oracle['source_digest'] == recorded['source_digest'], 'oracle source digest differs from git blobs'
    assert oracle['source_files'].endswith(f'({count} files)'), ('oracle source file count', oracle['source_files'], count)
    assert sha256(PROBE) == oracle['probe_sha256'] == recorded['probe_sha256'], 'authz probe changed'
    assert sha256(SEED) == oracle['seed_sha256'] == recorded['seed_sha256'], 'authz seed changed'
    assert len(fixture['cases']) == recorded['cases'] == len(fixture['profiles']) * len(fixture['tools']) * len(TOKEN_MODES)
    return fixture


def main():
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--generate', action='store_true', help='regenerate the host fixture from the Go oracle (needs Go)')
    mode.add_argument('--check', action='store_true', help='replay: verify the frozen fixture against the recorded Go observation (no Go)')
    mode.add_argument('--capture-go', action='store_true', help='regenerate from the Go oracle, require equality with the fixture, record it (needs Go)')
    args = parser.parse_args()
    goos = host_goos()
    fixture_file = fixture_path(goos)
    if args.capture_go:
        return capture(goos, fixture_file)
    if args.check:
        fixture = replay_check(goos, fixture_file)
    else:
        content = json.dumps(build_fixture(goos), indent=2, ensure_ascii=False) + '\n'
        fixture_file.write_text(content, encoding='utf-8')
        fixture = json.loads(content)
    print(f"PASS MCP authz matrix oracle ({goos}): {len(fixture['profiles'])} profiles x {len(fixture['tools'])} tools x "
          f"{len(TOKEN_MODES)} token modes = {len(fixture['cases'])} cases")


if __name__ == '__main__':
    main()
