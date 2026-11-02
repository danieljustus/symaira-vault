#!/usr/bin/env python3
"""Go-recorded MCP tools/call authorization matrix (MCP-002/MCP-003).

Builds the pinned corrected Go oracle out of tree, seeds one disposable vault per
agent profile (22 profiles, same set as mcp_process_contract.py) and records the
JSON-RPC response of a minimal `tools/call` for every registered tool plus one
unknown name, with no token, with a token scope excluding the tool and with a
token scope naming exactly the tool. Arguments are inert (`{}`), so no tool
reaches a clipboard, autotype, payment, Perplexity, network or child process.

  --generate   write testdata/port/mcp/authz-matrix.json
  --check      regenerate into memory and require byte equality with the file
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parent))
from build_timeout import oracle_build_timeout, remove_worktree
from mcp_oracle import CONTRACT, ORDERED, pinned_go, validate_reference
import mcp_process_contract as process

ROOT = process.ROOT
FIXTURE = ROOT / 'testdata/port/mcp/authz-matrix.json'
PROBE = ROOT / 'scripts/rust-port/mcp_authz_probe.go.txt'
SEED = process.PROBE
CATALOG = ROOT / 'testdata/port/mcp/tool-list.json'
UNKNOWN_TOOL = 'mcp_authz_unknown_tool'
TOKEN_MODES = ['none', 'excluding', 'including']
# Successful results that are random or depend on the whole prior audit trail
# (timestamps, earlier denials) cannot be frozen byte for byte. Their frozen
# value is the mask below; the replay applies the identical mask to Rust.
MASKS = {
    'generate_password': ('random_password', lambda text: {'masked': 'random_password', 'length': len(text)}),
    # normalize() already turned the JSON array text into {'json_text': [...]}.
    'symaira_audit_self': ('audit_rows', lambda text: {'masked': 'audit_rows', 'json_array': isinstance(text, dict) and isinstance(text.get('json_text'), list)}),
}


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
            unstable = [(a['tool'], a['token']) for a, b in zip(*observed) if a != b]
            receipt.setdefault('nondeterministic', {})[name] = unstable
        profiles.append({'name': name, 'agent': agent, 'builtin': builtin or None,
                         'overlay': profile, 'config_yaml': config_yaml,
                         'loaded_go_profile': json.loads(loaded)})
        for row in observed[0]:
            cases.append({'profile': name, 'tool': row['tool'], 'token': row['token'], 'response': row['response']})
    return profiles, cases


def build_fixture():
    validate_reference(ROOT)
    receipt = {}
    go_compiler, build_env, compiler = pinned_go(os.environ.copy(), ROOT)
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
            'compiler': {'version': compiler['version'], 'goos': compiler['build_settings']['GOOS'],
                         'goarch': compiler['build_settings']['GOARCH']},
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


def main():
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--generate', action='store_true')
    mode.add_argument('--check', action='store_true')
    args = parser.parse_args()
    content = json.dumps(build_fixture(), indent=2, ensure_ascii=False) + '\n'
    if args.check:
        if FIXTURE.read_text(encoding='utf-8') != content:
            raise SystemExit('MCP authz matrix fixture stale; run --generate and review the diff')
    else:
        FIXTURE.write_text(content, encoding='utf-8')
    fixture = json.loads(content)
    print(f"PASS MCP authz matrix oracle: {len(fixture['profiles'])} profiles x {len(fixture['tools'])} tools x "
          f"{len(TOKEN_MODES)} token modes = {len(fixture['cases'])} cases")


if __name__ == '__main__':
    main()
