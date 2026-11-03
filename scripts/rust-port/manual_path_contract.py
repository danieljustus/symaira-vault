#!/usr/bin/env python3
"""Exercise literal manual paths and unchanged help through actual CLI binaries."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import tempfile

from cli_artifacts_contract import ROOT, execute, literal_roff_text

CASES = ['ordinary', 's__b0nk_', 'a_b_c', 'a__b__c', 'a`b`c', 'a[b](c)d',
         'a![b](c)d', 'a&amp;b', 'a<b>c', 'a*b*c', 'a**b**c', 'a\\_b_c',
         " apostrophe' and space ", '.request', "'request", 'a\n.PS\r\t\x1b',
         'a\u0085\u2028\u2029', 'SYMVAULTLITERALCONFIGPATH']


def pages(binary, directory, config, env):
    directory.mkdir()
    result = execute([binary, 'generate', 'manpages', 'man'], directory, env)
    assert not result.stderr
    actual = {path.name: path.read_bytes() for path in (directory / 'man').glob('*.1')}
    assert len(actual) == 119
    expected_path = literal_roff_text(str(config / 'symaira-vault/config.yaml')).encode()
    assert b'(default: ' + expected_path + b'; existing installs' in actual['symvault-mcp.1']
    return actual


def normalized_pages(pages_by_name, config):
    placeholder = literal_roff_text(str(config / 'symaira-vault/config.yaml')).encode()
    return {name: content.replace(placeholder, b'__CONFIG_PATH__') for name, content in pages_by_name.items()}


def manual_digest(normalized):
    return hashlib.sha256(b''.join(name.encode() + b'\0' + normalized[name] + b'\0' for name in sorted(normalized))).hexdigest()


def case_environment(root, index, case, inherited_env):
    base = root / str(index)
    base.mkdir(parents=True)
    home = base / 'home'
    home.mkdir()
    config = base / 'config-inputs' / case
    env = dict(inherited_env)
    env.update(HOME=str(home), USERPROFILE=str(home), XDG_CONFIG_HOME=str(config),
               XDG_DATA_HOME=str(home / 'data'), XDG_CACHE_HOME=str(home / 'cache'),
               SYMVAULT_TEST_KEYRING='memory', SOURCE_DATE_EPOCH='0', TZ='UTC')
    return base, config, env


def observe_go_manual_paths(go_binary, root, inherited_env, artifact):
    """Capture mode: what the Go binary renders for every literal path case (needs the Go binary).

    Only path-independent facts are kept: the placeholder-normalized manual digest, the page
    count and the normalized unchanged help of `mcp` and `serve`.
    """
    observations = []
    for index, case in enumerate(CASES):
        base, config, env = case_environment(root, index, case, inherited_env)
        go = pages(go_binary, base / 'go', config, env)
        normalized = normalized_pages(go, config)
        assert normalized == {name: text.encode() for name, text in artifact['manpages'].items()}, ('unaffected manuals', case)
        help_pages = {}
        for command in ['mcp', 'serve']:
            output = execute([go_binary, command, '--help'], base, env)
            assert not output.stderr
            help_pages[command] = output.stdout.decode('utf-8').replace(str(config / 'symaira-vault/config.yaml'), '__CONFIG_PATH__')
            assert help_pages[command] == artifact['help']['symvault ' + command]
        observations.append({'case': case, 'manual_count': len(go), 'normalized_manual_digest': manual_digest(normalized),
                             'help': help_pages})
    assert [o['case'] for o in observations] == CASES and len(observations) == 18
    return observations


def verify_manual_paths(go_binary, rust_binary, root, inherited_env, artifact, legacy_binary=None, go_recorded=None):
    """Rust (and optionally live Go) literal manual paths.

    With `go_recorded` (observe_go_manual_paths output committed under
    scripts/rust-port/fixtures/go-observations) no Go binary runs: the recorded Go facts and the
    committed artifact are the oracle. Pass `go_binary` for the historical live comparison.
    """
    assert (go_binary is None) == (go_recorded is not None), 'exactly one of a live Go binary or recorded Go observations'
    binaries = [b for b in [go_binary, rust_binary, legacy_binary] if b]
    observations = []
    # These are documentation-only path inputs, not filenames being created.
    # Preserve angle brackets/controls on Windows without creating invalid files.
    for index, case in enumerate(CASES):
        base, config, env = case_environment(root, index, case, inherited_env)
        config_path = str(config / 'symaira-vault/config.yaml')
        rust = pages(rust_binary, base / 'rust', config, env)
        if go_binary is not None:
            go = pages(go_binary, base / 'go', config, env)
            assert go == rust, ('manual bytes', case, [name for name in go if go[name] != rust.get(name)])
        normalized = normalized_pages(rust, config)
        assert normalized == {name: text.encode() for name, text in artifact['manpages'].items()}, ('unaffected manuals', case)
        if go_recorded is not None:
            recorded = go_recorded[index]
            assert recorded['case'] == case and recorded['manual_count'] == len(rust), ('recorded Go case', case)
            assert recorded['normalized_manual_digest'] == manual_digest(normalized), ('recorded Go manual digest', case)
            go_mcp_page = rust['symvault-mcp.1']  # byte-equal to the recorded Go digest, asserted above
        else:
            go_mcp_page = go['symvault-mcp.1']
        actual_help = {}
        for command in ['mcp', 'serve']:
            outputs = [execute([binary, command, '--help'], base, env) for binary in binaries]
            assert all(not output.stderr for output in outputs)
            assert len({output.stdout for output in outputs}) == 1, ('unchanged help', command, case)
            text = outputs[0].stdout.decode('utf-8')
            if go_recorded is not None:
                assert text.replace(config_path, '__CONFIG_PATH__') == recorded['help'][command], ('recorded Go help', command, case)
            assert text.replace(config_path, '__CONFIG_PATH__') == artifact['help']['symvault ' + command]
            actual_help[command] = text
        observations.append({'case': case, 'manual_count': len(rust), 'actual_help': actual_help,
                             'actual_go_mcp_page': go_mcp_page.decode('utf-8'),
                             'actual_rust_mcp_page': rust['symvault-mcp.1'].decode('utf-8'),
                             'normalized_manual_digest': manual_digest(normalized),
                             'go_source': 'live' if go_binary is not None else 'recorded', 'passed': True})
    assert [observation['case'] for observation in observations] == CASES and len(observations) == 18
    return observations


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--go', type=Path, required=True)
    parser.add_argument('--legacy-go', type=Path, required=True)
    parser.add_argument('--rust', type=Path, required=True)
    parser.add_argument('--receipt', type=Path, required=True)
    parser.add_argument('--allow-dirty-for-development', action='store_true')
    args = parser.parse_args()
    binaries = [args.go.resolve(), args.legacy_go.resolve(), args.rust.resolve()]
    assert len(set(binaries)) == 3, 'three real binaries are required'
    hashes = [hashlib.sha256(binary.read_bytes()).hexdigest() for binary in binaries]
    assert len(set(hashes)) == 3, 'byte-identical binaries cannot establish parity'
    clean = not subprocess.check_output(['git', 'status', '--porcelain=v1', '--untracked-files=normal'], cwd=ROOT).strip()
    assert clean or args.allow_dirty_for_development
    artifact = json.loads((ROOT / 'testdata/port/cli/artifacts.json').read_bytes())
    env = {k: v for k, v in os.environ.items() if not k.upper().startswith('SYMVAULT_')}
    with tempfile.TemporaryDirectory(prefix='symvault-manual-path-') as temporary:
        observations = verify_manual_paths(binaries[0], binaries[2], Path(temporary), env, artifact, binaries[1])
    receipt = {'passed': True, 'candidate_commit': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip(),
               'candidate_worktree_clean': clean, 'native_os': platform.system(), 'architecture': platform.machine(),
               'binary_sha256': dict(zip(['go', 'legacy_go', 'rust'], hashes)),
               'driver_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(), 'cases': observations}
    args.receipt.write_bytes((json.dumps(receipt, indent=2)+'\n').encode())
    print(f'PASS literal manual paths: {len(observations)} cases, 119 manuals and mcp/serve unchanged help per case')


if __name__ == '__main__':
    main()
