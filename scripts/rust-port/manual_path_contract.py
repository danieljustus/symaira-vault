#!/usr/bin/env python3
"""Literal manual paths and unchanged help of the Rust CLI against the recorded Go facts (library; no Go)."""
import hashlib

from cli_artifacts_contract import execute, literal_roff_text

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


def verify_manual_paths(rust_binary, root, inherited_env, artifact, go_recorded):
    """Rust literal manual paths against the recorded Go facts.

    `go_recorded` is the committed observation (scripts/rust-port/fixtures/go-observations/cli-artifacts-contract.*)
    of the Go binary's rendering of every literal path case; no Go binary runs. The committed artifact is the
    oracle for the unaffected manuals and for the unchanged `mcp`/`serve` help.
    """
    observations = []
    # These are documentation-only path inputs, not filenames being created.
    # Preserve angle brackets/controls on Windows without creating invalid files.
    for index, case in enumerate(CASES):
        base, config, env = case_environment(root, index, case, inherited_env)
        config_path = str(config / 'symaira-vault/config.yaml')
        rust = pages(rust_binary, base / 'rust', config, env)
        normalized = normalized_pages(rust, config)
        assert normalized == {name: text.encode() for name, text in artifact['manpages'].items()}, ('unaffected manuals', case)
        recorded = go_recorded[index]
        assert recorded['case'] == case and recorded['manual_count'] == len(rust), ('recorded Go case', case)
        assert recorded['normalized_manual_digest'] == manual_digest(normalized), ('recorded Go manual digest', case)
        mcp_page = rust['symvault-mcp.1']  # its digest equals the recorded Go digest (asserted above)
        actual_help = {}
        for command in ['mcp', 'serve']:
            output = execute([rust_binary, command, '--help'], base, env)
            assert not output.stderr
            text = output.stdout.decode('utf-8')
            assert text.replace(config_path, '__CONFIG_PATH__') == recorded['help'][command], ('recorded Go help', command, case)
            assert text.replace(config_path, '__CONFIG_PATH__') == artifact['help']['symvault ' + command]
            actual_help[command] = text
        observations.append({'case': case, 'manual_count': len(rust), 'actual_help': actual_help,
                             'mcp_page_matching_go': mcp_page.decode('utf-8'),
                             'actual_rust_mcp_page': rust['symvault-mcp.1'].decode('utf-8'),
                             'normalized_manual_digest': manual_digest(normalized),
                             'go_source': 'recorded', 'passed': True})
    assert [observation['case'] for observation in observations] == CASES and len(observations) == 18
    return observations
