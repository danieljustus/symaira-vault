#!/usr/bin/env python3
"""Native production-source mutation controls, using disposable worktrees only."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

import tui_contract as tui


def rejected(tree, binary, receipt, reason, source_only=False):
    argv = [sys.executable, str(tree/'scripts/rust-port/tui_contract.py'),
            '--rust-cli', str(binary), '--receipt', str(receipt)]
    if source_only:
        argv.append('--source-only')
    result = subprocess.run(argv, cwd=tree, capture_output=True, timeout=1500)
    receipt.with_suffix('.stdout').write_bytes(result.stdout)
    receipt.with_suffix('.stderr').write_bytes(result.stderr)
    assert result.returncode != 0, 'mutated source unexpectedly accepted'
    observed = json.loads(receipt.read_bytes())
    assert observed['passed'] is False and reason in observed['failure'], observed.get('failure')
    return observed


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--rust-cli', required=True, type=Path)
    parser.add_argument('--receipt', required=True, type=Path)
    args = parser.parse_args()
    assert tui.clean_source(), 'mutation controls require clean baseline'
    args.receipt.parent.mkdir(parents=True, exist_ok=True)
    binary = args.rust_cli.resolve()
    candidate = tui.checked(['git', 'rev-parse', 'HEAD']).decode().strip()
    baseline_sources = tui.source_inventory()
    summary = {'candidate_commit': candidate, 'native_os': tui.platform.system(),
               'architecture': tui.platform.machine(), 'passed': False, 'controls': {}}
    with tempfile.TemporaryDirectory(prefix='tui-source-mutation-') as raw:
        base = Path(raw); tree = base/'candidate'
        tui.checked(['git', 'worktree', 'add', '--detach', tree, candidate])
        try:
            source = tree/'crates/symvault-cli/src/tui.rs'
            original = source.read_bytes()
            old, new = b'revealed: false,', b'revealed: true,'
            assert original.count(old) == 1, 'mutation anchor changed'
            source.write_bytes(original.replace(old, new, 1))
            dirty_receipt = args.receipt.with_name('tui-mutation-dirty.json')
            rejected(tree, binary, dirty_receipt, 'requires clean source', source_only=True)
            summary['controls']['dirty-source'] = True
            # A clean immutable mutant proves runtime rejection, not merely a
            # hash/dirty-state inequality. No remote ref or original source changes.
            tui.checked(['git', 'add', 'crates/symvault-cli/src/tui.rs'], cwd=tree)
            tui.checked(['git', '-c', 'user.name=Daniel Justus',
                         '-c', 'user.email=88160656+danieljustus@users.noreply.github.com',
                         'commit', '-m', 'Test default-reveal rejection in disposable source'], cwd=tree)
            summary['mutant_commit'] = tui.checked(['git', 'rev-parse', 'HEAD'], cwd=tree).decode().strip()
            summary['mutated_source_sha256'] = hashlib.sha256(source.read_bytes()).hexdigest()
            mutant_sources = dict(baseline_sources)
            mutant_sources['crates/symvault-cli/src/tui.rs'] = summary['mutated_source_sha256']
            env = os.environ.copy()
            env.update(CARGO_TARGET_DIR=str(base/'mutant-target'), CARGO_INCREMENTAL='0',
                       CARGO_PROFILE_DEV_DEBUG='0', CARGO_PROFILE_TEST_DEBUG='0')
            tui.checked(['cargo', 'build', '--manifest-path', tree/'Cargo.toml', '-p', 'symvault-cli',
                         '--bin', 'symvault', '--locked'], cwd=tree, env=env, timeout=900)
            mutant = base/'mutant-target/debug'/('symvault.exe' if os.name == 'nt' else 'symvault')
            mismatch = args.receipt.with_name('tui-mutation-binary-mismatch.json')
            rejected(tui.ROOT, mutant, mismatch, 'source/binary mismatch', source_only=True)
            summary['controls']['source-binary-mismatch'] = True
            semantic = args.receipt.with_name('tui-mutation-default-reveal.json')
            result = rejected(tree, mutant, semantic, 'implicit canary reveal')
            assert result['binary_source_verified'] is True
            assert result['rust'][0]['passed'] is False
            assert result['rust'][0]['case'] == tui.CASES[0]
            summary['controls']['default-reveal-runtime'] = True
            assert result['candidate_commit'] == summary['mutant_commit']
            assert result['candidate_sources'] == mutant_sources
            assert tui.source_inventory() == baseline_sources
            summary['passed'] = True
        except Exception as error:
            summary['failure'] = tui.scrub(type(error).__name__+': '+str(error))
            raise
        finally:
            args.receipt.write_text(json.dumps(summary, indent=2)+'\n')
            tui.checked(['git', 'worktree', 'remove', '--force', tree])
    assert tui.clean_source() and tui.checked(['git', 'rev-parse', 'HEAD']).decode().strip() == candidate
    print('PASS: dirty source, foreign binary and actual default-reveal mutation rejected')


if __name__ == '__main__':
    main()
