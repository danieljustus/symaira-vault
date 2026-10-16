#!/usr/bin/env python3
"""Reject an actual output-deadline mutation, restoring source and executable."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

from mcp_process_contract import ROOT


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--rust', type=Path, required=True)
    parser.add_argument('--receipt', type=Path, required=True)
    args = parser.parse_args()
    rust, receipt = args.rust.resolve(), args.receipt.resolve()
    mutant_receipt = receipt.with_suffix('.mutant.json')
    if receipt.exists() or mutant_receipt.exists():
        raise FileExistsError('mutation evidence paths must be fresh')
    source = ROOT / 'crates/symvault-mcp/src/http.rs'
    original = source.read_bytes()
    anchor = b'        let timeout = match self.write_deadline.get() {'
    if original.count(anchor) != 1:
        raise RuntimeError('output deadline mutation anchor is not unique')
    mutation = b'''        // Deliberately broken, development negative control only.
        self.write_deadline.set(None);
        self.configured_write_timeout.set(None);
'''
    metadata = json.loads(subprocess.check_output(
        ['cargo', 'metadata', '--no-deps', '--format-version=1'], cwd=ROOT))
    built = Path(metadata['target_directory']) / 'debug' / rust.name
    if built.resolve() != rust:
        raise RuntimeError('Rust executable must match the native debug Cargo output')
    report = dict(passed=False, scope='output-deadline-negative-control',
                  candidate_commit=subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT).decode().strip(),
                  original_source_sha256=digest(source), original_binary_sha256=digest(rust),
                  restored=False)
    try:
        with tempfile.TemporaryDirectory(prefix='http-write-mutation-', dir=rust.parent) as raw:
            saved = Path(raw) / rust.name
            shutil.copy2(rust, saved)
            try:
                source.write_bytes(original.replace(anchor, mutation + anchor, 1))
                report['mutant_source_sha256'] = digest(source)
                subprocess.run(['cargo', 'build', '--locked', '-p', 'symvault-cli', '--bin', 'symvault'], cwd=ROOT, check=True)
                report['mutant_binary_sha256'] = digest(rust)
                assert report['mutant_binary_sha256'] != report['original_binary_sha256']
                result = subprocess.run([sys.executable, '-B', str(ROOT / 'scripts/rust-port/http_write_contract.py'),
                    '--rust', str(rust), '--receipt', str(mutant_receipt),
                    '--tls-output-probe-only', '--allow-dirty-for-development'], cwd=ROOT)
                observed = json.loads(mutant_receipt.read_text(encoding='utf-8'))
                assert result.returncode != 0 and observed['passed'] is False
                assert observed['primary_failure'] == dict(type='AssertionError', message='expired write resumed after fast client drain')
                assert observed['scope'] == 'tls-output-probe-only'
                assert observed['candidate_commit'] == report['candidate_commit']
                assert observed['rust_binary_sha256'] == report['mutant_binary_sha256']
                assert 'cleanup_failure' not in observed
                go = observed['go']['tls-output']['slow_output']
                broken = observed['rust']['tls-output']['slow_output']
                assert go['received_chunk_bytes'] < go['declared_chunk_length']
                assert broken['received_chunk_bytes'] >= broken['declared_chunk_length']
                assert broken['fast_drain_started_seconds'] >= 34
                assert broken['peer_terminal_observed'] and not broken['forced_client_close']
                report.update(passed=True, mutation_rejected=True, mutant_receipt=mutant_receipt.name)
            finally:
                source.write_bytes(original)
                shutil.copy2(saved, rust)
                report['restored'] = digest(source) == report['original_source_sha256'] and digest(rust) == report['original_binary_sha256']
                if not report['restored']:
                    report['passed'] = False
                    raise RuntimeError('mutation source/executable restoration failed')
    except BaseException as error:
        report.update(passed=False, failure_type=type(error).__name__)
        raise
    finally:
        receipt.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print('PASS: actual TLS output deadline mutation rejected; source and executable restored')


if __name__ == '__main__':
    main()
