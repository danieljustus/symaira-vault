"""The historical MCP oracle and its narrowly corrected, independent successor."""
import hashlib
import os
from pathlib import Path
import re
import subprocess

HISTORICAL = 'd1cd0f97ac550bc3020bc86b0514989f8d28d95c'
ORDERED = '24acdb08fcc7021262717aa803d72eb8d151c66a'
CONTRACT = 'mcp-anomaly-ordered-v1'
REPAIR_FILES = ('internal/mcp/server/server.go',
                'internal/mcp/server/server_dispatch.go',
                'internal/mcp/server/server_anomaly_test.go')


def git(root, *args):
    return subprocess.check_output(['git', *args], cwd=root)


def validate_reference(root, commit=ORDERED):
    # No caller-selected branch, short SHA or moving ref can become an oracle.
    if not isinstance(commit, str) or not re.fullmatch('[0-9a-f]{40}', commit):
        raise ValueError('oracle requires a full lowercase commit SHA')
    if commit != ORDERED:
        raise ValueError('unknown corrected oracle')
    if git(root, 'rev-parse', commit+'^').decode().strip() != HISTORICAL:
        raise ValueError('corrected oracle must have the historical oracle as parent')
    changed = git(root, 'diff', '--name-only', HISTORICAL, commit).decode().splitlines()
    if set(changed) != set(REPAIR_FILES):
        raise ValueError('corrected oracle changed files outside the reviewed repair')
    for name in REPAIR_FILES:
        if (Path(root)/name).read_bytes() != git(root, 'show', commit+':'+name):
            raise ValueError('candidate differs from corrected oracle: '+name)


def inventory(root, names):
    return {name: hashlib.sha256((Path(root)/name).read_bytes()).hexdigest()
            for name in sorted(names)}


def pinned_go(env, cwd):
    """Resolve before HOME isolation, then prohibit automatic compiler switching."""
    version = subprocess.check_output(['go', 'env', 'GOVERSION'], cwd=cwd, env=env).decode().strip()
    if version != 'go1.26.6':
        raise ValueError('MCP oracle requires actual go1.26.6, got '+version)
    goroot = subprocess.check_output(['go', 'env', 'GOROOT'], cwd=cwd, env=env).decode().strip()
    go = Path(goroot)/'bin'/('go.exe' if os.name == 'nt' else 'go')
    local = dict(env, GOTOOLCHAIN='local', GOROOT=goroot, GOENV='off', GOWORK='off')
    if subprocess.check_output([str(go), 'env', 'GOVERSION'], cwd=cwd, env=local).decode().strip() != version:
        raise ValueError('resolved compiler identity changed')
    return str(go), local, {'version':version, 'compiler_sha256':hashlib.sha256(go.read_bytes()).hexdigest()}
