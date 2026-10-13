"""The historical MCP oracle and its narrowly corrected, independent successor."""
import hashlib
import json
import ntpath
import os
from pathlib import Path
import platform
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


def tool_environment(env, build=False):
    # Do not expose ambient API/cloud tokens, agent sockets or proxy credentials
    # to a fixture CLI, its executor children, Go tests or build helpers.
    allowed = {'PATH','HOME','USERPROFILE','TMPDIR','TMP','TEMP','SYSTEMROOT',
               'WINDIR','COMSPEC','PATHEXT','LANG','LC_ALL','LC_CTYPE'}
    if build:
        allowed |= {'GOTOOLCHAIN','GOCACHE','GOMODCACHE','GOPATH','GOTMPDIR','GOPROXY','GOSUMDB'}
    return {key:value for key,value in env.items() if key.upper() in allowed}


def pinned_go(env, cwd):
    """Resolve before HOME isolation, then prohibit automatic compiler switching."""
    # Windows derives GOCACHE from LOCALAPPDATA, not HOME. Use these public
    # directory hints only during resolution; never expose them to test CLIs.
    cache_hints = {key.upper():value for key,value in env.items()
                   if key.upper() in {'LOCALAPPDATA','APPDATA'}}
    env = tool_environment(env, build=True)
    env.update(GOENV='off',GOWORK='off')
    version = subprocess.check_output(['go', 'env', 'GOVERSION'], cwd=cwd, env=env).decode().strip()
    if version != 'go1.26.6':
        raise ValueError('MCP oracle requires actual go1.26.6, got '+version)
    goroot = subprocess.check_output(['go', 'env', 'GOROOT'], cwd=cwd, env=env).decode().strip()
    go = Path(goroot)/'bin'/('go.exe' if os.name == 'nt' else 'go')
    local = dict(env, GOTOOLCHAIN='local', GOROOT=goroot, GOFLAGS='-p=2',GOMAXPROCS='2')
    # Nested generators also invoke "go" by name. Bind those to the resolved
    # compiler, not the product compiler that happened to launch this wrapper.
    local['PATH'] = str(go.parent)+os.pathsep+env.get('PATH',os.defpath)
    if subprocess.check_output([str(go), 'env', 'GOVERSION'], cwd=cwd, env=local).decode().strip() != version:
        raise ValueError('resolved compiler identity changed')
    keys=['GOHOSTOS','GOHOSTARCH','GOOS','GOARCH','GOFLAGS','GOEXPERIMENT',
          'GOAMD64','GOARM64','CGO_ENABLED','CC','CXX','GOTOOLCHAIN']
    settings=json.loads(subprocess.check_output([str(go),'env','-json',*keys],cwd=cwd,env=local))
    native_os={'Darwin':'darwin','Linux':'linux','Windows':'windows'}.get(platform.system())
    native_arch={'arm64':'arm64','aarch64':'arm64','x86_64':'amd64','AMD64':'amd64'}.get(platform.machine())
    if settings['GOOS'] != native_os or settings['GOARCH'] != native_arch:
        raise ValueError('Go target is not the actual native target')
    caches=json.loads(subprocess.check_output(
        [str(go),'env','-json','GOCACHE','GOMODCACHE','GOPATH'],
        cwd=cwd,env=dict(local,**cache_hints)))
    path_module = ntpath if native_os == 'windows' else os.path
    for key in ('GOCACHE','GOMODCACHE'):
        if not isinstance(caches[key],str) or not path_module.isabs(caches[key]):
            raise ValueError('Go cache must be an absolute controlled path: '+key)
    local.update(caches)
    local.update(GOOS=settings['GOOS'],GOARCH=settings['GOARCH'])
    return str(go), local, {'version':version, 'compiler_sha256':hashlib.sha256(go.read_bytes()).hexdigest(),
                           'build_settings':settings, 'cache_paths':caches}
