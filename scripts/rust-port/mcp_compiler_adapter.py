"""Narrow, source-bound compiler preparation for immutable MCP generators."""
import hashlib
import json
import os
from pathlib import Path
import subprocess

from mcp_oracle import inventory, tool_environment

VERSION = 'mcp-historical-compiler-prerequisites-v2'
SOURCES = ('scripts/rust-port/mcp_compiler_adapter.py',
           'scripts/rust-port/mcp_compiler_adapter.go.txt')
PREREQUISITES = ('GOCACHE', 'GOMODCACHE', 'GOPATH', 'GOROOT')


def prepare(go, env, tree, output, steps, run_step):
    """Compile a private PATH adapter; never overlay the historical source tree."""
    output.mkdir(mode=0o700)
    compiler = Path(go).resolve(strict=True)
    prerequisites = {key: env[key] for key in PREREQUISITES}
    for key, value in prerequisites.items():
        if not Path(value).is_absolute():
            raise ValueError('adapter prerequisite must be absolute: '+key)
        prerequisites[key] = str(Path(value).resolve(strict=True))
    prerequisites.update(GOTOOLCHAIN='local', GOENV='off', GOWORK='off',
                         GOFLAGS='-p=2', GOMAXPROCS='2')
    if compiler != Path(prerequisites['GOROOT'])/'bin'/('go.exe' if os.name=='nt' else 'go'):
        raise ValueError('adapter compiler is outside resolved GOROOT')
    if subprocess.check_output([str(compiler),'env','GOVERSION'],cwd=tree,env=env).strip()!=b'go1.26.6':
        raise ValueError('adapter requires actual go1.26.6 in isolated HOME')
    child = (tree/'scripts/rust-port/cmd/execute_secret_child/main.go').resolve(strict=True)
    if not child.is_file() or not child.is_relative_to(tree.resolve(strict=True)):
        raise ValueError('adapter child must be an existing file inside the oracle tree')
    config = {'compiler':str(compiler),
              'compiler_sha256':hashlib.sha256(compiler.read_bytes()).hexdigest(),
              'child_source':str(child),
              'child_source_sha256':hashlib.sha256(child.read_bytes()).hexdigest(),
              'environment':prerequisites, 'trace':str(output/'invocations.jsonl')}
    # Bind all toolchain files, not a selected source list. The adapter build is
    # stdlib-only (CGO disabled); no module, embed or external library is omitted.
    goroot=Path(prerequisites['GOROOT'])
    toolchain=inventory(goroot,[p.relative_to(goroot).as_posix() for p in goroot.rglob('*') if p.is_file()])
    (output/'toolchain-inputs.json').write_text(json.dumps(toolchain,indent=2)+'\n')
    template=Path(__file__).with_suffix('.go.txt')
    (output/'main.go').write_bytes(template.read_bytes())
    (output/'config.go').write_text('package main\n\nconst configJSON = '+json.dumps(json.dumps(config,sort_keys=True))+'\n')
    executable=output/('go.exe' if os.name=='nt' else 'go')
    build_env=tool_environment(env,build=True)
    build_env.update(prerequisites,CGO_ENABLED='0',GO111MODULE='off')
    source_inputs=inventory(output,['main.go','config.go','toolchain-inputs.json'])
    command=[str(compiler),'build','-trimpath','-o',str(executable),'main.go','config.go']
    run_step(command,output,build_env,output,'build',steps)
    run_step([str(compiler),'version','-m',str(executable)],output,build_env,output,'build-info',steps)
    row={'version':VERSION,'configuration':config,'build_environment':build_env,
         'source_inputs':source_inputs,'binary':str(executable),
         'binary_sha256':hashlib.sha256(executable.read_bytes()).hexdigest(),
         'toolchain_files':len(toolchain)}
    (output/'preparation.json').write_text(json.dumps(row,indent=2)+'\n')
    return dict(env,PATH=str(output)+os.pathsep+env['PATH']),row


def verify(row):
    executable=Path(row['binary'])
    output=executable.parent
    if hashlib.sha256(executable.read_bytes()).hexdigest()!=row['binary_sha256']:
        raise ValueError('adapter binary changed')
    if inventory(output,row['source_inputs'])!=row['source_inputs']:
        raise ValueError('adapter build inputs changed')
    config=row['configuration']
    goroot=Path(config['environment']['GOROOT'])
    expected=json.loads((output/'toolchain-inputs.json').read_bytes())
    if inventory(goroot,[p.relative_to(goroot).as_posix() for p in goroot.rglob('*') if p.is_file()])!=expected:
        raise ValueError('adapter toolchain inputs changed')
    calls=[json.loads(line) for line in Path(config['trace']).read_text().splitlines()]
    if len(calls)!=1:
        raise ValueError('expected one real filtered compiler invocation')
    call=calls[0]
    command=call['command']
    child=Path(config['child_source'])
    if (len(command)!=3 or command[:2]!=[config['compiler'],'run'] or call['exit']!=0
            or not Path(command[2]).is_absolute() or not Path(command[2]).samefile(child)):
        raise ValueError('historical compiler invocation failed or changed')
    if (hashlib.sha256(child.read_bytes()).hexdigest()!=config['child_source_sha256']
            or call['child_source_sha256']!=config['child_source_sha256']):
        raise ValueError('historical child source identity drift')
    if call['compiler_sha256']!=config['compiler_sha256']:
        raise ValueError('historical compiler identity drift')
    keys=set(map(str.upper,call['input_keys']))
    # The real filter must still discard compiler settings. The adapter must
    # not receive ambient credentials/proxies, or replace intentional injection.
    allowed={'PATH','HOME','TMPDIR','TEMP','TMP','LANG','LC_ALL','SYSTEMROOT',
             'GITHUB_PASSWORD','PLAIN'}
    if not {'GITHUB_PASSWORD','PLAIN'}<=keys or keys-allowed:
        raise ValueError('unexpected filtered compiler environment: '+repr(sorted(keys)))
    row['invocations']=calls
    row['verified']=True
