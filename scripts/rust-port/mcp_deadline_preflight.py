#!/usr/bin/env python3
"""Separate hosted Linux compiler/capture probe; never a product diagnostic."""
import json
import os
from pathlib import Path
import platform
import subprocess
import sys

import mcp_deadline_diagnostic as diagnostic
from mcp_deadline_capture import require, verify_self_maps


def main():
    require(not sys.flags.optimize, 'unoptimized Python required')
    require(platform.system() == 'Linux' and platform.machine() == 'x86_64',
            'native Linux/x86_64 preflight required')
    require(os.environ.get('RUNNER_ENVIRONMENT') == 'github-hosted', 'hosted runner required')
    require('DEADLINE_PYTHON' not in os.environ and not os.environ.get('DEADLINE_REVIEW'),
            'compiler preflight must not run inside the diagnostic lane')
    head = diagnostic.git(diagnostic.ROOT,'rev-parse','HEAD').decode().strip()
    require(head == os.environ.get('PREFLIGHT_EXPECTED_SHA'), 'preflight source mismatch')
    output = diagnostic.ROOT/'target/deadline-compiler-preflight'
    output.mkdir(mode=0o700,parents=True)  # Never overwrite prior evidence.
    receipt = {'candidate':head, 'scope':'minimal compiler/capture compatibility only',
               'acceptance':False, 'passed':False, 'phases':[], 'errors':[]}
    try:
        query_env = {k:os.environ[k] for k in ('PATH','HOME','RUSTUP_HOME') if k in os.environ}
        query_env['RUSTUP_AUTO_INSTALL'] = '0'
        rustc = Path(subprocess.check_output(
            ['rustup','which','--toolchain','1.98.0','rustc'],
            env=query_env,text=True,timeout=30).strip()).resolve(strict=True)
        receipt['rustc'] = {'path':str(rustc),'sha256':diagnostic.digest(rustc)}
        receipt['capture_sha256'] = diagnostic.digest(Path(__file__).with_name('mcp_deadline_capture.py'))
        base = Path(os.environ['RUNNER_TEMP'])/'deadline-compiler-preflight'
        base.mkdir(mode=0o700)
        for phase in ('metadata','link'):
            private = base/phase
            private.mkdir(mode=0o700)
            for leaf in ('home','config','data','cache','runtime','tmp','build','compiler-tmp'):
                (private/leaf).mkdir(mode=0o700)
            env = dict(PATH=os.pathsep.join([str(rustc.parent),str(Path(sys.executable).parent),'/usr/bin','/bin']),
                       HOME=str(private/'home'), XDG_CONFIG_HOME=str(private/'config'),
                       XDG_DATA_HOME=str(private/'data'), XDG_CACHE_HOME=str(private/'cache'),
                       XDG_RUNTIME_DIR=str(private/'runtime'), TMPDIR=str(private/'compiler-tmp'),
                       TMP=str(private/'compiler-tmp'), TEMP=str(private/'compiler-tmp'),
                       LANG='C.UTF-8', LC_ALL='C.UTF-8', TZ='UTC', PYTHONDONTWRITEBYTECODE='1')
            source = private/'probe.rs'
            source.write_text('fn main() {}\n')
            product = private/'build'/('probe.rmeta' if phase == 'metadata' else 'probe')
            command = [str(rustc),'--crate-name','deadline_capture_preflight','--edition=2021',
                       str(source),'--emit='+phase,'-o',str(product)]
            row = {'phase':phase,'command':command,'source_sha256':diagnostic.digest(source),
                   'passed':False,'errors':[]}
            receipt['phases'].append(row)
            try:
                if phase == 'metadata':
                    require(diagnostic.run([str(rustc),'-vV'],env,output,'rustc-version',30) == 0,
                            'compiler version query failed')
                    require('release: 1.98.0\n' in (output/'rustc-version.stdout').read_text(),
                            'unexpected compiler version')
                directory = output/(phase+'-capture')
                traced = [sys.executable,'-B',str(Path(__file__).with_name('mcp_deadline_capture.py')),
                          str(private),str(directory),'--',*command]
                row['exit'] = diagnostic.run(traced,env,output,phase,120)
                data = json.loads((directory/'capture.json').read_bytes())
                row['capture_errors'] = data['errors']
                require(data['command'] == command and row['exit'] == 0 and data['complete']
                        and data['command_exit'] == 0 and not data['errors'], 'compiler capture incomplete')
                with (directory/'syscalls.jsonl').open() as stream:
                    verify_self_maps(directory,data,(json.loads(line) for line in stream))
                require(diagnostic.digest(source) == row['source_sha256'], 'probe source changed')
                require(product.is_file() and product.stat().st_size > 0, 'compiler output absent')
                if phase == 'link':
                    with product.open('rb') as stream:
                        require(stream.read(4) == b'\x7fELF', 'linked output is not ELF')
                row['output_sha256'] = diagnostic.digest(product)
                # Bind observed executable files, including the default linker;
                # paths alone are not a claim about which image was executed.
                row['observed_executable_files'] = {p:diagnostic.digest(Path(p)) for p in data['observed']
                    if Path(p).is_file() and os.access(p,os.X_OK)}
                row['passed'] = True
            except Exception as error:
                row['errors'].append(str(error))
        receipt['passed'] = len(receipt['phases']) == 2 and all(r['passed'] for r in receipt['phases'])
    except Exception as error:
        receipt['errors'].append(str(error))
    finally:
        diagnostic.save(output/'preflight.json',receipt)
    print(json.dumps(receipt,indent=2))
    return 0 if receipt['passed'] else 1


if __name__ == '__main__':
    sys.exit(main())
