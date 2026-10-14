#!/usr/bin/env python3
"""Native controls only: no compiler, product suite or diagnostic admission."""
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import sys

import mcp_deadline_capture as capture
import mcp_deadline_diagnostic as diagnostic


def main():
    diagnostic.require(platform.system() == 'Linux' and platform.machine() == 'x86_64',
                       'native Linux/x86_64 required')
    diagnostic.require(os.environ.get('RUNNER_ENVIRONMENT') == 'github-hosted', 'hosted runner required')
    root = diagnostic.ROOT
    head = subprocess.check_output(['git','rev-parse','HEAD'],cwd=root,text=True).strip()
    diagnostic.require(head == os.environ['CONTROL_EXPECTED_SHA'], 'candidate mismatch')
    diagnostic.require(not subprocess.check_output(['git','status','--porcelain'],cwd=root), 'dirty candidate')
    sources = {str(p.relative_to(root)):hashlib.sha256(p.read_bytes()).hexdigest()
               for p in sorted((root/'scripts/rust-port').glob('*.py'))}
    output = Path(os.environ['RUNNER_TEMP'])/'rejected-fd-controls'
    output.mkdir(mode=0o700)
    receipt = {'scope':'native control tests only', 'head':head, 'os':platform.system(),
               'arch':platform.machine(), 'source_sha256':sources, 'passed':False,
               'diagnostic_dispatched':False, 'cases':[], 'errors':[]}
    try:
        env = dict(os.environ, TMPDIR=str(output), PYTHONDONTWRITEBYTECODE='1')
        code = diagnostic.run([sys.executable,'-B',str(root/'scripts/rust-port/test_mcp_deadline_diagnostic.py')],
                              env,output,'controls',120)
        diagnostic.require(code == 0, 'control suite failed')
        log = (output/'controls.stderr').read_text()
        diagnostic.require('Ran 39 tests' in log and '\nOK\n' in log and 'skipped' not in log,
                           'missing expected control inventory or native execution')
        receipt['control_tests'] = 39
        for kind in ('writable','readonly-on-rdwr','deleted'):
            private = output/kind
            private.mkdir(mode=0o700)
            (private/'build').mkdir()
            (private/'compiler-tmp').mkdir()
            name = os.fsencode(private/'build')+b'/native-\xff'
            child = ('import json,mmap,os\n'
                     f'name={name!r}\n'
                     'fd=os.open(name,os.O_CREAT|os.O_EXCL|os.O_RDWR,0o600)\n'
                     'os.ftruncate(fd,1)\n'
                     'st=os.fstat(fd)\n'
                     'print(json.dumps(dict(pid=os.getpid(),device=st.st_dev,inode=st.st_ino)),flush=True)\n'
                     + ('os.unlink(name)\n' if kind == 'deleted' else '')
                     + f'view=mmap.mmap(fd,1,flags=mmap.MAP_SHARED,prot={1 if kind == "readonly-on-rdwr" else 3})\n'
                     'print("MAPPING_EXECUTED",flush=True)\n')
            directory = private/'capture'
            command = [sys.executable,'-B',str(Path(capture.__file__)),str(private),str(directory),
                       '--',sys.executable,'-B','-c',child]
            code = diagnostic.run(command,env,output,kind,60)
            run = json.loads((output/(kind+'.json')).read_bytes())
            data = json.loads((directory/'capture.json').read_bytes())
            raw = (output/(kind+'.stdout')).read_bytes()
            diagnostic.require(code == 1 and not run['timeout'] and run['cleanup']['complete'],
                               'missing bounded rejection/owned-child cleanup')
            diagnostic.require(b'MAPPING_EXECUTED' not in raw, 'rejected syscall resumed')
            identity = json.loads(raw.strip())
            diagnostic.require(data['complete'] is False and data['acceptance'] is False and data['errors'],
                               'rejected capture admitted')
            row = data['rejected_fd_observation']
            expected = name+(b' (deleted)' if kind == 'deleted' else b'')
            for label in ('snapshot_a','snapshot_b'):
                snapshot = row[label]
                diagnostic.require(bytes.fromhex(snapshot['path_hex']) == expected, 'path bytes changed')
                diagnostic.require(all(snapshot['stat'][key] == identity[key] for key in ('device','inode'))
                                   and snapshot['stat']['size'] == 1, 'descriptor identity mismatch')
            diagnostic.require(row['pid'] == identity['pid'] and row['evidence_role'] == 'diagnostic_only'
                               and row['ownership_proven'] is False and row['snapshot_consistency'] == 'equal'
                               and not row['errors'] and not row['truncated'], 'invalid observation')
            events = [json.loads(line) for line in (directory/'syscalls.jsonl').read_bytes().split(b'\n') if line]
            calls = [item for item in events if 'op' in item]
            diagnostic.require(calls[-1] == {'event':row['event'],'pid':row['pid'],'op':1,'values':row['values']},
                               'observation not bound to final rejected entry')
            diagnostic.require(not Path(f'/proc/{identity["pid"]}').exists(), 'tracee still present after reaping')
            receipt['cases'].append({'name':kind,'passed':True,'event':row['event'],
                                     'cleanup':run['cleanup'],'capture_complete':data['complete']})
        diagnostic.require(len(receipt['cases']) == 3, 'incomplete case inventory')
        diagnostic.require(all(hashlib.sha256((root/name).read_bytes()).hexdigest() == value
                               for name,value in sources.items()), 'source changed during controls')
        receipt['passed'] = True
    except Exception as error:
        receipt['errors'].append(str(error))
        raise
    finally:
        diagnostic.save(output/'receipt.json',receipt)
        print(json.dumps(receipt,indent=2))


if __name__ == '__main__':
    main()
