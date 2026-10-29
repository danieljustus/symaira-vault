#!/usr/bin/env python3
"""Exercise the exact github-script routing code with synthetic API/event controls."""
import json
import pathlib
import subprocess

root = pathlib.Path(__file__).resolve().parents[1]
workflow = root / '.github/workflows/macos-runner.yml'
text = workflow.read_text()
script = text.split('          script: |\n', 1)[1]
script = '\n'.join(line[12:] for line in script.splitlines())
labels = ['self-hosted', 'macOS', 'ARM64', 'macbook-symaira']
ready = dict(status='online', busy=False, labels=[dict(name=n) for n in labels])
cases = [
    ('same-repo idle', 'pull_request', 'owner/repo', [ready], False, True),
    ('fork idle', 'pull_request', 'fork/repo', [ready], False, False),
    ('push idle', 'push', '', [ready], False, True),
    ('dispatch idle', 'workflow_dispatch', '', [ready], False, True),
    ('schedule idle', 'schedule', '', [ready], False, True),
    ('busy', 'push', '', [dict(ready, busy=True)], False, False),
    ('offline', 'push', '', [dict(ready, status='offline')], False, False),
    ('API denied', 'push', '', [], True, False),
    ('unapproved event', 'pull_request_target', 'owner/repo', [ready], False, False),
]
for name, event, head, runners, denied, expected in cases:
    control = json.dumps(dict(event=event, head=head, runners=runners, denied=denied))
    harness = f'''
const test = {control};
let actual;
let calls = 0;
const context = {{repo: {{owner:'owner', repo:'repo'}}, eventName: test.event,
 payload: {{pull_request: {{head: {{repo: {{full_name:test.head}}}}}}}}}};
const core = {{info:()=>{{}}, warning:()=>{{}}, setOutput:(name,value)=>{{actual=JSON.parse(value)}},
 summary: {{addHeading(){{return this}},addRaw(){{return this}},async write(){{}}}}}};
const github = {{rest:{{actions:{{listSelfHostedRunnersForRepo:{{}}}}}},
 async paginate(){{calls++; if(test.denied)throw {{status:403}};return test.runners}}}};
process.env.HOSTED_RUNNER='macos-latest';
(async()=>{{
{script}
if(Array.isArray(actual)!=={str(expected).lower()})throw Error('unexpected target');
if(test.head==='fork/repo' && calls!==0)throw Error('fork queried local capacity');
console.log(JSON.stringify({{case:{json.dumps(name)},target:actual,apiCalls:calls}}));
}})().catch(e=>{{console.error(e);process.exit(1)}});
'''
    subprocess.run(['node', '-e', harness], check=True)
print(f'{len(cases)} synthetic routing controls passed')
