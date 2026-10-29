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
cases.append(('secret empty', 'push', '', [ready], False, False))
for name, event, head, runners, denied, expected in cases:
    control = json.dumps(dict(event=event, head=head, runners=runners, denied=denied, token=name != 'secret empty'))
    harness = f'''
const test = {control};
let actual;
let calls = 0;
const context = {{repo: {{owner:'owner', repo:'repo'}}, eventName: test.event,
 payload: {{pull_request: {{head: {{repo: {{full_name:test.head}}}}}}}}}};
const core = {{info:()=>{{}}, warning:()=>{{}}, setOutput:(name,value)=>{{actual=JSON.parse(value)}},
 summary: {{addHeading(){{return this}},addRaw(){{return this}},async write(){{}}}}}};
global.fetch = async (url, options)=>{{
 calls++;
 if(options.headers.Authorization !== 'Bearer synthetic-test-token')throw Error('wrong inventory credential');
 return {{status:test.denied?403:200,ok:!test.denied,json:async()=>({{runners:test.runners}})}};
}};
process.env.GH_TOKEN=test.token?'synthetic-test-token':'';
process.env.HOSTED_RUNNER='macos-latest';
(async()=>{{
{script}
if(Array.isArray(actual)!=={str(expected).lower()})throw Error('unexpected target');
if((test.head==='fork/repo' || !test.token) && calls!==0)throw Error('ineligible inventory request');
if(JSON.stringify(actual)!==JSON.stringify({json.dumps(labels) if expected else json.dumps('macos-latest')}))throw Error('incorrect runner selector');
console.log(JSON.stringify({{case:{json.dumps(name)},target:actual,apiCalls:calls}}));
}})().catch(e=>{{console.error(e);process.exit(1)}});
'''
    subprocess.run(['node', '-e', harness], check=True)
print(f'{len(cases)} synthetic routing controls passed')
