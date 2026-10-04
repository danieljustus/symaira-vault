#!/usr/bin/env python3
"""Capture/recheck real Go CLI artifacts; verify the standalone Rust surface."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import shlex
import subprocess
import tempfile
import urllib.request

ROOT = Path(__file__).resolve().parents[2]
PIN = "55da4ca13ead39d4000cf6f866ac8671ca86d8f2"
ARTIFACT = ROOT / "testdata/port/cli/artifacts.json"
PROBE = ROOT / "scripts/rust-port/cli_artifacts_probe.go.txt"
BASH_COMPLETION_COMMIT = "79d225bad8939a3833314b5af93509131c03f2f8"
BASH_COMPLETION_SHA256 = "f347b832c91d44358bb335e69fa7576241d67040795a1a4d8897317c739d35b1"
BASH_COMPAT_SHA256 = "ffe73ddfefc93936eae2a8aac8a3f749da8ed160485717393a272e84f9c754e2"


def execute(args, cwd, env, data=None):
    result = subprocess.run([str(a) for a in args], cwd=cwd, env=env,
                            input=data, capture_output=True, timeout=120)
    if result.returncode:
        raise RuntimeError(f"{args[0]} failed ({result.returncode}): "
                           + result.stderr.decode(errors="replace")[-3000:])
    return result


def requests(commands):
    result = []
    for command in ["get", "show", "cat", "list", "ls", "find", "delete", "set", "add", "edit"]:
        for prefix in ["", "alpha", "missing"]:
            result.append({"name": f"{command}-{prefix or 'all'}", "args": [command, prefix], "state": "cached"})
    for state in ["absent", "locked", "malformed", "expired"]:
        result.append({"name": f"get-{state}", "args": ["get", "alpha"], "state": state})
    result.append({"name": "get-second-argument", "args": ["get", "alpha/account", ""], "state": "cached"})
    for c in commands:
        for prefix in ["", "-", "--h"]:
            result.append({"name": f"{c['path']}/{prefix}", "args": c['path'].split()[1:]+[prefix], "state": "absent"})
    return result


def capture(tree, base, env):
    binary = base / ("go.exe" if os.name == "nt" else "go")
    execute(["go", "build", "-trimpath", "-buildvcs=false", "-o", binary, "."], tree, env)
    helper = tree / "scripts/rust-port/cmd/cli004probe"
    helper.mkdir()
    (helper / "main.go").write_bytes(PROBE.read_bytes())
    metadata = json.loads(execute(["go", "run", "./scripts/rust-port/cmd/cli004probe", "tree"], tree, env).stdout)
    commands = metadata['commands']
    help_pages = {}
    paths = [c["path"] for c in commands]
    for path in sorted(set(paths)):
        result = execute([binary, *path.split()[1:], "--help"], base, env)
        assert not result.stderr, path
        help_pages[path] = result.stdout.decode().replace(metadata['config_path'],'__CONFIG_PATH__')
    completions = {}
    for shell in ["bash", "zsh", "fish", "powershell"]:
        for plain in [False, True]:
            args = [binary, "completion", shell]
            if plain:
                args.append("--no-descriptions")
            result = execute(args, base, env)
            assert not result.stderr
            completions[f"{shell}/{'plain' if plain else 'descriptions'}"] = result.stdout.decode()
    man_dir = base / "man"
    result = execute([binary, "generate", "manpages", man_dir], base, env)
    assert not result.stderr
    manpages = {p.name: p.read_text().replace(metadata['config_path'],'__CONFIG_PATH__') for p in sorted(man_dir.glob("*.1"))}
    seeded = execute(["go", "run", "./scripts/rust-port/cmd/cli004probe"], tree, env,
                     json.dumps(requests(commands)).encode())
    observations = json.loads(seeded.stdout)
    assert len(observations) == len(requests(commands)) and all(not c.get("error") for c in observations)
    assert "alpha/account\n" in observations[0]["stdout"], "dynamic Go completion must execute real session/store reads"
    for c in observations:
        assert "public-fixture" not in c["stdout"]
    sources = subprocess.check_output(["git", "ls-tree", "-r", "--name-only", PIN], cwd=tree, text=True).splitlines()
    sources = sorted(p for p in sources if p in {"go.mod", "go.sum"} or (p.endswith(".go") and not p.endswith("_test.go")))
    digest = hashlib.sha256()
    for path in sources:
        digest.update(path.encode() + b"\0" + (tree / path).read_bytes() + b"\0")
    return {"schema_version": 1, "oracle_commit": PIN, "oracle_source_files": sources,
            "oracle_source_digest": digest.hexdigest(), "probe_sha256": hashlib.sha256(PROBE.read_bytes()).hexdigest(),
            "commands": commands, "config_keys": metadata['config_keys'], "help": help_pages, "completions": completions,
            "manpages": manpages, "entry_completions": observations}, binary


def verify_rust(binary, artifact, base, env):
    counts = {}
    config_path = str(Path(env['XDG_CONFIG_HOME'])/'symaira-vault/config.yaml')
    for path, expected in artifact['help'].items():
        result = execute([binary, *path.split()[1:], '--help'], base, env)
        assert result.stdout.decode().replace(config_path,'__CONFIG_PATH__') == expected and not result.stderr, ('help', path)
    counts['help_pages'] = len(artifact['help'])
    for key, expected in artifact['completions'].items():
        shell, mode = key.split('/')
        args = [binary, 'completion', shell]
        if mode == 'plain': args.append('--no-descriptions')
        result = execute(args, base, env)
        assert result.stdout == expected.encode() and not result.stderr, ('script', key)
    counts['scripts'] = len(artifact['completions'])
    man = base / 'rust-man'
    result = execute([binary, 'generate', 'manpages', man], base, env)
    assert not result.stderr
    actual = {p.name: p.read_text().replace(config_path,'__CONFIG_PATH__') for p in sorted(man.glob('*.1'))}
    assert actual == artifact['manpages'], 'all manual filenames and bytes must match real Go'
    counts['manuals'] = len(actual)
    queries = [c for c in artifact['entry_completions'] if c['state'] == 'absent']
    for case in queries:
        result = execute([binary, '--vault', base / 'absent-vault', '__complete', *case['args']], base, env)
        assert result.stdout.decode() == case['stdout'], ('protocol', case['name'], result.stdout)
        assert result.stderr.decode() == case['stderr'], ('protocol stderr', case['name'])
    counts['actual_cli_queries'] = len(queries)
    assert not (base / 'absent-vault').exists(), 'completion must never unlock or initialize a vault'
    return counts


def terminal_completion(shell, setup, base, env):
    # Real Tab completion needs the shell's completion context (not a mocked
    # compadd/compopt function). The Unix native jobs use an actual PTY.
    import errno
    import pty
    import select
    import time
    master, slave = pty.openpty()
    process = subprocess.Popen([shell, '-f' if Path(shell).name == 'zsh' else '--norc', '-i'],
                               cwd=base, env=dict(env, TERM='dumb'),
                               stdin=slave, stdout=slave, stderr=slave, start_new_session=True)
    os.close(slave)

    def read_until(marker):
        output = b''
        deadline = time.monotonic() + 10
        while marker not in output and time.monotonic() < deadline:
            if not select.select([master], [], [], .1)[0]:
                continue
            try:
                chunk = os.read(master, 65536)
            except OSError as error:
                if error.errno != errno.EIO: raise
                break
            if not chunk: break
            output += chunk
        assert marker in output, ('actual shell completion timed out', output)
        return output

    try:
        os.write(master, (setup + '; printf "\\nSHELL-%s\\n" READY\n').encode())
        read_until(b'SHELL-READY')
        os.write(master, b'symvault g\t\t')
        output = read_until(b'generate')
        # Both names may arrive in separate terminal writes.
        if b'get' not in output:
            output += read_until(b'get')
        while select.select([master], [], [], .2)[0]:
            output += os.read(master, 65536)
        screen = output.decode(errors='replace').replace('\r', '')
        return {'screen':screen,
                'candidates':[line.strip() for line in screen.splitlines()
                              if re.match(r'^(?:generate|get|git)\s',line)]}
    finally:
        os.write(master, b'\x15exit\n')
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            process.terminate()
            process.wait(timeout=3)
        os.close(master)


def verify_shells(go, rust, artifact, base, env, require_native_shells):
    # Execute the same generated script against each actual binary. Disposable
    # PATH directories make the script resolve exactly the selected candidate.
    scripts = base / 'shell-scripts'
    scripts.mkdir()
    script = scripts / 'symvault.bash'
    script.write_text(artifact['completions']['bash/descriptions'])
    bash = os.environ.get('CLI_ARTIFACTS_BASH') or shutil.which('bash')
    assert bash, 'actual Bash completion execution is required on every runner'
    # Cobra's compatibility fallback calls the real bash-completion library.
    # Download only a test prerequisite; it is not embedded in the executable.
    library = scripts / 'bash_completion'
    url = f'https://raw.githubusercontent.com/scop/bash-completion/{BASH_COMPLETION_COMMIT}/bash_completion'
    with urllib.request.urlopen(url, timeout=30) as response:
        data = response.read()
    assert hashlib.sha256(data).hexdigest() == BASH_COMPLETION_SHA256
    library.write_bytes(data)
    compat = scripts / 'bash_completion.d'
    compat.mkdir()
    url = f'https://raw.githubusercontent.com/scop/bash-completion/{BASH_COMPLETION_COMMIT}/bash_completion.d/000_bash_completion_compat.bash'
    with urllib.request.urlopen(url, timeout=30) as response:
        data = response.read()
    assert hashlib.sha256(data).hexdigest() == BASH_COMPAT_SHA256
    (compat / '000_bash_completion_compat.bash').write_bytes(data)
    command = 'source "$1"; source "$2"; COMP_WORDS=(symvault g); COMP_CWORD=1; COMP_LINE="symvault g"; COMP_POINT=${#COMP_LINE}; __start_symvault; printf "%s\\n" "${COMPREPLY[@]}"'
    results = []
    for name, binary in [('go',go),('rust',rust)]:
        directory = base / f'{name}-shell-bin'
        directory.mkdir()
        executable = directory / ('symvault.exe' if os.name == 'nt' else 'symvault')
        shutil.copy2(binary, executable)
        shell_env = dict(env, PATH=str(directory)+os.pathsep+env['PATH'],
                         BASH_COMPLETION_COMPAT_DIR=str(compat), BASH_COMPLETION_USER_FILE='/dev/null')
        result = execute([bash,'--noprofile','--norc','-c',command,'contract',library,script],base,shell_env)
        results.append(result.stdout)
    assert results[0] == results[1] and b'get' in results[0] and b'generate' in results[0], ('actual sourced Bash scripts must return the same candidates', results)
    proof = {'bash': {'go':results[0].decode(),'rust':results[1].decode(),
                     'library_commit':BASH_COMPLETION_COMMIT,
                     'library_sha256':BASH_COMPLETION_SHA256,
                     'compat_sha256':BASH_COMPAT_SHA256}}
    if os.name != 'nt':
        for shell in ['bash', 'zsh']:
            executable = bash if shell == 'bash' else shutil.which(shell)
            assert executable, f'actual {shell} is required on Unix native runners'
            script = scripts / f'symvault.{shell}'
            script.write_text(artifact['completions'][shell+'/descriptions'])
            setup = (f'PS1="contract> "; source {shlex.quote(str(library))}' if shell == 'bash'
                     else 'PROMPT="contract> "; RPROMPT=""; autoload -Uz compinit; compinit -D')
            setup += '; source ' + shlex.quote(str(script))
            results = []
            for name in ['go','rust']:
                shell_env = dict(env, PATH=str(base/f'{name}-shell-bin')+os.pathsep+env['PATH'],
                                 BASH_COMPLETION_COMPAT_DIR=str(compat), BASH_COMPLETION_USER_FILE='/dev/null')
                results.append(terminal_completion(executable, setup, base, shell_env))
            candidates = results[0]['candidates']
            assert candidates == results[1]['candidates'] and any(c.startswith('get ') for c in candidates) and any(c.startswith('generate ') for c in candidates), (shell, results)
            proof.setdefault(shell, {})['terminal'] = {'go':results[0],'rust':results[1]}
        fish = shutil.which('fish')
        assert fish or not require_native_shells, 'actual Fish is required for native Unix acceptance'
        if fish:
            script = scripts / 'symvault.fish'
            script.write_text(artifact['completions']['fish/descriptions'])
            results = []
            for name in ['go','rust']:
                shell_env = dict(env, PATH=str(base/f'{name}-shell-bin')+os.pathsep+env['PATH'])
                command = f'source {shlex.quote(str(script))}; complete --do-complete "symvault g"'
                results.append(execute([fish,'--no-config','-c',command],base,shell_env).stdout)
            assert results[0] == results[1] and b'get' in results[0] and b'generate' in results[0], ('fish',results)
            proof['fish'] = {'go':results[0].decode(),'rust':results[1].decode()}
    if platform.system() == 'Windows':
        pwsh = shutil.which('pwsh')
        assert pwsh, 'native PowerShell completion is required on Windows'
        ps = scripts / 'symvault.ps1'
        ps.write_text(artifact['completions']['powershell/descriptions'])
        # Register and exercise the native argument completer through the real
        # PowerShell completion API; no script-format heuristic substitutes.
        probe = scripts / 'probe.ps1'
        probe.write_text('param([string]$Script)\n. $Script\n(TabExpansion2 -inputScript "symvault g" -cursorColumn 10).CompletionMatches | ForEach-Object { $_.CompletionText }\n')
        results = []
        for name in ['go','rust']:
            shell_env = dict(env, PATH=str(base/f'{name}-shell-bin')+os.pathsep+env['PATH'])
            results.append(execute([pwsh,'-NoProfile','-NonInteractive','-File',probe,str(ps)],base,shell_env).stdout)
        assert results[0] == results[1] and b'get' in results[0] and b'generate' in results[0]
        proof['powershell'] = {'go':results[0].decode(),'rust':results[1].decode()}
    return proof


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--capture", action="store_true")
    parser.add_argument("--rust", type=Path)
    parser.add_argument("--receipt", type=Path)
    parser.add_argument("--allow-dirty-for-development", action="store_true")
    parser.add_argument("--require-native-shells", action="store_true")
    args = parser.parse_args()
    clean = not subprocess.check_output(['git','status','--porcelain=v1','--untracked-files=normal'],cwd=ROOT).strip()
    if args.rust:
        assert args.receipt, 'a source/binary receipt is required for native acceptance'
        assert clean or args.allow_dirty_for_development, 'commit the candidate before recording acceptance'
    with tempfile.TemporaryDirectory(prefix="symvault-cli-artifacts-") as raw:
        base = Path(raw)
        home = base / "home"
        home.mkdir()
        env = {k: v for k, v in os.environ.items() if not k.startswith("SYMVAULT_")}
        env.update(HOME=str(home), USERPROFILE=str(home), XDG_CONFIG_HOME=str(home / "config"),
                   XDG_DATA_HOME=str(home / "data"), XDG_CACHE_HOME=str(home / "cache"),
                   SYMVAULT_TEST_KEYRING="memory", TZ="UTC", SOURCE_DATE_EPOCH="0")
        tree = base / "oracle"
        execute(["git", "worktree", "add", "--detach", tree, PIN], ROOT, os.environ.copy())
        try:
            artifact, go = capture(tree, base, env)
            if args.capture:
                ARTIFACT.write_text(json.dumps(artifact, ensure_ascii=False, indent=2) + "\n")
            else:
                expected = json.loads(ARTIFACT.read_text())
                if artifact != expected:
                    changed = [key for key in artifact if artifact[key] != expected.get(key)]
                    print('Changed artifact sections:', changed)
                    for key in changed:
                        left, right = expected.get(key), artifact[key]
                        if isinstance(right, dict):
                            print(key, [k for k in right if left.get(k) != right[k]][:12])
                        elif isinstance(right, list):
                            print(key, [(i,str(a)[:220],str(b)[:220]) for i,(a,b) in enumerate(zip(left,right)) if a!=b][:8])
                        else: print(key, str(left)[:220],str(right)[:220])
                    raise AssertionError('actual immutable Go CLI artifacts changed')
            if args.rust:
                rust = args.rust.resolve()
                counts = verify_rust(rust, artifact, base, env)
                shells = verify_shells(go,rust,artifact,base,env,args.require_native_shells)
                candidate_files = subprocess.check_output(['git','ls-files','--cached','--others','--exclude-standard'],cwd=ROOT,text=True).splitlines()
                candidate_files = sorted(p for p in candidate_files if (p.startswith(('crates/','third_party/','testdata/')) and p.endswith(('.rs','.toml','.lock','.json','.txt'))) or p.startswith('scripts/rust-port/cmd/cligap/') or p in {'Cargo.toml','Cargo.lock','scripts/rust-port/cli_artifacts_contract.py','scripts/rust-port/cli_artifacts_probe.go.txt','.github/workflows/rust-cli-artifacts.yml'})
                digest = hashlib.sha256()
                for path in candidate_files:
                    digest.update(path.encode()+b'\0'+(ROOT/path).read_bytes()+b'\0')
                receipt = {'passed': True, 'candidate_commit':subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip(),
                    'candidate_worktree_clean':clean,'candidate_source_files':candidate_files,'candidate_source_digest':digest.hexdigest(),
                    'oracle_commit':PIN,'oracle_source_files':artifact['oracle_source_files'],'oracle_source_digest':artifact['oracle_source_digest'],
                    'probe_sha256':artifact['probe_sha256'],'driver_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                    'go_binary_sha256':hashlib.sha256(go.read_bytes()).hexdigest(),'rust_binary_sha256':hashlib.sha256(rust.read_bytes()).hexdigest(),
                    'native_os':platform.system(),'architecture':platform.machine(),'keyring':'memory','actual_counts':counts,
                    'go_protocol_observations':artifact['entry_completions'],'actual_shells':shells}
                args.receipt.write_text(json.dumps(receipt,indent=2)+'\n')
                print(f'PASS actual Go/Rust CLI artifacts: {counts}')
            else:
                print(f"PASS actual Go capture: {len(artifact['help'])} help pages, {len(artifact['completions'])} scripts, {len(artifact['manpages'])} manuals, {len(artifact['entry_completions'])} protocol queries")
        finally:
            execute(["git", "worktree", "remove", "--force", tree], ROOT, os.environ.copy())


if __name__ == "__main__":
    main()
