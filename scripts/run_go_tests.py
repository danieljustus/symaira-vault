#!/usr/bin/env python3
"""Bootstrap the real Rust CLI before Go suites that include the vault gate."""

import json
import os
import subprocess
import sys


def main(argv):
    try:
        separator = argv.index("--")
        cargo, go = argv[:separator], argv[separator + 1:]
        if not cargo or not go:
            raise ValueError("expected cargo command -- go command")
        env = os.environ.copy()
        if not env.get("SYMVAULT_RUST_BINARY"):
            build = subprocess.run(
                cargo + ["build", "-p", "symvault-cli", "--bin", "symvault",
                         "--locked", "--message-format=json"],
                stdout=subprocess.PIPE, text=True, encoding="utf-8",
            )
            if build.returncode:
                print(build.stdout, file=sys.stderr, end="")
                return build.returncode
            # Cargo reports the real path, including custom target dirs and .exe.
            messages = [json.loads(line) for line in build.stdout.splitlines()]
            binaries = {
                message["executable"] for message in messages
                if message.get("reason") == "compiler-artifact"
                and message.get("target", {}).get("name") == "symvault"
                and "bin" in message.get("target", {}).get("kind", [])
                and message.get("executable")
            }
            if len(binaries) != 1:
                raise ValueError("Cargo did not report exactly one symvault binary")
            env["SYMVAULT_RUST_BINARY"] = binaries.pop()
        return subprocess.call(go, env=env)
    except (OSError, ValueError) as error:
        print(f"Go test bootstrap: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
