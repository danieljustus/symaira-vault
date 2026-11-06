"""Identity of the historical MCP oracle and its narrowly corrected successor (constants and helpers; no Go).

The pins are commits of the archived Go tree (tag `legacy/go-oracle`, docs/rust-port/go-oracle-archive.md). The recordings
made from them live under scripts/rust-port/fixtures/go-observations/ and are replayed by the process contracts;
`make oracle-reachability-check` keeps both commits reachable. Nothing here builds or starts a Go toolchain.
"""
import hashlib
from pathlib import Path

HISTORICAL = 'd1cd0f97ac550bc3020bc86b0514989f8d28d95c'
ORDERED = '24acdb08fcc7021262717aa803d72eb8d151c66a'
CONTRACT = 'mcp-anomaly-ordered-v1'


def inventory(root, names):
    return {name: hashlib.sha256((Path(root)/name).read_bytes()).hexdigest()
            for name in sorted(names)}


def tool_environment(env):
    # Do not expose ambient API/cloud tokens, agent sockets or proxy credentials
    # to a fixture CLI or its executor children.
    allowed = {'PATH','HOME','USERPROFILE','TMPDIR','TMP','TEMP','SYSTEMROOT',
               'WINDIR','COMSPEC','PATHEXT','LANG','LC_ALL','LC_CTYPE'}
    return {key:value for key,value in env.items() if key.upper() in allowed}
