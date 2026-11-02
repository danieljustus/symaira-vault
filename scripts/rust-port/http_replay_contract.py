#!/usr/bin/env python3
"""Actual Go/Rust HTTP SSE-negotiation, replay, envelope, route and request-framing contract.

Both real CLIs start from byte-identical encrypted fixtures on the same loopback
port, sequentially.  Every case is a raw request transcript.  Responses are
compared (status line, full header multiset without Date, entity bytes) and each
case is either identical or listed in DECLARED with an independently asserted
Go status, Rust status and rationale label.  A declaration that stops differing
is itself a failure, so the table cannot go stale silently.
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import socket
import sys
import tempfile
import time

sys.dont_write_bytecode = True
from http_oauth_contract import PASSPHRASE, PROBE, Server
from http_process_contract import SECRET, request
from mcp_process_contract import ORACLE, ROOT, checked, inventory, isolated, oracle_build_timeout, remove_worktree, vault_snapshot

INIT = b'{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","clientInfo":{"name":"public-replay-fixture","version":"1"},"capabilities":{}}}'
PING = b'{"jsonrpc":"2.0","id":2,"method":"ping"}'
NOTIF = b'{"jsonrpc":"2.0","method":"notifications/initialized"}'
TOOLS = b'{"jsonrpc":"2.0","id":4,"method":"tools/list"}'
HEALTH = b'{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"health","arguments":{}}}'
HEALTH_NOTIF = b'{"jsonrpc":"2.0","method":"tools/call","params":{"name":"health","arguments":{}}}'

# Cases whose responses are not byte-identical by an explicit, rationale-bound decision.
# name -> (label, expected Go status code, expected Rust status code); None = no response bytes.
PARSER_PAGE = 'stable-parser-error-page'      # both reject with 400; net/http page vs Rust's fixed page
STRICT_FORM = 'rust-rejects-ambiguous-request-form'
COMPLETE_BODY = 'complete-json-body-required'
UTF8 = 'valid-utf8-required'
DECLARED = {}
for _name in ['line-no-slash', 'line-double-space', 'line-double-space2', 'line-trailing-space', 'line-http09', 'line-http-lower',
              'line-tab-sep', 'line-empty', 'line-only-method', 'line-bad-method-char', 'lead-crlf', 'lead-2crlf', 'lead-lf',
              'hdr-space-before-colon', 'hdr-no-colon', 'hdr-empty-name', 'hdr-nul-value', 'hdr-cr-value', 'hdr-del-value',
              'hdr-bad-name-char', 'hdr-dup-host', 'hdr-no-host', 'cl-plus', 'cl-hex', 'cl-list-same', 'cl-list-diff',
              'cl-negative', 'cl-huge', 'cl-empty', 'cl-alpha', 'cl-float', 'cl-underscore', 'cl-dup-diff', 'garbage', 'h2-preface']:
    DECLARED[_name] = (PARSER_PAGE, 400, 400)
for _name in ['line-absolute-form', 'line-absolute-other-host', 'line-http12', 'bare-lf', 'mixed-eol', 'hdr-obs-fold',
              'hdr-nonascii-value', 'hdr-no-host-http10', 'hdr-empty-host', 'hdr-dup-ct', 'hdr-dup-agent', 'hdr-dup-origin',
              'cl-dup-same', 'ver-dup', 'hdr-dup-protocol-version']:
    DECLARED[_name] = (STRICT_FORM, 200, 400)
for _name in ['env-two-obj', 'env-obj-then-garbage', 'trail-garbage']:
    DECLARED[_name] = (COMPLETE_BODY, 200, 400)
for _name in ['env-invalid-utf8-id', 'env-invalid-utf8-method']:
    DECLARED[_name] = (UTF8, 200, 400)
DECLARED.update({
    'line-http2': ('go-505-unsupported-version-vs-rust-400', 505, 400),
    'line-star': ('go-options-asterisk-vs-rust-400', 200, 400),
    'line-connect': ('go-mux-404-vs-rust-400', 404, 400),
    'tls-clienthello': ('go-400-page-vs-rust-silent-close', 400, None),
    'cl-too-big': ('go-answers-first-json-value-vs-rust-awaits-declared-length', 200, None),
})
# Cases whose FINAL (non-interim) transcript must be byte-identical.  Go writes `HTTP/1.1 100 Continue` only when its
# handler first reads the body (net/http `expectContinueReader.Read`, go1.26.6 server.go), i.e. after the Origin,
# bearer, agent, Content-Type and Accept checks; Rust reads the whole body before it authenticates, so it never has
# the same point to emit it.  Reproducing the exact emission point would mean deferring body reads behind those
# checks, which is not a cheap or safe change; the interim line is the only difference and is asserted exactly
# (Go sends one, Rust none) so that the case fails if either side changes.
INTERIM_ONLY = {
    'expect-100': 'go-sends-interim-100-continue-after-auth-rust-does-not',
    'expect-100-chunked': 'go-sends-interim-100-continue-after-auth-rust-does-not',
}
for _name in ['te-identity', 'te-gzip-chunked', 'te-chunked-gzip', 'te-chunked-chunked', 'te-x-chunked', 'te-empty', 'te-quoted',
              'te-chunked-param', 'te-dup']:
    DECLARED[_name] = ('go-501-unsupported-transfer-encoding-vs-rust-400', 501, 400)
DECLARED['te-http10'] = (PARSER_PAGE, 400, 400)
DECLARED['replay-invalid-length-then-ping'] = (COMPLETE_BODY, 200, 400)

# Hand-written expectations for representative identical cases (protects against both sides being wrong).
EXPECT = {
    'post-accept-sse-only': 406, 'post-accept-json-only': 406, 'post-accept-star': 406, 'post-accept-app-star-sse': 200,
    'post-accept-sse-first': 200, 'post-accept-upper': 200, 'post-accept-param': 200, 'post-accept-bad-mime2': 200,
    'method-GET': 405, 'method-HEAD': 405, 'method-DELETE': 405, 'method-OPTIONS': 405, 'method-FOO': 405,
    'get-last-event-id': 405, 'delete-session': 405, 'post-last-event-id': 200, 'post-session-id': 200,
    'ver-ping-2024-11-05': 200, 'ver-ping-2024-10-07': 400, 'ver-ping-latest': 400, 'env-notif': 202,
    'env-notif-with-id': 202, 'env-ping-notification': 200, 'env-response-msg': 202, 'env-result-only': 202,
    'env-bad-jsonrpc-version': 200, 'env-no-jsonrpc': 200, 'env-no-method': 200, 'env-empty-obj': 202, 'env-null-body': 202,
    'env-upper-keys': 200, 'env-dup-method': 200, 'env-array-batch': 400, 'env-array-tuple': 400, 'env-num-body': 400,
    'env-tools-call-notification': 200, 'env-initialize-notification': 200, 'env-error-empty-obj': 202, 'env-error-string': 400,
    'route-double-slash-mcp': 307, 'route-dot-mcp': 307, 'route-pct-mcp': 200, 'route-slash-mcp': 404,
    'route-get-metrics': 501, 'route-get-unknown': 404, 'ct-trailing-semi': 200, 'ct-json-x': 415, 'expect-other': 417,
    'te-mixed-case': 200, 'te-chunked-trailing-space': 200, 'conn-upgrade-h2c': 200, 'cl-lead-zero': 200,
}
HEALTH_CASES = {'route-get-health', 'route-post-health', 'route-head-health', 'route-options-health', 'route-delete-health',
                'route-get-health-query', 'route-get-health-pct', 'route-get-health-auth', 'route-get-health-origin'}


def raw_request(port, tokens, line='POST /mcp HTTP/1.1', body=PING, drop=(), extra=(), content_length=True, eol=b'\r\n', replace=None):
    fields = [('Host', f'127.0.0.1:{port}'), ('Authorization', 'Bearer ' + tokens['full']), ('X-Symaira-Agent', 'fixture'),
              ('Content-Type', 'application/json'), ('Accept', 'application/json, text/event-stream')]
    fields = [item for item in fields if item[0] not in drop] + list(extra)
    if content_length:
        fields.append(('Content-Length', str(len(body))))
    data = line.encode() + eol + b''.join(f'{k}: {v}'.encode('utf-8') + eol for k, v in fields) + eol + body
    for old, new in (replace or []):
        assert old in data, 'replacement anchor must exist'
        data = data.replace(old, new, 1)
    return data


def chunk(body):
    return format(len(body), 'x').encode() + b'\r\n' + body + b'\r\n0\r\n\r\n'


def cases(port, tokens):
    R = lambda **kw: raw_request(port, tokens, **kw)
    P = lambda path, method='POST', body=PING, **kw: request(path, port, tokens, method=method, body=body, **kw)
    keep = lambda body: P('/mcp', body=body).replace(b'Connection: close\r\n', b'Connection: keep-alive\r\n')
    swap = lambda value, **kw: R(**kw, replace=[(b'Content-Type: application/json', b'Content-Type: ' + value)])
    result = []   # (name, bytes, half_close, head)
    add = lambda name, data, half=True, head=False: result.append((name, data, half, head))
    # --- SSE negotiation: Go has no event stream; Accept only gates POST responses -----------------------
    for name, accept in [('sse-only', 'text/event-stream'), ('json-only', 'application/json'), ('star', '*/*'),
                         ('app-star-sse', 'application/*, text/event-stream'), ('q-zero', 'application/json;q=0, text/event-stream;q=0.5'),
                         ('text-star', 'text/*'), ('sse-first', 'text/event-stream, application/json'),
                         ('upper', 'APPLICATION/JSON, TEXT/EVENT-STREAM'), ('param', 'application/json; charset=utf-8, text/event-stream; x=y'),
                         ('bad-mime', 'application/json, ,text/event-stream'), ('bad-mime2', 'application/json, @@, text/event-stream'),
                         ('empty-parts', ',,application/json,,text/event-stream,'), ('trailing-semi', 'application/json;, text/event-stream;')]:
        add('post-accept-' + name, P('/mcp', headers=[('Accept', accept)]))
    for method in ['GET', 'HEAD', 'DELETE', 'PUT', 'PATCH', 'OPTIONS', 'TRACE', 'FOO', 'get']:
        add('method-' + method, P('/mcp', method=method, body=b'', headers=[('Accept', 'text/event-stream')]), head=method == 'HEAD')
    add('get-no-accept', P('/mcp', method='GET', body=b'', headers=[('Accept', '')]))
    add('get-last-event-id', P('/mcp', method='GET', body=b'', headers=[('Accept', 'text/event-stream'), ('Last-Event-ID', '42')]))
    add('get-session-id', P('/mcp', method='GET', body=b'', headers=[('Accept', 'text/event-stream'), ('Mcp-Session-Id', 'abc')]))
    add('delete-session', P('/mcp', method='DELETE', body=b'', headers=[('Mcp-Session-Id', 'abc')]))
    add('delete-noauth', P('/mcp', method='DELETE', body=b'', auth=None))
    add('get-noauth', P('/mcp', method='GET', body=b'', auth=None))
    add('options-cors', P('/mcp', method='OPTIONS', body=b'', auth=None, agent=None,
                          headers=[('Origin', f'http://127.0.0.1:{port}'), ('Access-Control-Request-Method', 'POST')]))
    add('post-last-event-id', P('/mcp', headers=[('Last-Event-ID', '7')]))
    add('post-session-id', P('/mcp', headers=[('Mcp-Session-Id', 'bogus')]))
    add('post-session-id-multi', P('/mcp', headers=[('Mcp-Session-Id', 'a'), ('Mcp-Session-Id', 'b')]))
    add('post-init-session-id', P('/mcp', body=INIT, headers=[('Mcp-Session-Id', 'bogus')]))
    for version in ['2025-11-25', '2025-06-18', '2025-03-26', '2024-11-05', '2024-10-07', '', '2025-11-25,2025-06-18', 'latest']:
        label = version.replace(',', '_') or 'empty'
        add('ver-ping-' + label, P('/mcp', headers=[('MCP-Protocol-Version', version)]))
        add('ver-init-' + label, P('/mcp', body=INIT, headers=[('MCP-Protocol-Version', version)]))
    add('ver-dup', P('/mcp', headers=[('MCP-Protocol-Version', '2025-11-25'), ('MCP-Protocol-Version', '2099')]))
    # --- JSON-RPC envelope: Go decodes transport.Message without the stdio guards -----------------------
    envelopes = {
        'notif': NOTIF, 'notif-with-id': b'{"jsonrpc":"2.0","id":9,"method":"notifications/initialized"}',
        'notif-unknown': b'{"jsonrpc":"2.0","method":"notifications/unknown"}', 'ping-notification': b'{"jsonrpc":"2.0","method":"ping"}',
        'response-msg': b'{"jsonrpc":"2.0","id":1,"result":{}}', 'error-msg': b'{"jsonrpc":"2.0","id":1,"error":{"code":-1,"message":"x"}}',
        'array-batch': b'[' + PING + b',' + PING + b']', 'array-empty': b'[]', 'array-tuple': b'[null,"2.0","ping",1]',
        'string-id': b'{"jsonrpc":"2.0","id":"abc","method":"ping"}', 'null-id': b'{"jsonrpc":"2.0","id":null,"method":"ping"}',
        'float-id': b'{"jsonrpc":"2.0","id":1.5,"method":"ping"}', 'big-id': b'{"jsonrpc":"2.0","id":123456789012345678901234567890,"method":"ping"}',
        'object-id': b'{"jsonrpc":"2.0","id":{"a":1},"method":"ping"}', 'array-id': b'{"jsonrpc":"2.0","id":[1],"method":"ping"}',
        'id-escape': b'{"jsonrpc":"2.0","id":"a\\u00e9\\n","method":"ping"}', 'id-lone-surrogate': b'{"jsonrpc":"2.0","id":"\\ud800","method":"ping"}',
        'bad-jsonrpc-version': b'{"jsonrpc":"1.0","id":2,"method":"ping"}', 'no-jsonrpc': b'{"id":2,"method":"ping"}',
        'no-method': b'{"jsonrpc":"2.0","id":2}', 'unknown-method': b'{"jsonrpc":"2.0","id":2,"method":"nope/nope"}',
        'empty-obj': b'{}', 'null-body': b'null', 'num-body': b'5', 'true-body': b'true', 'str-body': b'"x"', 'empty-body': b'',
        'bom-body': b'\xef\xbb\xbf' + PING, 'lead-ws': b' \n\t' + PING, 'trail-ws': PING + b' \n\n',
        'upper-keys': b'{"JSONRPC":"2.0","ID":2,"METHOD":"ping"}', 'mixed-keys': b'{"JsonRpc":"2.0","Id":2,"Method":"ping"}',
        'long-s-key': '{"j\u017fonrpc":"2.0","id":2,"method":"ping"}'.encode(), 'kelvin-extra-key': '{"jsonrpc":"2.0","id":2,"method":"ping","\u212a":1}'.encode(),
        'dup-method': b'{"jsonrpc":"2.0","id":2,"method":"nope","method":"ping"}', 'dup-id': b'{"jsonrpc":"2.0","id":3,"id":2,"method":"ping"}',
        'dup-jsonrpc': b'{"jsonrpc":"1","jsonrpc":"2.0","id":2,"method":"ping"}',
        'method-null': b'{"jsonrpc":"2.0","id":2,"method":null}', 'method-number': b'{"jsonrpc":"2.0","id":2,"method":5}',
        'method-object': b'{"jsonrpc":"2.0","id":2,"method":{}}', 'jsonrpc-number': b'{"jsonrpc":2.0,"id":2,"method":"ping"}',
        'jsonrpc-null': b'{"jsonrpc":null,"id":2,"method":"ping"}', 'error-null': b'{"jsonrpc":"2.0","id":2,"method":"ping","error":null}',
        'error-string': b'{"jsonrpc":"2.0","id":2,"method":"ping","error":"x"}', 'error-empty-obj': b'{"jsonrpc":"2.0","id":2,"method":"ping","error":{}}',
        'error-code-string': b'{"jsonrpc":"2.0","id":2,"method":"ping","error":{"code":"x"}}',
        'error-extra': b'{"jsonrpc":"2.0","id":2,"method":"ping","error":{"code":1,"message":"m","data":{"a":1},"zzz":2}}',
        'result-null': b'{"jsonrpc":"2.0","id":2,"method":"ping","result":null}', 'result-obj': b'{"jsonrpc":"2.0","id":2,"method":"ping","result":{}}',
        'result-only': b'{"jsonrpc":"2.0","id":2,"result":{}}', 'params-null': b'{"jsonrpc":"2.0","id":2,"method":"ping","params":null}',
        'params-array': b'{"jsonrpc":"2.0","id":2,"method":"ping","params":[1]}', 'params-string': b'{"jsonrpc":"2.0","id":2,"method":"ping","params":"x"}',
        'init-params-null': b'{"jsonrpc":"2.0","id":2,"method":"initialize","params":null}', 'init-params-array': b'{"jsonrpc":"2.0","id":2,"method":"initialize","params":[]}',
        'init-no-params': b'{"jsonrpc":"2.0","id":2,"method":"initialize"}', 'init-version-type': b'{"jsonrpc":"2.0","id":2,"method":"initialize","params":{"protocolVersion":5}}',
        'init-unknown-version': b'{"jsonrpc":"2.0","id":2,"method":"initialize","params":{"protocolVersion":"1999"}}',
        'id-true': b'{"jsonrpc":"2.0","id":true,"method":"ping"}', 'id-ws': b'{"jsonrpc":"2.0","id": 7 ,"method":"ping"}',
        'id-exp': b'{"jsonrpc":"2.0","id":1e2,"method":"ping"}', 'extra-fields': b'{"jsonrpc":"2.0","id":2,"method":"ping","x":{"y":[1,2,3]},"z":null}',
        'tools-call-notification': HEALTH_NOTIF, 'tools-list-notification': b'{"jsonrpc":"2.0","method":"tools/list"}',
        'initialize-notification': b'{"jsonrpc":"2.0","method":"initialize","params":{"protocolVersion":"2025-11-25"}}',
        'initialized-short': b'{"jsonrpc":"2.0","method":"initialized"}', 'initialized-short-id': b'{"jsonrpc":"2.0","id":3,"method":"initialized"}',
        'prompts-list': b'{"jsonrpc":"2.0","id":3,"method":"prompts/list"}', 'prompts-get-bad': b'{"jsonrpc":"2.0","id":3,"method":"prompts/get","params":{}}',
        'tools-call-nothing': b'{"jsonrpc":"2.0","id":3,"method":"tools/call"}',
        'tools-call-unknown': b'{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"nope","arguments":{}}}',
        'tools-call-bad-args': b'{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"health","arguments":5}}',
        'nul-in-string': b'{"jsonrpc":"2.0","id":"a\x00b","method":"ping"}',
        'depth-ok': b'{"jsonrpc":"2.0","id":2,"method":"ping","x":' + b'[' * 5000 + b']' * 5000 + b'}',
        'comment': b'{"jsonrpc":"2.0",/*c*/"id":2,"method":"ping"}', 'trailing-comma': b'{"jsonrpc":"2.0","id":2,"method":"ping",}',
        'single-quote': b"{'jsonrpc':'2.0','id':2,'method':'ping'}", 'nan': b'{"jsonrpc":"2.0","id":NaN,"method":"ping"}',
        'leading-zero': b'{"jsonrpc":"2.0","id":01,"method":"ping"}', 'two-obj': PING + b' ' + PING, 'obj-then-garbage': PING + b'}',
        'invalid-utf8-id': b'{"jsonrpc":"2.0","id":"\xff","method":"ping"}', 'invalid-utf8-method': b'{"jsonrpc":"2.0","id":2,"method":"pi\xffng"}',
    }
    envelopes['trail-garbage'] = PING + b'x'
    for name, body in envelopes.items():
        add('trail-garbage' if name == 'trail-garbage' else 'env-' + name, P('/mcp', body=body))
    # --- replay: persistent connections repeat identical requests and ids --------------------------------
    add('replay-init-twice', keep(INIT) + keep(INIT))
    add('replay-ping-twice', keep(PING) + keep(PING))
    add('replay-init-notif-ping', keep(INIT) + keep(NOTIF) + keep(PING))
    add('replay-init-health-init-health', keep(INIT) + keep(HEALTH) + keep(INIT) + keep(HEALTH))
    add('replay-tools-list-twice', keep(INIT) + keep(TOOLS) + keep(TOOLS))
    add('replay-error-then-ping', keep(b'{') + keep(PING))
    add('replay-notification-then-health', keep(HEALTH_NOTIF) + keep(HEALTH))
    add('replay-invalid-length-then-ping', keep(PING + b'zzz'))
    add('replay-sse-get-then-ping', P('/mcp', method='GET', body=b'', headers=[('Accept', 'text/event-stream')]).replace(b'Connection: close\r\n', b'Connection: keep-alive\r\n') + keep(PING))
    add('replay-last-event-id-twice', keep(PING).replace(b'Content-Length', b'Last-Event-ID: 5\r\nContent-Length', 1) * 2)
    # --- routes: Go mux ------------------------------------------------------------------------------------
    G = lambda path, method='GET', **kw: P(path, method=method, body=b'', auth=kw.pop('auth', None), agent=None, **kw)
    for name, path in [('slash-mcp', '/mcp/'), ('double-slash-mcp', '//mcp'), ('dotdot-mcp', '/mcp/../mcp'), ('dot-mcp', '/./mcp'),
                       ('upper-mcp', '/MCP'), ('semicolon-mcp', '/mcp;x=1'), ('fragment-mcp', '/mcp#f'), ('empty-query-mcp', '/mcp?'),
                       ('pct-mcp', '/m%63p'), ('pct-nul-mcp', '/mcp%00'), ('pct-slash-mcp', '/mcp%2f'), ('unknown-double-slash', '//nothing/here'),
                       ('double-slash-health', '//health'), ('dot-health', '/./health'), ('dotdot-pct-health', '/%2e%2e/health'),
                       ('health-slash', '/health/'), ('healthz', '/healthz'), ('metrics-slash', '/metrics/'), ('root', '/'), ('favicon', '/favicon.ico')]:
        add('route-' + name, P(path, method='POST') if name.endswith('mcp') else G(path))
    for name, (path, method, extra) in {
            'get-health': ('/health', 'GET', {}), 'post-health': ('/health', 'POST', {}), 'head-health': ('/health', 'HEAD', {}),
            'options-health': ('/health', 'OPTIONS', {}), 'delete-health': ('/health', 'DELETE', {}),
            'get-health-query': ('/health?x=1', 'GET', {}), 'get-health-pct': ('/%68ealth', 'GET', {}),
            'get-health-auth': ('/health', 'GET', {'auth': 'full'}), 'get-health-origin': ('/health', 'GET', {'headers': [('Origin', 'https://foreign.example')]}),
            'get-metrics': ('/metrics', 'GET', {}), 'post-metrics': ('/metrics', 'POST', {}), 'get-metrics-auth': ('/metrics', 'GET', {'auth': 'full'}),
            'get-unknown': ('/public-missing', 'GET', {})}.items():
        add('route-' + name, G(path, method, **extra), head=method == 'HEAD')
    # --- request line, header and body framing --------------------------------------------------------------
    for name, line in [('absolute-form', f'POST http://127.0.0.1:{port}/mcp HTTP/1.1'), ('absolute-other-host', 'POST http://evil.example/mcp HTTP/1.1'),
                       ('no-slash', 'POST mcp HTTP/1.1'), ('double-space', 'POST  /mcp HTTP/1.1'), ('double-space2', 'POST /mcp  HTTP/1.1'),
                       ('trailing-space', 'POST /mcp HTTP/1.1 '), ('lower-method', 'post /mcp HTTP/1.1'), ('http12', 'POST /mcp HTTP/1.2'),
                       ('http2', 'POST /mcp HTTP/2.0'), ('http09', 'POST /mcp'), ('http-lower', 'POST /mcp http/1.1'), ('tab-sep', 'POST\t/mcp\tHTTP/1.1'),
                       ('star', 'OPTIONS * HTTP/1.1'), ('connect', f'CONNECT 127.0.0.1:{port} HTTP/1.1'), ('empty', ''), ('only-method', 'POST'),
                       ('bad-method-char', 'PO@ST /mcp HTTP/1.1')]:
        add('line-' + name, R(line=line))
    add('lead-crlf', b'\r\n' + R())
    add('lead-2crlf', b'\r\n\r\n' + R())
    add('lead-lf', b'\n' + R())
    add('bare-lf', R(eol=b'\n'))
    add('mixed-eol', R().replace(b'\r\n', b'\n', 1))
    add('hdr-space-before-colon', R(replace=[(b'Accept:', b'Accept :')]))
    add('hdr-obs-fold', R(replace=[(b'Accept: application/json,', b'Accept: application/json,\r\n  ')]))
    add('hdr-no-colon', R(extra=[('X-A', 'b')], replace=[(b'X-A: b', b'X-A b')]))
    add('hdr-empty-name', R(replace=[(b'Accept:', b': x\r\nAccept:')]))
    add('hdr-underscore', R(extra=[('X_Under', '1')]))
    add('hdr-utf8-value', R(extra=[('X-A', '\u00e9\u00ff')]))
    add('hdr-nonascii-value', R(extra=[('X-A', 'a')], replace=[(b'X-A: a', b'X-A: \xe9\xff')]))
    add('hdr-nul-value', R(extra=[('X-A', 'a\x00b')]))
    add('hdr-cr-value', R(extra=[('X-A', 'a\rb')]))
    add('hdr-del-value', R(extra=[('X-A', 'a\x7fb')]))
    add('hdr-tab-value', R(extra=[('X-A', 'a\tb')]))
    add('hdr-empty-value', R(extra=[('X-A', '')]))
    add('hdr-bad-name-char', R(extra=[('X A', '1')]))
    add('hdr-many-200', R(extra=[(f'X-{i}', 'v') for i in range(200)]))
    add('hdr-dup-host', R(extra=[('Host', f'127.0.0.1:{port}')]))
    add('hdr-no-host', R(drop=['Host']))
    add('hdr-no-host-http10', R(line='POST /mcp HTTP/1.0', drop=['Host']))
    add('hdr-empty-host', R(drop=['Host'], extra=[('Host', '')]))
    add('hdr-dup-ct', R(extra=[('Content-Type', 'application/json')]))
    add('hdr-dup-agent', R(extra=[('X-Symaira-Agent', 'fixture')]))
    add('hdr-dup-origin', R(extra=[('Origin', f'http://127.0.0.1:{port}'), ('Origin', f'http://127.0.0.1:{port}')]))
    add('hdr-dup-protocol-version', R(extra=[('MCP-Protocol-Version', '2025-11-25'), ('MCP-Protocol-Version', '2099')]))
    add('hdr-dup-unknown', R(extra=[('X-Dup', '1'), ('X-Dup', '2')]))
    add('hdr-dup-accept-split', R(drop=['Accept'], extra=[('Accept', 'application/json'), ('Accept', 'text/event-stream')]))
    add('hdr-lower-names', R(replace=[(b'Authorization:', b'authorization:'), (b'Content-Type:', b'content-type:')]))
    add('hdr-upper-names', R(replace=[(b'Authorization:', b'AUTHORIZATION:'), (b'X-Symaira-Agent:', b'X-SYMAIRA-AGENT:')]))
    add('hdr-extra-ws', R(replace=[(b'Content-Type: application/json', b'Content-Type:   application/json   ')]))
    length = str(len(PING))
    for name, value in [('plus', '+' + length), ('lead-space', ' ' + length), ('trail-space', length + ' '), ('lead-zero', '00' + length),
                        ('hex', '0x25'), ('list-same', f'{length}, {length}'), ('list-diff', f'{length}, 99'), ('negative', '-1'),
                        ('huge', '99999999999999999999'), ('empty', ''), ('alpha', 'abc'), ('float', length + '.0'), ('underscore', '3_9'),
                        ('too-big', '1000')]:
        add('cl-' + name, R(content_length=False, extra=[('Content-Length', value)]))
    add('cl-dup-same', R(extra=[('Content-Length', length)]))
    add('cl-dup-diff', R(extra=[('Content-Length', '3')]))
    add('cl-zero-body', R(body=b''))
    add('cl-missing-post', R(content_length=False, body=b''))
    for name, value in [('identity', 'identity'), ('gzip-chunked', 'gzip, chunked'), ('chunked-gzip', 'chunked, gzip'), ('chunked-chunked', 'chunked, chunked'),
                        ('mixed-case', 'Chunked'), ('chunked-trailing-space', 'chunked '), ('x-chunked', 'x-chunked'), ('empty', ''),
                        ('quoted', '"chunked"'), ('chunked-param', 'chunked;q=1')]:
        add('te-' + name, R(content_length=False, extra=[('Transfer-Encoding', value)], body=chunk(PING)))
    add('te-dup', R(content_length=False, extra=[('Transfer-Encoding', 'chunked'), ('Transfer-Encoding', 'chunked')], body=chunk(PING)))
    add('te-http10', R(line='POST /mcp HTTP/1.0', content_length=False, extra=[('Transfer-Encoding', 'chunked')], body=chunk(PING)))
    add('expect-100', R(extra=[('Expect', '100-continue')]))
    add('expect-other', R(extra=[('Expect', 'foo')]))
    add('expect-100-chunked', R(content_length=False, extra=[('Expect', '100-continue'), ('Transfer-Encoding', 'chunked')], body=chunk(PING)))
    add('conn-keepalive', R(extra=[('Connection', 'keep-alive')]))
    add('conn-close', R(extra=[('Connection', 'close')]))
    add('conn-upgrade-h2c', R(extra=[('Connection', 'Upgrade, HTTP2-Settings'), ('Upgrade', 'h2c'), ('HTTP2-Settings', 'AAMAAABkAAQAAP__')]))
    add('conn-upgrade-websocket', R(extra=[('Connection', 'Upgrade'), ('Upgrade', 'websocket'), ('Sec-WebSocket-Key', 'x'), ('Sec-WebSocket-Version', '13')]))
    add('conn-http10-keepalive', R(line='POST /mcp HTTP/1.0', extra=[('Connection', 'keep-alive')]))
    add('conn-http10-plain', R(line='POST /mcp HTTP/1.0'))
    add('garbage', b'\x00\x01\x02\x03\r\n\r\n')
    add('h2-preface', b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n')
    add('tls-clienthello', b'\x16\x03\x01\x00\x05\x01\x00\x00\x01\x00')
    for name, value in [('charset', b'application/json; charset=utf-8'), ('upper', b'APPLICATION/JSON'), ('trailing-semi', b'application/json;'),
                        ('json-x', b'application/jsonx'), ('empty', b''), ('vnd-json', b'application/vnd+json'), ('bad-param', b'application/json; charset')]:
        add('ct-' + name, swap(value))
    add('ct-missing', R(drop=['Content-Type']))
    return result


def parse_stream(raw, head=False):
    """Split consecutive HTTP/1.x responses; keep every actual byte of every entity."""
    rows, rest = [], bytes(raw)
    while rest:
        end = rest.find(b'\r\n\r\n')
        if end < 0:
            rows.append(dict(truncated=True, partial_base64=base64.b64encode(rest).decode()))
            break
        lines = rest[:end].decode('latin1').split('\r\n')
        fields = [(name.lower(), value.strip()) for name, _, value in (line.partition(':') for line in lines[1:])]
        body, code = rest[end + 4:], int(lines[0].split()[1])
        transfers = [v for k, v in fields if k == 'transfer-encoding']
        lengths = [v for k, v in fields if k == 'content-length']
        interim = code == 100
        truncated = False
        if interim or head or code in {204, 304}:
            entity, rest = b'', body
        elif transfers:
            assert transfers == ['chunked'] and not lengths, 'unambiguous chunked response framing'
            entity, rest = bytearray(), body
            while True:
                line_end = rest.find(b'\r\n')
                if line_end < 0:
                    truncated = True
                    break
                size = int(rest[:line_end], 16)
                rest = rest[line_end + 2:]
                if size == 0:
                    assert rest[:2] == b'\r\n', 'complete final chunk'
                    rest = rest[2:]
                    break
                entity += rest[:size]
                rest = rest[size + 2:]
            entity = bytes(entity)
        elif lengths:
            assert len(lengths) == 1
            size = int(lengths[0])
            entity, rest = body[:size], body[size:]
            truncated = len(entity) < size
        else:
            entity, rest = body, b''
        rows.append(dict(status_line=lines[0], code=code, interim=interim, headers=fields,
                         headers_without_date=sorted((k, v) for k, v in fields if k != 'date'),
                         body_base64=base64.b64encode(entity).decode(), truncated=truncated))
        if truncated:
            break
    return rows


def exchange(port, data, half_close=True, head=False, timeout=8):
    raw, reset, started = bytearray(), None, time.monotonic()
    with socket.create_connection(('127.0.0.1', port), timeout=timeout) as stream:
        try:
            stream.sendall(data)
            if half_close:
                stream.shutdown(socket.SHUT_WR)
        except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError):
            reset = 'send'
        while True:
            try:
                part = stream.recv(65536)
            except socket.timeout:
                reset = 'timeout'
                break
            except (ConnectionResetError, ConnectionAbortedError):
                reset = reset or 'receive'
                break
            if not part:
                break
            raw += part
            assert len(raw) < 8 * 1024 * 1024
    return dict(raw_base64=base64.b64encode(bytes(raw)).decode(), reset=reset, elapsed_seconds=time.monotonic() - started,
                responses=parse_stream(bytes(raw), head))


def observe(binary, home, port, tokens, result):
    known = [SECRET, PASSPHRASE] + list(tokens.values())
    server = Server(binary, home, port, result['processes'], list(tokens.values()))
    try:
        for name, data, half, head in cases(port, tokens):
            row = dict(case=name, request_sha256=hashlib.sha256(data).hexdigest(), request_base64=base64.b64encode(data).decode())
            result['rows'].append(row)
            row.update(exchange(port, data, half, head))
            assert not any(value.encode() in base64.b64decode(row['raw_base64']) for value in known), 'secret/token in response'
            assert row['reset'] != 'timeout', (name, 'server left the connection open past the exchange')
    finally:
        server.close()


def final_codes(row):
    finals = [r for r in row['responses'] if not r.get('interim') and 'code' in r]
    return finals[0]['code'] if finals else None


def transcript(row):
    return [(r.get('status_line'), r.get('headers_without_date'), r.get('body_base64'), r.get('truncated', False), r.get('interim', False))
            for r in row['responses']]


def health_equal_except_clock(left, right, port):
    for row in [left, right]:
        assert len(row['responses']) == 1 and row['responses'][0]['code'] == 200
    bodies = [json.loads(base64.b64decode(row['responses'][0]['body_base64'])) for row in [left, right]]
    for body in bodies:
        assert sorted(body) == ['port', 'status', 'timestamp', 'version'] and body['port'] == port and body['status'] == 'healthy'
        assert body['version'] == 'dev' and re.fullmatch(r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ', body['timestamp']), 'complete health document'
    stamps = [time.mktime(time.strptime(b['timestamp'], '%Y-%m-%dT%H:%M:%SZ')) - time.timezone for b in bodies]
    assert abs(stamps[0] - stamps[1]) < 120, 'health clocks agree within the sequential run'
    first = transcript(left)[0]
    assert first[1] == transcript(right)[0][1], 'health header multiset'
    return True


def compare(go_rows, rust_rows, port=None):
    """Pure comparison + policy; returns (identical, declared, semantic, interim_only).  Raises AssertionError on any violation."""
    assert [r['case'] for r in go_rows] == [r['case'] for r in rust_rows], 'same case inventory'
    names = [r['case'] for r in go_rows]
    assert len(set(names)) == len(names), 'unique case names'
    assert set(DECLARED) <= set(names), ('declared case missing from corpus', sorted(set(DECLARED) - set(names)))
    assert set(EXPECT) <= set(names), ('expected case missing from corpus', sorted(set(EXPECT) - set(names)))
    assert set(INTERIM_ONLY) <= set(names) and not set(INTERIM_ONLY) & set(DECLARED), 'interim-only case inventory'
    identical, declared, semantic, interim_only = [], [], [], []
    for left, right in zip(go_rows, rust_rows, strict=True):
        name = left['case']
        assert left['request_sha256'] == right['request_sha256'], name
        for side in (left, right):
            assert not any(r.get('truncated') for r in side['responses']) or name in DECLARED, (name, 'truncated response')
            for r in side['responses']:
                assert 'text/event-stream' not in [v for k, v in r.get('headers', []) if k == 'content-type'], (name, 'Go has no event stream')
                assert not any(k in {'mcp-session-id', 'last-event-id'} for k, _ in r.get('headers', [])), (name, 'no session/replay header')
        if name in HEALTH_CASES and not name.endswith('head-health'):
            semantic.append(name if health_equal_except_clock(left, right, port) else None)
            continue
        if name == 'route-head-health':
            assert transcript(left)[0][0] == transcript(right)[0][0] == 'HTTP/1.1 200 OK' and not any(b[2] for b in transcript(left) + transcript(right))
            continue
        go_code, rust_code = final_codes(left), final_codes(right)
        if name in INTERIM_ONLY:
            def interims(row):
                return [r for r in row['responses'] if r.get('interim')]

            def finals(row):
                return [r for r in transcript(dict(responses=row['responses'])) if not r[4]]
            assert [r['code'] for r in interims(left)] == [100] and not interims(right), (name, INTERIM_ONLY[name], 'interim line set')
            assert finals(left) == finals(right) and finals(left), (name, 'final response differs beyond the interim line')
            assert go_code == EXPECT.get(name, go_code) == rust_code, (name, go_code, rust_code)
            interim_only.append(dict(case=name, decision=INTERIM_ONLY[name], go=left['responses'], rust=right['responses']))
            continue
        if name in EXPECT:
            assert go_code == EXPECT[name] == rust_code or name in DECLARED, (name, go_code, rust_code, EXPECT[name])
        if name in DECLARED:
            label, expect_go, expect_rust = DECLARED[name]
            first = lambda row: row['responses'][0]['code'] if row['responses'] else None
            assert (first(left), first(right)) == (expect_go, expect_rust), (name, label, first(left), first(right))
            assert transcript(left) != transcript(right), (name, label, 'declared difference no longer observed')
            declared.append(dict(case=name, decision=label, go=left['responses'], rust=right['responses']))
        else:
            assert transcript(left) == transcript(right), (name, 'undeclared difference', left['responses'], right['responses'])
            identical.append(name)
    return identical, declared, semantic, interim_only


def candidate_paths():
    return sorted(p for p in checked(['git', 'ls-files', '--cached', '--others', '--exclude-standard']).decode().splitlines()
                  if p.startswith(('crates/', 'third_party/', 'testdata/', 'scripts/rust-port/', 'internal/mcp/apitemplates/builtin/'))
                  or p in {'Cargo.toml', 'Cargo.lock', '.gitattributes'})


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--rust', type=Path, required=True)
    parser.add_argument('--receipt', type=Path, required=True)
    parser.add_argument('--allow-dirty-for-development', action='store_true')
    args = parser.parse_args()
    clean = not checked(['git', 'status', '--porcelain=v1']).strip()
    assert clean or args.allow_dirty_for_development
    rust = args.rust.resolve()
    paths = candidate_paths()
    receipt = dict(passed=False, candidate_commit=checked(['git', 'rev-parse', 'HEAD']).decode().strip(), candidate_worktree_clean=clean,
                   candidate_sources=inventory(paths, ROOT), native_os=platform.system(), architecture=platform.machine(),
                   rust_binary_sha256=hashlib.sha256(rust.read_bytes()).hexdigest(), oracle_commit=ORACLE,
                   driver_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                   go=dict(rows=[], processes=[]), rust=dict(rows=[], processes=[]), declared_differences=[])
    try:
        with tempfile.TemporaryDirectory(prefix='symvault-http-replay-') as raw:
            base, tree = Path(raw), Path(raw) / 'oracle'
            checked(['git', 'worktree', 'add', '--detach', tree, ORACLE])
            try:
                files = checked(['git', 'ls-tree', '-r', '--name-only', ORACLE]).decode().splitlines()
                sources = sorted(p for p in files if p in {'go.mod', 'go.sum'} or p.endswith('.go') and not p.endswith('_test.go'))
                embedded = sorted(p for p in files if p.startswith('internal/mcp/apitemplates/builtin/'))
                assert len(embedded) == 17
                receipt.update(oracle_sources=inventory(sources, tree), oracle_embedded=inventory(embedded, tree), seed_probe_sha256=hashlib.sha256(PROBE.read_bytes()).hexdigest())
                helper = tree / 'scripts/rust-port/cmd/httpreplayseed'
                helper.mkdir()
                (helper / 'main.go').write_bytes(PROBE.read_bytes())
                suffix = '.exe' if os.name == 'nt' else ''
                go, seed = base / ('go-cli' + suffix), base / ('go-seed' + suffix)
                checked(['go', 'build', '-trimpath', '-buildvcs=false', '-o', go, '.'], tree, timeout=oracle_build_timeout())
                checked(['go', 'build', '-trimpath', '-buildvcs=false', '-o', seed, './scripts/rust-port/cmd/httpreplayseed'], tree, timeout=oracle_build_timeout())
                receipt.update(go_binary_sha256=hashlib.sha256(go.read_bytes()).hexdigest(), seed_binary_sha256=hashlib.sha256(seed.read_bytes()).hexdigest())
                seed_home = base / 'seed'
                seed_home.mkdir()
                tokens = json.loads(checked([seed, '--root', seed_home / 'vault'], seed_home, isolated(seed_home)))
                snapshot = vault_snapshot(seed_home / 'vault')
                receipt['fixture_snapshot'] = snapshot
                with socket.socket() as selection:
                    selection.bind(('127.0.0.1', 0))
                    port = selection.getsockname()[1]
                receipt['port'] = port
                for implementation, binary in [('go', go), ('rust', rust)]:
                    home = base / implementation
                    home.mkdir()
                    shutil.copytree(seed_home / 'vault', home / 'vault')
                    assert vault_snapshot(home / 'vault') == snapshot
                    observe(binary, home, port, tokens, receipt[implementation])
                identical, declared, semantic, interim_only = compare(receipt['go']['rows'], receipt['rust']['rows'], port)
                receipt.update(declared_differences=declared, identical_cases=len(identical), semantic_cases=len(semantic), interim_only_cases=interim_only)
                assert inventory(paths, ROOT) == receipt['candidate_sources'] and candidate_paths() == paths, 'candidate changed during observations'
                assert hashlib.sha256(rust.read_bytes()).hexdigest() == receipt['rust_binary_sha256']
                receipt['candidate_worktree_clean_at_end'] = not checked(['git', 'status', '--porcelain=v1']).strip()
                assert receipt['candidate_worktree_clean_at_end'] or args.allow_dirty_for_development
                receipt['passed'] = True
            finally:
                remove_worktree(lambda: checked(['git', 'worktree', 'remove', '--force', tree]), 'oracle worktree')
    finally:
        args.receipt.write_text(json.dumps(receipt, indent=2) + '\n', encoding='utf-8')
    total = len(receipt['go']['rows'])
    print(f"PASS: {total} replay/SSE/envelope/route/framing cases per implementation on {platform.system()}: "
          f"{receipt['identical_cases']} identical, {len(receipt['declared_differences'])} declared, {receipt['semantic_cases']} semantic (health clock), "
          f"{len(receipt['interim_only_cases'])} final-identical (Go-only interim 100 Continue)")


if __name__ == '__main__':
    main()
