# Pending approval CLI

The `symvault approval` commands operate on the queue owned by the running
local MCP server. They do not read a queue file and do not create or emulate
an enrolled approval device.

```sh
symvault approval list
symvault approval list --output json
symvault approval decide <request-id> --approve
symvault approval decide <request-id> --deny
```

`--json` is equivalent to `--output json`. JSON list responses have this
stable shape:

```json
{"requests":[{"id":"apr-...","agent_name":"agent","path":"work/file","write":true,"reason":"agent write requires approval","created_at":"...","expires_at":"...","status":"pending"}]}
```

Decision responses have the shape `{"outcome":{...}}` and include the request
ID, resulting status, decision timestamp, and server-side attribution. No
secret values are returned. The CLI endpoint is reachable only over a
loopback connection and requires proof of ownership of the local vault
directory. The server remains authoritative for queue state and decisions.
