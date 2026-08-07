# API Templates

`symvault` can call external APIs on an agent's behalf through the
`execute_api_request` MCP tool. Each call is shaped by an **API template**:
a small YAML file that declares the base URL, the authentication shape, and
the endpoints/methods the template is allowed to reach. Credentials are
resolved from a vault entry at request time and never enter the agent's
environment, argv, logs or audit trail.

## Built-in providers

The following templates ship embedded in the binary (directory
`internal/mcp/apitemplates/builtin/`):

| Template    | Base URL                          | Auth shape                  |
|-------------|-----------------------------------|-----------------------------|
| anthropic   | https://api.anthropic.com         | `Authorization: Bearer`     |
| github      | https://api.github.com            | `Authorization: Bearer`     |
| openai      | https://api.openai.com            | `Authorization: Bearer`     |
| perplexity  | https://api.perplexity.ai         | `Authorization: Bearer`     |
| slack       | https://slack.com/api             | `Authorization: Bearer`     |
| gitlab      | https://gitlab.com/api/v4         | `PRIVATE-TOKEN` header      |
| linear      | https://api.linear.app            | `Authorization: Bearer`     |
| notion      | https://api.notion.com/v1         | `Authorization: Bearer`     |
| stripe      | https://api.stripe.com/v1         | `Authorization: Bearer`     |
| sentry      | https://sentry.io                 | `Authorization: Bearer`     |
| cloudflare  | https://api.cloudflare.com/client/v4 | `Authorization: Bearer`  |
| vercel      | https://api.vercel.com            | `Authorization: Bearer`     |
| resend      | https://api.resend.com            | `Authorization: Bearer`     |
| gemini      | https://generativelanguage.googleapis.com | `x-goog-api-key` header |
| openrouter  | https://openrouter.ai/api/v1      | `Authorization: Bearer`     |
| npm         | https://registry.npmjs.org        | `Authorization: Bearer`     |
| telegram    | https://api.telegram.org          | token in URL path           |

Each built-in YAML carries a comment citing the vendor documentation its
auth shape was derived from, and its `allowed_endpoints` / `allowed_methods`
are deliberately narrow — a built-in is not a blanket grant. Every built-in
passes `Validate()` (asserted by tests).

The vault entry referenced by `entry_ref` must exist and contain the
credential. The conventional field name is `credential`; `token` and
`password` are accepted as fallbacks by the `bearer` shape. For templates
that need a custom header name (e.g. GitLab's `PRIVATE-TOKEN`), the header
value is delivered through a substitution placeholder (see below) — the
entry still only needs a `credential` field.

## Overriding a built-in with a vault-local template

User templates take precedence over built-ins. To override one, place a file
named after the template in `<vault>/templates/`:

```text
<vault>/
  templates/
    github.yaml
```

The vault-local file uses the same schema and completely replaces the
built-in of the same name. Example:

```yaml
# docs: https://docs.github.com/rest/authentication
base_url: https://api.github.com
auth_type: bearer
entry_ref: work/github
allowed_endpoints:
  - /repos/*
allowed_methods:
  - GET
```

## Template schema

```yaml
base_url: https://api.example.com        # required
auth_type: bearer | basic | header | query_param | none   # required
entry_ref: op:///example                 # required — vault entry with the credential
allowed_endpoints: [ "/path/*" ]         # glob patterns; matching ignores the query string
allowed_methods: [ GET, POST ]           # upper-case methods
default_headers: { X-Name: value }       # optional
substitutions: []                        # optional, see below
allow_private: false                     # optional; must be true for local/private hosts
```

### `auth_type`

- `bearer` — sends `Authorization: Bearer <credential|token|password>`.
- `basic` — sends HTTP Basic auth from `username` + `credential`/`password`.
- `header` — sends the header named by the entry's `header_name` field with
  the entry's `header_value` (or `credential`/`token`/`password`).
- `query_param` — sends the query parameter named by `param_name` with the
  value from `param_value` (or `credential`/`token`/`password`).
- `none` — no auth header is injected; the credential is delivered entirely
  through `substitutions`. A template with `auth_type: none` must declare at
  least one substitution.

## Substitutions

Some APIs carry their credential outside a header — in the URL path
(Telegram), a query parameter, a JSON body field, or a header with a fixed
name/prefix (GitLab's `PRIVATE-TOKEN`, Gemini's `x-goog-api-key`). The
optional `substitutions:` list covers those shapes:

```yaml
auth_type: none
default_headers:
  PRIVATE-TOKEN: __GITLAB_TOKEN__
substitutions:
  - placeholder: __GITLAB_TOKEN__
    field: credential
    in: [header]
```

Each substitution declares:

- `placeholder` — the literal text replaced in the request.
- `field` — the vault entry field the credential is read from.
- `in` — the surfaces where the placeholder is replaced: `path`, `query`,
  `header`, `body`. When omitted, the default is `path` + `query`.

Placeholder rules (enforced at template load):

- at least 4 characters;
- only RFC 3986 unreserved characters `[A-Za-z0-9_.~-]`;
- at least one alphanumeric character;
- a mandatory delimiter (`__` or a non-word character) so a short
  placeholder cannot accidentally match a legitimate URL word;
- no duplicate placeholders across substitutions.

Substituted values are resolved from the vault entry at request time, are
never logged or audited, and are redacted (`***`) from error messages if a
request fails after substitution. When `auth_type` and a substitution both
apply to the `Authorization` header, `auth_type` wins.

Example — Telegram-shaped template (token in the path):

```yaml
base_url: https://api.telegram.org/bot__BOT_TOKEN__
auth_type: none
entry_ref: op:///telegram
substitutions:
  - placeholder: __BOT_TOKEN__
    field: credential
    in: [path]
allowed_endpoints:
  - /sendMessage
allowed_methods:
  - POST
```

## Security notes

- Built-in templates never combine a root-wildcard endpoint (`/*`) with a
  mutating method.
- Requests to private/local network addresses are blocked unless the
  template sets `allow_private: true`; DNS is re-resolved at dial time so a
  rebinding attack cannot redirect injected credentials.
- Response bodies are sanitized for known credential values and common
  secret patterns before being returned to the agent.
