# Commercial Boundary

Symaira Vault self-hosted remains free and open source under the Apache-2.0 License.

The public repository contains the self-hosted core, CLI, runtime behavior,
documentation, and release artifacts that users can run independently. Public
contributions to this repository are accepted under the repository license.

Commercial hosted-service code lives outside this repository. That private Pro
layer may provide managed hosting, tenant operations, billing, support workflows,
cloud deployment automation, compliance operations, and monitoring.

## Rules

- Keep self-hosted functionality free and Apache-2.0 licensed in this repository.
- Do not require private code to build, test, or run the public self-hosted
  product.
- Do not copy private Pro code into the public repository.
- Do not copy public `internal/` packages into the private Pro repository.
- When the hosted service needs a new core capability, implement and release it
  publicly here first, then let the private Pro repository consume the tagged
  runtime artifact.

## Versioning Note

The current Symaira Vault release line is `v0.x`. Historical OpenPass releases
such as `v4.0.0` remain part of the old release history and must not be treated
as the current Symaira Vault release target. The next planned core milestone is
`v0.10.0`.

## Related

- [`research-handoff-eu-commercialization.md`](research-handoff-eu-commercialization.md)
  preserves the public-core findings from the EU compliance and commercialization
  research folders.
