# Commercial Boundary

Symaira Vault self-hosted remains free and open source under the Apache-2.0 License.

The public repository contains the self-hosted core, CLI, runtime behavior,
documentation, and release artifacts that users can run independently. Public
contributions to this repository are accepted under the repository license.

There is no separate Pro edition. Symaira Vault ships as one product; there is no
private counterpart repository holding managed hosting, tenant operations,
billing, or compliance tooling, and none is planned.

## Rules

- Keep self-hosted functionality free and Apache-2.0 licensed in this repository.
- Do not require private code to build, test, or run the public self-hosted
  product.
- Do not add billing, tenant-management, hosted-account, or subscription code.
- Managed hosting, SSO/SCIM, hosted RBAC, SIEM export, and compliance operations
  are out of scope. If any of it is ever built, it must not turn this repository
  into a feature-limited client.

## Versioning Note

The current Symaira Vault release line is `v0.x`. Historical OpenPass releases
such as `v4.0.0` remain part of the old release history and must not be treated
as the current Symaira Vault release target. The next planned core milestone is
`v0.16.0`.

## Related

- [`research-handoff-eu-commercialization.md`](research-handoff-eu-commercialization.md)
  preserves the public-core findings from the EU compliance and commercialization
  research folders.
