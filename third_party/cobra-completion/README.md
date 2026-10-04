# Cobra completion templates

The eight generated scripts in `testdata/port/cli/artifacts.json` contain
templates from github.com/spf13/cobra v1.10.2, pinned by `go.mod` and `go.sum`.
Copyright 2013-2023 The Cobra Authors. Their Apache-2.0 license is retained in
`LICENSE.txt` next to this notice. Upstream:
https://github.com/spf13/cobra/tree/v1.10.2.

The templates are emitted by the real Go generator without edits. The artifact
also contains symaira-vault command documentation and completion observations.
`scripts/rust-port/cli_artifacts_contract.py` records the actual Go source
revision, production inventory and probe digest used to regenerate it. The
advertised environment-derived configuration path uses a named placeholder,
rendered by the Rust shared path resolver at runtime; manual dates are likewise
rendered at runtime. ADR 0011 documents those declared substitutions.
