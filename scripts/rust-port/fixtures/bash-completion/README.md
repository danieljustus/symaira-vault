# Vendored bash-completion (test prerequisite)

The CLI artifact contract (`cli_artifacts_contract.py`) sources the real
[bash-completion](https://github.com/scop/bash-completion) library to run Cobra-style completion scripts in a
native `bash`. Replay must not need the network, so the two files are committed, pinned to upstream commit
`79d225bad8939a3833314b5af93509131c03f2f8`; the contract refuses any other bytes.

| file | upstream path | sha256 |
|---|---|---|
| `bash_completion` | `bash_completion` | `f347b832c91d44358bb335e69fa7576241d67040795a1a4d8897317c739d35b1` |
| `000_bash_completion_compat.bash` | `bash_completion.d/000_bash_completion_compat.bash` | `ffe73ddfefc93936eae2a8aac8a3f749da8ed160485717393a272e84f9c754e2` |
| `COPYING` | `COPYING` | `8177f97513213526df2cf6184d8ff986c675afb514d4e68a404010521b880643` |

License: bash-completion is GPL-2.0-or-later (`COPYING`). These files are used as test input only, are never
linked into or shipped with a Symaira Vault artifact, and are kept out of the Cargo packages. Remove the
directory together with the Bash completion contract when the Go oracle is retired.
