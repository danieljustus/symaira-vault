#!/bin/sh
# Smoke-test a built symvault container image.
# Usage: scripts/docker-smoke.sh IMAGE [EXPECTED_VERSION] [DOCKER_ARGS...]
#
# 1. `version` prints the expected version (when given).
# 2. git and ca-certificates are present (git is a hard runtime dependency,
#    docs/adr/0033-git-binary-runtime-dependency.md).
# 3. A real init / set / get round trip inside the container with an
#    environment passphrase, which also exercises the git-backed vault history.
set -eu

image="${1:?usage: docker-smoke.sh IMAGE [EXPECTED_VERSION] [DOCKER_ARGS...]}"
expected="${2:-}"
[ $# -ge 2 ] && shift 2 || shift

if [ -n "$expected" ]; then
    out="$(docker run --rm "$@" "$image" version)"
    echo "version: $out"
    case "$out" in
        *"$expected"*) ;;
        *) echo "docker-smoke: version output does not contain $expected" >&2; exit 1 ;;
    esac
else
    docker run --rm "$@" "$image" version
fi

docker run --rm "$@" --entrypoint sh "$image" -c 'git --version && test -s /etc/ssl/certs/ca-certificates.crt'

secret='Xk9-correct-horse-Battery'
got="$(docker run --rm "$@" \
    -e SYMVAULT_ALLOW_ENV_PASSPHRASE=1 -e SYMVAULT_PASSPHRASE=test-passphrase-123 \
    -e SECRET="$secret" --entrypoint sh "$image" -c '
        set -eu
        symvault init >/dev/null 2>&1
        printf "%s\n" "$SECRET" | symvault set smoke.password --stdin-value >/dev/null 2>&1
        symvault get smoke.password 2>/dev/null
    ')"
if [ "$got" != "$secret" ]; then
    echo "docker-smoke: init/set/get round trip returned an unexpected value" >&2
    exit 1
fi
echo "docker-smoke: init/set/get round trip ok"
