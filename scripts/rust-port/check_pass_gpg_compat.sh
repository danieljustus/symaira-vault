#!/bin/sh
set -eu

root=$(git rev-parse --show-toplevel)
gpg_bin=$(command -v gpg) || {
	printf '%s\n' 'NOT RUN: gpg is required for real pass ciphertext compatibility.' >&2
	exit 77
}
tmp=$(mktemp -d /tmp/symvault-pass-gpg.XXXXXX)
trap 'rm -rf "$tmp"' EXIT HUP INT TERM
export GNUPGHOME="$tmp/gnupg"
mkdir -m 700 "$GNUPGHOME"
mkdir -m 700 "$tmp/other-gnupg"

"$gpg_bin" --batch --homedir "$GNUPGHOME" --pinentry-mode loopback --passphrase '' \
	--quick-generate-key 'Symaira pass compatibility <pass-good@example.invalid>' rsa2048 encr 0
"$gpg_bin" --batch --homedir "$tmp/other-gnupg" --pinentry-mode loopback --passphrase '' \
	--quick-generate-key 'Symaira wrong recipient <pass-wrong@example.invalid>' rsa2048 encr 0
good_fpr=$("$gpg_bin" --batch --homedir "$GNUPGHOME" --with-colons --list-secret-keys |
	awk -F: '$1 == "fpr" { print $10; exit }')
bad_fpr=$("$gpg_bin" --batch --homedir "$tmp/other-gnupg" --with-colons --list-secret-keys |
	awk -F: '$1 == "fpr" { print $10; exit }')
"$gpg_bin" --batch --homedir "$tmp/other-gnupg" --export "$bad_fpr" > "$tmp/wrong-public-key.gpg"
"$gpg_bin" --batch --homedir "$GNUPGHOME" --import "$tmp/wrong-public-key.gpg"

mkdir -p "$tmp/store/Personal" "$tmp/wrong-store/Personal"
cat > "$tmp/pass-entry.txt" <<'EOF'
synthetic-password
url: https://example.test/login
username: alice
otpauth://totp/example?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP
otpauth://totp/broken?secret=bad
first note
second note
EOF
"$gpg_bin" --batch --homedir "$GNUPGHOME" --yes --trust-model always --recipient "$good_fpr" \
	--output "$tmp/store/Personal/Example Entry.gpg" --encrypt "$tmp/pass-entry.txt"
"$gpg_bin" --batch --homedir "$GNUPGHOME" --yes --trust-model always --recipient "$bad_fpr" \
	--output "$tmp/wrong-store/Personal/Example Entry.gpg" --encrypt "$tmp/pass-entry.txt"

export SYMVAULT_PASS_GPG_STORE="$tmp/store"
export SYMVAULT_PASS_GPG_BAD_STORE="$tmp/wrong-store"
printf 'gpg: %s\n' "$($gpg_bin --version | sed -n '1p')"
cd "$root"
cargo test -p symvault-sync --test pass_gpg_compat -- --ignored --nocapture
