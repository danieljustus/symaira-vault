/*
 * symvault_ffi.h - C ABI of crates/symvault-ffi (FFI-001).
 *
 * Replaces the gomobile `pkg/mobilebind` bridge. Every function mirrors one
 * Go function with the same results and the same error texts.
 *
 * Conventions
 *  - Inputs are (pointer, length) byte pairs. A NULL pointer is valid only with
 *    length 0. Arguments that name text (vault directory, entry path, prefix,
 *    entry JSON, identity, recipient, public key) must be valid UTF-8; no
 *    terminator is needed. Passphrases are raw bytes, exactly like Go's
 *    []byte(passphrase): any byte sequence is accepted, including invalid UTF-8
 *    and NUL, and the same bytes always derive the same key. (The Swift wrapper
 *    takes a String and therefore always passes UTF-8.)
 *  - Every function returns a status:
 *        0  success
 *        1  Go-compatible failure: the exact Go error text is in *err
 *        2  an internal panic was contained at the boundary (text in *err)
 *        3  unusable arguments: NULL with a length, or invalid UTF-8 in a text
 *           argument (text in *err)
 *  - Results are written to *out as a SvBuf owned by this library. *out and
 *    *err are reset to empty before the call does anything else; a NULL
 *    out-parameter discards that output (it is zeroized and freed inside the
 *    call). Every non-empty SvBuf a call hands back - *out and *err are two
 *    separate buffers - must be released exactly once with symvault_buf_free,
 *    which zeroizes it first. Do not free one twice, do not free a copy of the
 *    struct after freeing the original, and never free a buffer with free().
 *  - The library keeps no copy of identities, passphrases or plaintexts after
 *    the call returns and zeroizes the intermediates it controls (entry data,
 *    key material, result buffers). Not covered: reallocation leftovers inside
 *    Rust collections or serde_json, entry metadata strings, and copies the
 *    caller makes (for example Swift Strings and Data built from a result).
 *  - Calls are thread-safe; vault operations on one directory serialize on the
 *    store's own locks.
 */
#ifndef SYMVAULT_FFI_H
#define SYMVAULT_FFI_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct SvBuf {
    uint8_t *ptr;
    size_t len;
} SvBuf;

enum {
    SYMVAULT_OK = 0,
    SYMVAULT_ERR = 1,
    SYMVAULT_PANIC = 2,
    SYMVAULT_BAD_ARGS = 3,
};

/* ABI revision; bumped when any signature changes. Currently 1. */
uint32_t symvault_ffi_abi_version(void);

/* Zeroizes and releases a buffer returned by this library. Empty is a no-op. */
void symvault_buf_free(SvBuf buf);

/* GenerateIdentity() (string, error) */
int32_t symvault_generate_identity(SvBuf *out, SvBuf *err);

/* IdentityPublicKey(identity) (string, error) */
int32_t symvault_identity_public_key(const uint8_t *identity, size_t identity_len,
                                     SvBuf *out, SvBuf *err);

/* PublicKeyFingerprint(pubkey) string - cannot fail, *err stays empty. */
int32_t symvault_public_key_fingerprint(const uint8_t *pubkey, size_t pubkey_len,
                                        SvBuf *out, SvBuf *err);

/* EncryptWithPublicKey(recipient, plaintext) ([]byte, error) */
int32_t symvault_encrypt_with_public_key(const uint8_t *recipient, size_t recipient_len,
                                         const uint8_t *plaintext, size_t plaintext_len,
                                         SvBuf *out, SvBuf *err);

/* DecryptWithIdentity(identity, ciphertext) ([]byte, error) */
int32_t symvault_decrypt_with_identity(const uint8_t *identity, size_t identity_len,
                                       const uint8_t *ciphertext, size_t ciphertext_len,
                                       SvBuf *out, SvBuf *err);

/* EncryptWithPassphrase(passphrase, plaintext) ([]byte, error) */
int32_t symvault_encrypt_with_passphrase(const uint8_t *passphrase, size_t passphrase_len,
                                         const uint8_t *plaintext, size_t plaintext_len,
                                         SvBuf *out, SvBuf *err);

/* DecryptWithPassphrase(passphrase, ciphertext) ([]byte, error) */
int32_t symvault_decrypt_with_passphrase(const uint8_t *passphrase, size_t passphrase_len,
                                         const uint8_t *ciphertext, size_t ciphertext_len,
                                         SvBuf *out, SvBuf *err);

/* InitVault(vaultDir, passphrase) error */
int32_t symvault_init_vault(const uint8_t *vault_dir, size_t vault_dir_len,
                            const uint8_t *passphrase, size_t passphrase_len,
                            SvBuf *err);

/* Rust-only: directory for the verified pre-migration backup of a Go-created
 * vault (empty path = $XDG_STATE_HOME/$HOME default). Call before the first
 * write; a host without a usable home directory must set it. Excluding the
 * directory from iCloud backup is the host's responsibility. */
int32_t symvault_set_backup_dir(const uint8_t *dir, size_t dir_len, SvBuf *err);
/* Calling-thread override; replaces the thread's value outright (empty clears
 * it). For a bounded scope use push/pop below, which restore the displaced value. */
int32_t symvault_set_thread_backup_dir(const uint8_t *dir, size_t dir_len, SvBuf *err);
/* Opens a nestable calling-thread scope: installs dir (empty = no override) and
 * saves the displaced value; *token identifies the scope (never 0). Pop it on
 * every exit path, on the same thread. */
int32_t symvault_push_thread_backup_dir(const uint8_t *dir, size_t dir_len, uint64_t *token,
                                        SvBuf *err);
/* Closes the innermost scope and restores exactly what it displaced; a token that is
 * not the innermost open scope is refused (status 1) and changes nothing. */
int32_t symvault_pop_thread_backup_dir(uint64_t token, SvBuf *err);

/* OpenVaultWithPassphrase(vaultDir, passphrase) (string, error) */
int32_t symvault_open_vault_with_passphrase(const uint8_t *vault_dir, size_t vault_dir_len,
                                            const uint8_t *passphrase, size_t passphrase_len,
                                            SvBuf *out, SvBuf *err);

/* ReadEntryJSON(vaultDir, entryPath, identity) (string, error) */
int32_t symvault_read_entry_json(const uint8_t *vault_dir, size_t vault_dir_len,
                                 const uint8_t *entry_path, size_t entry_path_len,
                                 const uint8_t *identity, size_t identity_len,
                                 SvBuf *out, SvBuf *err);

/* WriteEntryJSON(vaultDir, entryPath, entryJSON, identity) error */
int32_t symvault_write_entry_json(const uint8_t *vault_dir, size_t vault_dir_len,
                                  const uint8_t *entry_path, size_t entry_path_len,
                                  const uint8_t *entry_json, size_t entry_json_len,
                                  const uint8_t *identity, size_t identity_len,
                                  SvBuf *err);

/* ListEntriesJSON(vaultDir, prefix, identity) (string, error) */
int32_t symvault_list_entries_json(const uint8_t *vault_dir, size_t vault_dir_len,
                                   const uint8_t *prefix, size_t prefix_len,
                                   const uint8_t *identity, size_t identity_len,
                                   SvBuf *out, SvBuf *err);

/* VerifyManifestIntegrity(vaultDir, identity) (bool, error); *ok is 1 or 0. */
int32_t symvault_verify_manifest_integrity(const uint8_t *vault_dir, size_t vault_dir_len,
                                           const uint8_t *identity, size_t identity_len,
                                           int32_t *ok, SvBuf *err);

#ifdef __cplusplus
}
#endif

#endif /* SYMVAULT_FFI_H */
