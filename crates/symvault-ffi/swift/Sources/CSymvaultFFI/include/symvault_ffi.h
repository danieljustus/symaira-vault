/*
 * symvault_ffi.h - C ABI of crates/symvault-ffi (FFI-001).
 *
 * Replaces the gomobile `pkg/mobilebind` bridge. Every function mirrors one
 * Go function with the same results and the same error texts.
 *
 * Conventions
 *  - Inputs are (pointer, length) byte pairs. A NULL pointer is valid only with
 *    length 0. Text arguments must be UTF-8 and need no terminator.
 *  - Every function returns a status:
 *        0  success
 *        1  Go-compatible failure: the exact Go error text is in *err
 *        2  an internal panic was contained at the boundary (text in *err)
 *        3  unusable arguments: NULL with a length, or invalid UTF-8 (text in *err)
 *  - Results are written to *out as a SvBuf owned by this library. Release
 *    every non-empty SvBuf (out and err) with symvault_buf_free, which zeroizes
 *    it first. *out and *err are always reset to empty before the call does
 *    anything else; a NULL out-parameter discards that output.
 *  - Secrets (identities, passphrases, plaintexts) are never retained by the
 *    library after the call returns.
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
