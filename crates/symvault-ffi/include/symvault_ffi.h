#ifndef SYMVAULT_FFI_H
#define SYMVAULT_FFI_H

#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint8_t *data;
    size_t len;
} SymvaultBuffer;

typedef struct {
    SymvaultBuffer output;
    SymvaultBuffer error;
} SymvaultResult;

/* Release a Rust-owned result buffer exactly once. */
void symvault_buffer_free(SymvaultBuffer buffer);

/* All byte inputs are borrowed for the duration of the call. */
SymvaultResult symvault_generate_identity(void);
SymvaultResult symvault_identity_public_key(const uint8_t *identity, size_t identity_len);
SymvaultResult symvault_public_key_fingerprint(const uint8_t *public_key, size_t public_key_len);
SymvaultResult symvault_encrypt_with_public_key(
    const uint8_t *recipient, size_t recipient_len,
    const uint8_t *plaintext, size_t plaintext_len);
SymvaultResult symvault_decrypt_with_identity(
    const uint8_t *identity, size_t identity_len,
    const uint8_t *ciphertext, size_t ciphertext_len);
SymvaultResult symvault_encrypt_with_passphrase(
    const uint8_t *passphrase, size_t passphrase_len,
    const uint8_t *plaintext, size_t plaintext_len);
SymvaultResult symvault_decrypt_with_passphrase(
    const uint8_t *passphrase, size_t passphrase_len,
    const uint8_t *ciphertext, size_t ciphertext_len);

/* JSON output matches the Go mobile bridge; manifest result is one byte (0 or 1). */
SymvaultResult symvault_read_entry_json(
    const uint8_t *vault_dir, size_t vault_dir_len,
    const uint8_t *entry_path, size_t entry_path_len,
    const uint8_t *identity, size_t identity_len);
SymvaultResult symvault_list_entries_json(
    const uint8_t *vault_dir, size_t vault_dir_len,
    const uint8_t *prefix, size_t prefix_len,
    const uint8_t *identity, size_t identity_len);
SymvaultResult symvault_verify_manifest_integrity(
    const uint8_t *vault_dir, size_t vault_dir_len,
    const uint8_t *identity, size_t identity_len);

#endif
