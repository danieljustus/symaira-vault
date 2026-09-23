#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include "symvault_ffi.h"

static int ok(SymvaultResult r) { return r.error.len == 0 && r.output.len != 0; }
static void release(SymvaultResult r) {
    symvault_buffer_free(r.output);
    symvault_buffer_free(r.error);
}

int main(void) {
    SymvaultResult id = symvault_generate_identity();
    if (!ok(id)) return 1;
    SymvaultResult pub = symvault_identity_public_key(id.output.data, id.output.len);
    if (!ok(pub)) { release(id); return 2; }
    uint8_t raw[] = { 0xff, 0, 0x80, 0x41 };
    SymvaultResult enc = symvault_encrypt_with_public_key(pub.output.data, pub.output.len, raw, sizeof raw);
    if (!ok(enc)) { release(pub); release(id); return 3; }
    SymvaultResult dec = symvault_decrypt_with_identity(id.output.data, id.output.len, enc.output.data, enc.output.len);
    int code = ok(dec) && dec.output.len == sizeof raw && memcmp(dec.output.data, raw, sizeof raw) == 0 ? 0 : 4;
    const uint8_t bad_identity[] = "invalid";
    const uint8_t path[] = ".";
    SymvaultResult read = symvault_read_entry_json(path, sizeof path - 1, path, sizeof path - 1, bad_identity, sizeof bad_identity - 1);
    SymvaultResult list = symvault_list_entries_json(path, sizeof path - 1, path, sizeof path - 1, bad_identity, sizeof bad_identity - 1);
    SymvaultResult verify = symvault_verify_manifest_integrity(path, sizeof path - 1, bad_identity, sizeof bad_identity - 1);
    if (!code && (read.error.len == 0 || list.error.len == 0 || verify.error.len == 0)) code = 5;
    const uint8_t entry_path[] = "services/example";
    const uint8_t invalid_json[] = "{";
    SymvaultResult write = symvault_write_entry_json(
        path, sizeof path - 1,
        entry_path, sizeof entry_path - 1,
        invalid_json, sizeof invalid_json - 1,
        id.output.data, id.output.len);
    if (!code && (write.error.len == 0 || write.output.len != 0)) code = 6;
    release(write);
    const uint8_t passphrase[] = "test passphrase";
    const uint8_t invalid_ciphertext[] = "not an age envelope";
    SymvaultResult argon = symvault_decrypt_with_passphrase_argon2id(
        passphrase, sizeof passphrase - 1,
        invalid_ciphertext, sizeof invalid_ciphertext - 1);
    if (!code && (argon.error.len == 0 || argon.output.len != 0)) code = 7;
    release(argon);
    release(verify);
    release(list);
    release(read);
    release(dec);
    release(enc);
    release(pub);
    release(id);
    const char *tmp_root = getenv("TMPDIR");
    char vault[PATH_MAX];
    if (!tmp_root || snprintf(vault, sizeof vault, "%s/symvault-ffi-abi-XXXXXX", tmp_root) >= (int)sizeof vault) {
        return code ? code : 8;
    }
    if (!mkdtemp(vault)) return code ? code : 8;
    const uint8_t init_passphrase[] = "C ABI fixture passphrase";
    SymvaultResult initialized = symvault_init_vault(
        (const uint8_t *)vault, strlen(vault), init_passphrase, sizeof init_passphrase - 1);
    if (initialized.error.len != 0 || initialized.output.len != 0) code = code ? code : 9;
    release(initialized);
    SymvaultResult opened = symvault_open_vault_with_passphrase(
        (const uint8_t *)vault, strlen(vault), init_passphrase, sizeof init_passphrase - 1);
    if (!code && (!ok(opened) || opened.output.len == 0)) code = 10;
    const uint8_t mobile_entry_path[] = "abi-smoke";
    const uint8_t mobile_entry_json[] = "{\"data\":{\"username\":\"ffi-abi\"}}";
    SymvaultResult written = symvault_write_entry_json(
        (const uint8_t *)vault, strlen(vault),
        mobile_entry_path, sizeof mobile_entry_path - 1,
        mobile_entry_json, sizeof mobile_entry_json - 1,
        opened.output.data, opened.output.len);
    if (!code && (written.error.len != 0 || written.output.len != 0)) code = 11;
    release(written);
    const uint8_t empty_prefix[] = "";
    SymvaultResult listed = symvault_list_entries_json(
        (const uint8_t *)vault, strlen(vault),
        empty_prefix, 0, opened.output.data, opened.output.len);
    const uint8_t expected_list[] = "[\"abi-smoke\"]";
    if (!code && (listed.error.len != 0 || listed.output.len != sizeof expected_list - 1 ||
                  memcmp(listed.output.data, expected_list, sizeof expected_list - 1) != 0)) {
        code = 12;
    }
    release(listed);
    SymvaultResult manifest = symvault_verify_manifest_integrity(
        (const uint8_t *)vault, strlen(vault), opened.output.data, opened.output.len);
    if (!code && (manifest.error.len != 0 || manifest.output.len != 1 ||
                  manifest.output.data[0] != 1)) {
        code = 13;
    }
    release(manifest);
    release(opened);
    char cleanup_path[sizeof vault + sizeof "/identity.age"];
    (void)snprintf(cleanup_path, sizeof cleanup_path, "%s/identity.age", vault);
    (void)unlink(cleanup_path);
    (void)snprintf(cleanup_path, sizeof cleanup_path, "%s/config.yaml", vault);
    (void)unlink(cleanup_path);
    (void)snprintf(cleanup_path, sizeof cleanup_path, "%s/entries", vault);
    (void)rmdir(cleanup_path);
    (void)rmdir(vault);
    return code;
}
