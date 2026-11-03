/*
 * FFI-001 C ABI check: compiled with the system C compiler against
 * swift/Sources/CSymvaultFFI/include/symvault_ffi.h and linked with the
 * staticlib Cargo built, so a mismatch between the header and the Rust
 * `extern "C"` definitions (argument order, integer widths, struct passing)
 * shows up as a wrong result here instead of in an app.
 *
 * usage: abi_check <empty-vault-directory>
 */
#include "symvault_ffi.h"

#include <stddef.h>
#include <stdio.h>
#include <string.h>

_Static_assert(sizeof(SvBuf) == sizeof(void *) + sizeof(size_t), "SvBuf is {ptr, len}");
_Static_assert(offsetof(SvBuf, ptr) == 0, "SvBuf.ptr first");
_Static_assert(offsetof(SvBuf, len) == sizeof(void *), "SvBuf.len second");
_Static_assert(SYMVAULT_OK == 0 && SYMVAULT_ERR == 1 && SYMVAULT_PANIC == 2 && SYMVAULT_BAD_ARGS == 3,
               "status codes");

/* Every exported function with exactly the prototype the header promises. */
static int32_t (*const generate_identity)(SvBuf *, SvBuf *) = symvault_generate_identity;
static int32_t (*const identity_public_key)(const uint8_t *, size_t, SvBuf *, SvBuf *) =
    symvault_identity_public_key;
static int32_t (*const fingerprint)(const uint8_t *, size_t, SvBuf *, SvBuf *) =
    symvault_public_key_fingerprint;
static int32_t (*const encrypt_pk)(const uint8_t *, size_t, const uint8_t *, size_t, SvBuf *,
                                   SvBuf *) = symvault_encrypt_with_public_key;
static int32_t (*const decrypt_id)(const uint8_t *, size_t, const uint8_t *, size_t, SvBuf *,
                                   SvBuf *) = symvault_decrypt_with_identity;
static int32_t (*const encrypt_pw)(const uint8_t *, size_t, const uint8_t *, size_t, SvBuf *,
                                   SvBuf *) = symvault_encrypt_with_passphrase;
static int32_t (*const decrypt_pw)(const uint8_t *, size_t, const uint8_t *, size_t, SvBuf *,
                                   SvBuf *) = symvault_decrypt_with_passphrase;
static int32_t (*const init_vault)(const uint8_t *, size_t, const uint8_t *, size_t, SvBuf *) =
    symvault_init_vault;
static int32_t (*const open_vault)(const uint8_t *, size_t, const uint8_t *, size_t, SvBuf *,
                                   SvBuf *) = symvault_open_vault_with_passphrase;
static int32_t (*const read_entry)(const uint8_t *, size_t, const uint8_t *, size_t,
                                   const uint8_t *, size_t, SvBuf *, SvBuf *) =
    symvault_read_entry_json;
static int32_t (*const write_entry)(const uint8_t *, size_t, const uint8_t *, size_t,
                                    const uint8_t *, size_t, const uint8_t *, size_t, SvBuf *) =
    symvault_write_entry_json;
static int32_t (*const list_entries)(const uint8_t *, size_t, const uint8_t *, size_t,
                                     const uint8_t *, size_t, SvBuf *, SvBuf *) =
    symvault_list_entries_json;
static int32_t (*const set_backup_dir)(const uint8_t *, size_t, SvBuf *) = symvault_set_backup_dir;
static int32_t (*const push_thread_dir)(const uint8_t *, size_t, uint64_t *, SvBuf *) =
    symvault_push_thread_backup_dir;
static int32_t (*const pop_thread_dir)(uint64_t, SvBuf *) = symvault_pop_thread_backup_dir;
static int32_t (*const unwind_thread_dir)(uint64_t, SvBuf *) = symvault_unwind_thread_backup_dir;
static int32_t (*const verify_manifest)(const uint8_t *, size_t, const uint8_t *, size_t, int32_t *,
                                        SvBuf *) = symvault_verify_manifest_integrity;

static int failures;

#define CHECK(cond)                                                          \
    do {                                                                     \
        if (!(cond)) {                                                       \
            fprintf(stderr, "abi_check:%d: check failed: %s\n", __LINE__, #cond); \
            failures++;                                                      \
        }                                                                    \
    } while (0)

#define S(literal) ((const uint8_t *)(literal)), (sizeof(literal) - 1)

static SvBuf empty(void) {
    SvBuf buf = {NULL, 0};
    return buf;
}

static int equals(SvBuf buf, const char *expected) {
    return buf.len == strlen(expected) && (buf.len == 0 || memcmp(buf.ptr, expected, buf.len) == 0);
}

/* Owns a copy, so the library buffer can be released straight away. */
static size_t take(SvBuf buf, uint8_t *into, size_t capacity) {
    size_t n = buf.len < capacity ? buf.len : capacity;
    if (n > 0) memcpy(into, buf.ptr, n);
    symvault_buf_free(buf);
    return n;
}

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "usage: abi_check <vault-directory>\n");
        return 2;
    }
    const char *dir = argv[1];
    size_t dir_len = strlen(dir);
    uint8_t identity[128], recipient[128], cipher[512], listing[256], entry[512];
    size_t identity_len, recipient_len, cipher_len, listing_len, entry_len;
    SvBuf out, err;

    CHECK(symvault_ffi_abi_version() == 1);

    /* A relative backup directory is refused; an empty one restores the default. */
    err = empty();
    CHECK(set_backup_dir((const uint8_t *)"rel", 3, &err) == SYMVAULT_ERR && err.len > 0);
    symvault_buf_free(err);
    err = empty();
    CHECK(set_backup_dir(NULL, 0, &err) == SYMVAULT_OK && err.len == 0);
    symvault_buf_free(err);

    /* Thread-scoped backup directory: push/pop nest; a token is a process-unique
     * serial, so a closed scope's token is refused even when a later scope sits at
     * the same depth; unwind restores the named scope and drops leaked inner ones;
     * a null token pointer and a relative path never open a scope. */
    {
        uint64_t outer = 0, inner = 0, again = 0, leaked = 0;
        err = empty();
        CHECK(push_thread_dir(S("/tmp/outer"), &outer, &err) == SYMVAULT_OK && outer != 0 && err.len == 0);
        symvault_buf_free(err);
        err = empty();
        CHECK(push_thread_dir(S("/tmp/inner"), &inner, &err) == SYMVAULT_OK && inner != 0 && inner != outer);
        symvault_buf_free(err);
        err = empty();
        CHECK(pop_thread_dir(outer, &err) == SYMVAULT_ERR && err.len > 0);
        symvault_buf_free(err);
        err = empty();
        CHECK(pop_thread_dir(inner, &err) == SYMVAULT_OK && err.len == 0);
        symvault_buf_free(err);
        err = empty();
        CHECK(pop_thread_dir(outer, &err) == SYMVAULT_OK && err.len == 0);
        symvault_buf_free(err);
        err = empty();
        CHECK(pop_thread_dir(outer, &err) == SYMVAULT_ERR && err.len > 0);
        symvault_buf_free(err);
        /* Push/pop/push/pop(stale): depth 1 again, but the old token is dead. */
        err = empty();
        CHECK(push_thread_dir(S("/tmp/again"), &again, &err) == SYMVAULT_OK && again != 0 && again != outer && again != inner);
        symvault_buf_free(err);
        err = empty();
        CHECK(pop_thread_dir(outer, &err) == SYMVAULT_ERR && err.len > 0);
        symvault_buf_free(err);
        err = empty();
        CHECK(unwind_thread_dir(outer, &err) == SYMVAULT_ERR && err.len > 0);
        symvault_buf_free(err);
        /* Unwind closes the named scope and the leaked scope inside it. */
        err = empty();
        CHECK(push_thread_dir(S("/tmp/leaked"), &leaked, &err) == SYMVAULT_OK);
        symvault_buf_free(err);
        err = empty();
        CHECK(pop_thread_dir(again, &err) == SYMVAULT_ERR && err.len > 0);
        symvault_buf_free(err);
        err = empty();
        CHECK(unwind_thread_dir(again, &err) == SYMVAULT_OK && err.len == 0);
        symvault_buf_free(err);
        err = empty();
        CHECK(pop_thread_dir(leaked, &err) == SYMVAULT_ERR && err.len > 0);
        symvault_buf_free(err);
        err = empty();
        CHECK(unwind_thread_dir(again, &err) == SYMVAULT_ERR && err.len > 0);
        symvault_buf_free(err);
        err = empty();
        CHECK(push_thread_dir(S("rel"), &outer, &err) == SYMVAULT_ERR && outer == 0);
        symvault_buf_free(err);
        err = empty();
        CHECK(push_thread_dir(S("/tmp/x"), NULL, &err) == SYMVAULT_BAD_ARGS);
        symvault_buf_free(err);
    }

    out = empty(); err = empty();
    CHECK(generate_identity(&out, &err) == SYMVAULT_OK);
    CHECK(out.len == 74 && memcmp(out.ptr, "AGE-SECRET-KEY-1", 16) == 0 && err.len == 0);
    identity_len = take(out, identity, sizeof identity);
    symvault_buf_free(err);

    out = empty(); err = empty();
    CHECK(identity_public_key(identity, identity_len, &out, &err) == SYMVAULT_OK);
    CHECK(out.len == 62 && memcmp(out.ptr, "age1", 4) == 0);
    recipient_len = take(out, recipient, sizeof recipient);

    out = empty(); err = empty();
    CHECK(fingerprint(recipient, recipient_len, &out, &err) == SYMVAULT_OK && out.len > 0);
    symvault_buf_free(out);
    symvault_buf_free(err);

    /* public-key round trip */
    out = empty(); err = empty();
    CHECK(encrypt_pk(recipient, recipient_len, S("hello, symvault\n"), &out, &err) == SYMVAULT_OK);
    cipher_len = take(out, cipher, sizeof cipher);
    out = empty(); err = empty();
    CHECK(decrypt_id(identity, identity_len, cipher, cipher_len, &out, &err) == SYMVAULT_OK);
    CHECK(equals(out, "hello, symvault\n"));
    symvault_buf_free(out);

    /* The scrypt calls are exercised on their argument order only: a key
     * derivation at work factor 18 takes tens of seconds in the unoptimized
     * library this test links, and the fixture replay covers their results. */
    out = empty(); err = empty();
    CHECK(encrypt_pw(NULL, 0, S("x"), &out, &err) == SYMVAULT_ERR && equals(err, "passphrase is empty"));
    symvault_buf_free(err);
    out = empty(); err = empty();
    CHECK(encrypt_pw(S("pw"), NULL, 0, &out, &err) == SYMVAULT_ERR && equals(err, "plaintext is empty"));
    symvault_buf_free(err);
    out = empty(); err = empty();
    CHECK(decrypt_pw(S("pw"), NULL, 0, &out, &err) == SYMVAULT_ERR && equals(err, "ciphertext is empty"));
    symvault_buf_free(err);

    /* failure: Go's text in *err, status 1 */
    out = empty(); err = empty();
    CHECK(identity_public_key(S("nope"), &out, &err) == SYMVAULT_ERR);
    CHECK(err.len > 19 && memcmp(err.ptr, "validate identity: ", 19) == 0);
    symvault_buf_free(err);

    /* NULL with a length is refused, NULL out-parameters are tolerated */
    out = empty(); err = empty();
    CHECK(identity_public_key(NULL, 3, &out, &err) == SYMVAULT_BAD_ARGS && equals(err, "argument identity is null"));
    symvault_buf_free(err);
    CHECK(identity_public_key(NULL, 0, NULL, NULL) == SYMVAULT_ERR);

    /* a vault: init, open, write, read, list, verify */
    /* a passphrase is raw bytes: this one is not valid UTF-8 and holds a NUL */
    static const uint8_t raw_passphrase[] = {0xff, 0xfe, 'p', 0x00, 'w'};
    err = empty();
    CHECK(init_vault((const uint8_t *)dir, dir_len, raw_passphrase, sizeof raw_passphrase, &err) == SYMVAULT_OK && err.len == 0);
    out = empty(); err = empty();
    CHECK(open_vault((const uint8_t *)dir, dir_len, raw_passphrase, sizeof raw_passphrase, &out, &err) == SYMVAULT_OK);
    identity_len = take(out, identity, sizeof identity);
    CHECK(identity_len == 74);
    err = empty();
    CHECK(write_entry((const uint8_t *)dir, dir_len, S("a/b"), S("{\"data\":{\"k\":\"v\"}}"),
                      identity, identity_len, &err) == SYMVAULT_OK);
    out = empty(); err = empty();
    CHECK(read_entry((const uint8_t *)dir, dir_len, S("a/b"), identity, identity_len, &out, &err) == SYMVAULT_OK);
    entry_len = take(out, entry, sizeof entry - 1);
    entry[entry_len] = 0;
    CHECK(strstr((const char *)entry, "\"data\":{\"k\":\"v\"}") != NULL);
    out = empty(); err = empty();
    CHECK(list_entries((const uint8_t *)dir, dir_len, S(""), identity, identity_len, &out, &err) == SYMVAULT_OK);
    listing_len = take(out, listing, sizeof listing);
    CHECK(listing_len == 7 && memcmp(listing, "[\"a/b\"]", 7) == 0);
    int32_t ok = 7;
    err = empty();
    CHECK(verify_manifest((const uint8_t *)dir, dir_len, identity, identity_len, &ok, &err) == SYMVAULT_OK);
    CHECK(ok == 1);

    if (failures != 0) {
        fprintf(stderr, "abi_check: %d failure(s)\n", failures);
        return 1;
    }
    printf("abi_check: ok\n");
    return 0;
}
