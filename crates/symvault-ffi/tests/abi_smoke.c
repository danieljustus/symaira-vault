#include <stdint.h>
#include <string.h>
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
    release(dec);
    release(enc);
    release(pub);
    release(id);
    return code;
}
