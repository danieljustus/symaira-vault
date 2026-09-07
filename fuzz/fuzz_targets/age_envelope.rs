#![no_main]

use std::borrow::Cow;

use base64::{Engine, engine::general_purpose::STANDARD};
use libfuzzer_sys::fuzz_target;
use symvault_crypto::{decrypt, detect_envelope, parse_argon2id_params, parse_identity};

const ID: &str = "AGE-SECRET-KEY-1HS3YTK69EJH0ZYM8ANNNDWQMPT7ZMLPYGTMC47F5T4EDJ5N7EYMQ4L5CDL";

fn decode_seed(input: &[u8]) -> Cow<'_, [u8]> {
    input
        .strip_prefix(b"b64:")
        .and_then(|encoded| STANDARD.decode(encoded).ok())
        .map(Cow::Owned)
        .unwrap_or_else(|| Cow::Borrowed(input))
}

fuzz_target!(|input: &[u8]| {
    let candidate = decode_seed(input);

    // Exercise the age header parser on arbitrary bytes. The fixed identity is
    // parsed only after the input adapter, so no input controls allocations or
    // cryptographic parameters in this harness.
    let _ = detect_envelope(&candidate);
    let identity = parse_identity(ID).expect("fixed fuzz identity");
    let _ = decrypt(&candidate, &identity);

    // Exercise the production KDF stanza parser independently. This keeps the
    // fuzz run bounded while covering every untrusted parameter string, including
    // values that would otherwise trigger an expensive derivation.
    if let Ok(value) = std::str::from_utf8(input) {
        let _ = parse_argon2id_params(value);
    }
});
