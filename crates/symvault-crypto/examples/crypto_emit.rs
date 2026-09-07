use base64::{Engine, engine::general_purpose::STANDARD};
use symvault_crypto::{
    Argon2idParams, SecretBytes, encrypt, encrypt_argon2id, encrypt_scrypt, parse_identity,
    parse_recipient,
};

fn main() {
    let first = parse_identity(
        "AGE-SECRET-KEY-1HS3YTK69EJH0ZYM8ANNNDWQMPT7ZMLPYGTMC47F5T4EDJ5N7EYMQ4L5CDL",
    )
    .expect("fixed identity");
    let second = parse_recipient("age1wxknyar29luhmltc320wnllzxd7n0cjvldxqjunyh9u3l4gpd3kq9r4lgr")
        .expect("fixed recipient");
    let passphrase = SecretBytes::new(b"rust-interop-fixture-passphrase-v1");
    let age = encrypt(
        b"Rust encrypts age for Go",
        &[
            parse_recipient(&symvault_crypto::recipient_string(&first)).unwrap(),
            second,
        ],
    )
    .expect("age encryption");
    let original = encrypt(
        b"Rust re-encrypts age for Go",
        &[parse_recipient(&symvault_crypto::recipient_string(&first)).unwrap()],
    )
    .expect("original encryption");
    let reencrypted = symvault_crypto::reencrypt(
        &original,
        &first,
        &[
            parse_recipient(&symvault_crypto::recipient_string(&first)).unwrap(),
            parse_recipient("age1wxknyar29luhmltc320wnllzxd7n0cjvldxqjunyh9u3l4gpd3kq9r4lgr")
                .unwrap(),
        ],
    )
    .expect("re-encryption");
    let scrypt =
        encrypt_scrypt(b"Rust encrypts scrypt for Go", &passphrase, 12).expect("scrypt encryption");
    let argon = encrypt_argon2id(
        b"Rust encrypts argon2id for Go",
        &passphrase,
        Argon2idParams {
            time: 1,
            memory_kib: 32,
            threads: 1,
        },
    )
    .expect("argon2id encryption");
    println!("age={}", STANDARD.encode(age));
    println!("reencrypt={}", STANDARD.encode(reencrypted));
    println!("scrypt={}", STANDARD.encode(scrypt));
    println!("argon2id={}", STANDARD.encode(argon));
}
