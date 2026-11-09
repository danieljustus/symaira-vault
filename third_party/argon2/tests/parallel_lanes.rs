//! Lane-parallel block filling must stay bit-identical to Go's
//! `golang.org/x/crypto/argon2.IDKey` for the production parameters
//! (`t=3, m=65536, p=4`) and other lane counts.
//!
//! The expected keys were generated with `argon2.IDKey([]byte("par-test-pass"),
//! []byte("par-test-salt-16"), t, m, p, 32)` from golang.org/x/crypto v0.58.0.

#![cfg(feature = "alloc")]

use argon2::{Algorithm, Argon2, Params, Version};
use hex_literal::hex;

const PASSWORD: &[u8] = b"par-test-pass";
const SALT: &[u8] = b"par-test-salt-16";

fn id_key(m: u32, t: u32, p: u32) -> [u8; 32] {
    let params = Params::new(m, t, p, Some(32)).unwrap();
    let mut out = [0u8; 32];
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(PASSWORD, SALT, &mut out)
        .unwrap();
    out
}

#[test]
fn go_vector_production_parameters_four_lanes() {
    assert_eq!(
        id_key(65536, 3, 4),
        hex!("7397005bab342e2725ea88603ed18f9a8116c666d01a20a08405c7ab3cb904f6")
    );
}

#[test]
fn go_vector_three_lanes() {
    assert_eq!(
        id_key(65536, 3, 3),
        hex!("42ee3641d228dee107c2bab475ad64e66d8189c23d1c2bc5aad5b974ceefbe66")
    );
}

#[test]
fn go_vector_single_lane() {
    assert_eq!(
        id_key(65536, 3, 1),
        hex!("8aa37c0b43e0a4a510799c1c5f132b10af43fb9ae1957abba1716afd72bb5779")
    );
}

#[test]
fn go_vector_two_lanes() {
    assert_eq!(
        id_key(4096, 2, 2),
        hex!("9b5b2651d579e9823b33649ab3e6152eef34fcfa342b48ad8042743c763c81bd")
    );
}

#[test]
fn go_vector_eight_lanes() {
    assert_eq!(
        id_key(8192, 4, 8),
        hex!("38fe87231795c11a1f73cfcec03902fc93941cd84ed01c79e5b0aa0448be0290")
    );
}

#[test]
fn go_vector_small_memory_four_lanes() {
    assert_eq!(
        id_key(32, 3, 4),
        hex!("9318b2f7115ea46d47874d2d42da7198a6c8c718ed4b19b7d83396fc41452c8d")
    );
}
