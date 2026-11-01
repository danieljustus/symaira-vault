//! Rust replacement for the gomobile `pkg/mobilebind` bridge (FFI-001).
//!
//! * [`api`] holds the thirteen functions with Go-identical results and error
//!   texts, built on `symvault-crypto` and `symvault-store`.
//! * [`abi`] exposes them as a narrow C ABI (`include/symvault_ffi.h`) with
//!   caller-freed buffers, an explicit error out-parameter and no unwinding
//!   across the boundary.
//!
//! The behavior is pinned by `testdata/port/ffi/mobilebind.json`, recorded from
//! the real Go functions by `scripts/rust-port/cmd/mobilebindgen`.

#![deny(unsafe_code)]

pub mod api;
mod gotext;
mod marshal;
mod vault;

#[allow(unsafe_code)]
pub mod abi;
