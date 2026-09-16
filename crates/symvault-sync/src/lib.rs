#![deny(unsafe_code)]

//! Standalone synchronization and import/export contracts for Symaira Vault.
//! The Go implementation remains the production oracle; this crate exposes
//! deterministic, adapter-friendly Rust building blocks for the RUST-008 slice.

pub mod archive;
pub mod devices;
pub mod export;
pub mod git;
pub mod importer;
pub mod intake;
pub mod pairing;
pub mod recipients;
pub mod reconcile;
pub mod safeio;
pub mod winner;

pub use archive::{ArchiveEntry, ArchiveError, backup, restore};
pub use devices::{Device, DeviceError, DeviceList, DeviceRegistry};
pub use git::{Commit, CommitOptions, GitError, GitRepository, GitStatus, PullResult, PushResult};
pub use pairing::{
    GoTime, JoinResponse, PairingError, PairingFile, TokenStore, display_token, generate_token,
    marshal_join_response, marshal_pairing_file, parse_join_response, parse_pairing_file,
    response_filenames, validate_pairing_token,
};
pub use recipients::{RecipientsError, RecipientsFile};
pub use reconcile::{Conflict, ReconcileInput, ReconcileOutput, reconcile};
pub use winner::winner_by_version;
