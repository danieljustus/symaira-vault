#![deny(unsafe_code)]

//! Standalone synchronization and import/export contracts for Symaira Vault.
//! The Go implementation remains the production oracle; this crate exposes
//! deterministic, adapter-friendly Rust building blocks for the RUST-008 slice.

pub mod archive;
pub mod export;
pub mod git;
pub mod importer;
pub mod intake;
pub mod reconcile;

pub use archive::{ArchiveEntry, ArchiveError, backup, restore};
pub use git::{Commit, CommitOptions, GitError, GitRepository, GitStatus, PullResult, PushResult};
pub use reconcile::{Conflict, ReconcileInput, ReconcileOutput, reconcile};
