use std::sync::{Condvar, Mutex};
use std::time::{Duration, Instant};

use crate::{Argon2idParams, CryptoError, FailureClass};

/// Host execution policy; the existing age stanza and HKDF remain unchanged.
pub const POLICY_VERSION: &str = "argon2-resources-v1";
pub const MAX_TIME: u32 = 4;
pub const MAX_MEMORY_KIB: u32 = 128 * 1024;
pub const MAX_THREADS: u32 = 4;
const MEMORY_BUDGET_KIB: u32 = 256 * 1024;
const MAX_ACTIVE: usize = 4;
const MAX_WAITERS: usize = 32;
const WAIT_LIMIT: Duration = Duration::from_secs(10);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ReadMode {
    Automatic,
    LegacyMigration,
}

pub(crate) fn validate(params: Argon2idParams, mode: ReadMode) -> Result<(), CryptoError> {
    if mode == ReadMode::Automatic
        && (params.time > MAX_TIME
            || params.memory_kib > MAX_MEMORY_KIB
            || params.threads > MAX_THREADS)
    {
        return Err(policy_error());
    }
    Ok(())
}

pub(crate) const fn policy_error() -> CryptoError {
    CryptoError::new(
        FailureClass::ResourcePolicy,
        "argon2id resource policy: use migrate kdf --allow-legacy-kdf for a historical identity",
    )
}

fn busy() -> CryptoError {
    CryptoError::new(FailureClass::ResourceBusy, "argon2id resources busy")
}

#[derive(Default)]
struct State {
    memory: u32,
    active: usize,
    waiters: usize,
    legacy: bool,
}

pub(crate) struct Admission {
    state: Mutex<State>,
    changed: Condvar,
}

impl Admission {
    pub(crate) const fn new() -> Self {
        Self {
            state: Mutex::new(State {
                memory: 0,
                active: 0,
                waiters: 0,
                legacy: false,
            }),
            changed: Condvar::new(),
        }
    }

    fn fits(state: &State, memory: u32, mode: ReadMode) -> bool {
        if mode == ReadMode::LegacyMigration {
            return state.active == 0;
        }
        !state.legacy && state.active < MAX_ACTIVE && state.memory + memory <= MEMORY_BUDGET_KIB
    }

    pub(crate) fn acquire(&self, memory: u32, mode: ReadMode) -> Result<Lease<'_>, CryptoError> {
        let mut state = self.state.lock().map_err(|_| busy())?;
        if !Self::fits(&state, memory, mode) {
            if state.waiters >= MAX_WAITERS {
                return Err(busy());
            }
            state.waiters += 1;
            let deadline = Instant::now() + WAIT_LIMIT;
            while !Self::fits(&state, memory, mode) {
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    state.waiters -= 1;
                    return Err(busy());
                }
                match self.changed.wait_timeout(state, remaining) {
                    Ok((updated, _)) => state = updated,
                    Err(error) => {
                        error.into_inner().0.waiters -= 1;
                        return Err(busy());
                    }
                }
            }
            state.waiters -= 1;
            if Instant::now() >= deadline {
                return Err(busy());
            }
        }
        state.memory += memory;
        state.active += 1;
        state.legacy = mode == ReadMode::LegacyMigration;
        Ok(Lease {
            admission: self,
            memory,
        })
    }
}

pub(crate) static PROCESS: Admission = Admission::new();

pub(crate) struct Lease<'a> {
    admission: &'a Admission,
    memory: u32,
}

impl Drop for Lease<'_> {
    fn drop(&mut self) {
        let mut state = self
            .admission
            .state
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        state.memory -= self.memory;
        state.active -= 1;
        state.legacy = false;
        self.admission.changed.notify_all();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn queue_exhaustion_rejects_real_kdf_and_admitted_derivations_release() {
        let admission = Admission::new();
        let first = admission.acquire(128 * 1024, ReadMode::Automatic).unwrap();
        let second = admission.acquire(128 * 1024, ReadMode::Automatic).unwrap();
        std::thread::scope(|scope| {
            let mut tasks = Vec::new();
            for _ in 0..MAX_WAITERS {
                let admission = &admission;
                tasks.push(scope.spawn(move || {
                    crate::derive_admitted(
                        b"public fixture",
                        b"0123456789abcdef",
                        Argon2idParams {
                            time: 1,
                            memory_kib: 32,
                            threads: 1,
                        },
                        ReadMode::Automatic,
                        admission,
                    )
                }));
            }
            let deadline = Instant::now() + Duration::from_secs(2);
            while admission.state.lock().unwrap().waiters != MAX_WAITERS {
                assert!(
                    Instant::now() < deadline,
                    "real KDF calls failed to enter admission"
                );
                std::thread::sleep(Duration::from_millis(1));
            }
            let error = crate::derive_admitted(
                b"public fixture",
                b"0123456789abcdef",
                Argon2idParams {
                    time: 1,
                    memory_kib: 32,
                    threads: 1,
                },
                ReadMode::Automatic,
                &admission,
            )
            .unwrap_err();
            assert_eq!(error.class(), FailureClass::ResourceBusy);
            drop(second);
            for task in tasks {
                assert_eq!(task.join().unwrap().unwrap().as_bytes().len(), 32);
            }
        });
        let state = admission.state.lock().unwrap();
        assert_eq!(
            (state.active, state.memory, state.waiters),
            (1, 128 * 1024, 0)
        );
        drop(state);
        drop(first);
    }

    #[test]
    fn explicit_legacy_reservation_excludes_automatic_real_kdf() {
        let admission = Admission::new();
        let legacy = admission.acquire(32, ReadMode::LegacyMigration).unwrap();
        std::thread::scope(|scope| {
            let task = scope.spawn(|| {
                crate::derive_admitted(
                    b"public fixture",
                    b"0123456789abcdef",
                    Argon2idParams {
                        time: 1,
                        memory_kib: 32,
                        threads: 1,
                    },
                    ReadMode::Automatic,
                    &admission,
                )
            });
            let deadline = Instant::now() + Duration::from_secs(2);
            while admission.state.lock().unwrap().waiters != 1 {
                assert!(Instant::now() < deadline);
                std::thread::sleep(Duration::from_millis(1));
            }
            assert!(!task.is_finished());
            drop(legacy);
            assert_eq!(task.join().unwrap().unwrap().as_bytes().len(), 32);
        });
    }
}
