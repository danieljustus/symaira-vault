//! Process-wide reservations for transient vault payload reads.

use crate::StoreError;
use std::sync::{
    Condvar, Mutex, OnceLock,
    atomic::{AtomicU64, Ordering},
};
use std::time::{Duration, Instant};

const MAX_ACTIVE: usize = 4;
const MAX_PENDING: usize = 32;
const MAX_WAIT: Duration = Duration::from_secs(10);
pub(crate) const MAX_BATCH_BYTES: u64 = 256 * 1024 * 1024;
pub(crate) const MAX_PATH_BYTES: usize = 8 * 1024 * 1024;
pub(crate) const MAX_INDEX_BYTES: usize = 8 * 1024 * 1024;

#[derive(Default)]
struct State {
    active: usize,
    pending: usize,
}

#[derive(Default)]
pub(crate) struct Admission {
    state: Mutex<State>,
    changed: Condvar,
}

pub(crate) struct Lease<'a>(&'a Admission);

impl Admission {
    pub(crate) fn acquire(&self) -> Result<Lease<'_>, StoreError> {
        let mut state = self.state.lock().map_err(|_| StoreError::ResourceBusy)?;
        if state.active < MAX_ACTIVE {
            state.active += 1;
            return Ok(Lease(self));
        }
        if state.pending >= MAX_PENDING {
            return Err(StoreError::ResourceBusy);
        }
        state.pending += 1;
        let deadline = Instant::now() + MAX_WAIT;
        loop {
            let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
                state.pending -= 1;
                return Err(StoreError::ResourceBusy);
            };
            let (next, _) = self
                .changed
                .wait_timeout(state, remaining)
                .map_err(|_| StoreError::ResourceBusy)?;
            state = next;
            if Instant::now() >= deadline {
                state.pending -= 1;
                return Err(StoreError::ResourceBusy);
            }
            if state.active < MAX_ACTIVE {
                state.pending -= 1;
                state.active += 1;
                return Ok(Lease(self));
            }
        }
    }
}

impl Drop for Lease<'_> {
    fn drop(&mut self) {
        if let Ok(mut state) = self.0.state.lock() {
            state.active -= 1;
            self.0.changed.notify_all();
        }
    }
}

pub(crate) fn acquire() -> Result<Lease<'static>, StoreError> {
    static ADMISSION: OnceLock<Admission> = OnceLock::new();
    ADMISSION.get_or_init(Admission::default).acquire()
}

#[derive(Default)]
pub(crate) struct Batch {
    ciphertext: AtomicU64,
    decoded: AtomicU64,
}

impl Batch {
    fn charge(counter: &AtomicU64, bytes: usize) -> Result<(), StoreError> {
        const FAILED: u64 = u64::MAX;
        let previous = counter
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |used| {
                if used == FAILED {
                    return None;
                }
                Some(
                    used.checked_add(bytes as u64)
                        .filter(|next| *next <= MAX_BATCH_BYTES)
                        .unwrap_or(FAILED),
                )
            })
            .map_err(|_| StoreError::ResourceLimit)?;
        if previous
            .checked_add(bytes as u64)
            .is_none_or(|next| next > MAX_BATCH_BYTES)
        {
            return Err(StoreError::ResourceLimit);
        }
        Ok(())
    }

    pub(crate) fn consume(&self, bytes: usize) -> Result<(), StoreError> {
        Self::charge(&self.ciphertext, bytes)
    }

    pub(crate) fn consume_decoded(&self, bytes: usize) -> Result<(), StoreError> {
        let result = Self::charge(&self.decoded, bytes);
        if result.is_err() {
            self.fail();
        }
        result
    }

    pub(crate) fn fail(&self) {
        self.ciphertext.store(u64::MAX, Ordering::Relaxed);
        self.decoded.store(u64::MAX, Ordering::Relaxed);
    }
}

pub(crate) fn add_path_bytes(total: &mut usize, path: &str) -> Result<(), StoreError> {
    let next = total
        .checked_add(path.len())
        .ok_or(StoreError::ResourceLimit)?;
    if next > MAX_PATH_BYTES {
        return Err(StoreError::ResourceLimit);
    }
    *total = next;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounded_admission_runs_authenticated_reads_after_a_saturated_queue() {
        let admission = Admission::default();
        let identity = symvault_crypto::generate_identity();
        let ciphertext = symvault_crypto::encrypt(
            b"public-fixture",
            &[
                symvault_crypto::parse_recipient(&symvault_crypto::recipient_string(&identity))
                    .unwrap(),
            ],
        )
        .unwrap();
        std::thread::scope(|scope| {
            let mut held = (0..MAX_ACTIVE)
                .map(|_| admission.acquire().unwrap())
                .collect::<Vec<_>>();
            let readers = (0..MAX_PENDING)
                .map(|_| {
                    scope.spawn(|| {
                        let _lease = admission.acquire().unwrap();
                        assert!(admission.state.lock().unwrap().active <= MAX_ACTIVE);
                        assert_eq!(
                            symvault_crypto::decrypt_bounded(&ciphertext, &identity, 1024).unwrap(),
                            b"public-fixture"
                        );
                    })
                })
                .collect::<Vec<_>>();
            let deadline = Instant::now() + Duration::from_secs(3);
            while admission.state.lock().unwrap().pending < MAX_PENDING {
                assert!(
                    Instant::now() < deadline,
                    "readers never filled the bounded queue"
                );
                std::thread::yield_now();
            }
            assert!(matches!(admission.acquire(), Err(StoreError::ResourceBusy)));
            held.clear();
            for reader in readers {
                reader.join().unwrap();
            }
        });
        let state = admission.state.lock().unwrap();
        assert_eq!((state.active, state.pending), (0, 0));
    }
}
