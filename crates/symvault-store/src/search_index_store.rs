//! Serialized process-local ownership for encrypted search indexes.
//!
//! The Go oracle keeps one index per canonical vault directory behind a
//! process-wide mutex.  This wrapper preserves that ownership boundary for
//! Rust callers: a load and an invalidation for the same vault cannot commit
//! out of order and resurrect an index after it was invalidated.

use std::{
    collections::{BTreeMap, VecDeque},
    path::PathBuf,
    sync::{Arc, Mutex, OnceLock},
};

use symvault_crypto::Identity;

use crate::{SearchIndex, Store, StoreError};

const MAX_INDEX_STORE_SIZE: usize = 8;
type IndexSlot = Arc<Mutex<Option<SearchIndex>>>;

#[derive(Default)]
struct IndexStoreState {
    indices: BTreeMap<PathBuf, IndexSlot>,
    order: VecDeque<PathBuf>,
}

/// Thread-safe process-wide collection of per-vault search indexes.
///
/// Disk files are retained when an entry is evicted from the bounded in-memory
/// collection.  Call [`Self::invalidate`] for a specific vault to remove both
/// memory and persisted state.  The shared coordination lock is held through
/// each operation so eviction cannot race with a delayed caller.
pub struct SearchIndexStore {
    state: &'static Mutex<IndexStoreState>,
}

static PROCESS_INDEX_STATE: OnceLock<Mutex<IndexStoreState>> = OnceLock::new();

impl Default for SearchIndexStore {
    fn default() -> Self {
        Self::new()
    }
}

impl SearchIndexStore {
    /// Creates a handle to the process-wide bounded index store.
    #[must_use]
    pub fn new() -> Self {
        Self {
            state: PROCESS_INDEX_STATE.get_or_init(|| Mutex::new(IndexStoreState::default())),
        }
    }

    /// Builds and installs the index for `store` only after a successful build.
    pub fn build(&self, store: &Store, identity: &Identity) -> Result<(), StoreError> {
        let mut state = lock_state(self.state)?;
        let slot = Self::slot_locked(&mut state, store)?;
        let mut current = lock_slot(&slot)?;
        let built = SearchIndex::build(store, identity)?;
        *current = Some(built);
        Ok(())
    }

    /// Loads the persisted index for `store`, returning whether one was found.
    ///
    /// A missing or stale index clears the cached slot.  An I/O/decryption
    /// error leaves the previously cached slot untouched, matching the Go
    /// loader's fail-closed state transition.
    pub fn load(&self, store: &Store, identity: &Identity) -> Result<bool, StoreError> {
        let mut state = lock_state(self.state)?;
        let slot = Self::slot_locked(&mut state, store)?;
        let mut current = lock_slot(&slot)?;
        let loaded = SearchIndex::load(store, identity)?;
        *current = loaded;
        Ok(current.is_some())
    }

    /// Searches the currently loaded index for `needle`.
    pub fn search(
        &self,
        store: &Store,
        candidates: &[String],
        needle: &str,
    ) -> Result<std::collections::BTreeSet<String>, StoreError> {
        let mut state = lock_state(self.state)?;
        let slot = Self::slot_locked(&mut state, store)?;
        let mut current = lock_slot(&slot)?;
        current
            .as_mut()
            .ok_or_else(|| StoreError::Config("search index is not loaded".into()))?
            .search(candidates, needle)
    }

    /// Reports whether the process-wide slot for `store` currently holds an index.
    pub fn is_loaded(&self, store: &Store) -> Result<bool, StoreError> {
        let mut state = lock_state(self.state)?;
        let slot = Self::slot_locked(&mut state, store)?;
        Ok(lock_slot(&slot)?
            .as_ref()
            .is_some_and(SearchIndex::is_loaded))
    }

    /// Invalidates one vault's index, clearing memory and deleting its file.
    pub fn invalidate(&self, store: &Store) -> Result<(), StoreError> {
        let mut state = lock_state(self.state)?;
        let slot = Self::slot_locked(&mut state, store)?;
        let mut current = lock_slot(&slot)?;
        if let Some(index) = current.as_mut() {
            index.invalidate()?;
        } else {
            SearchIndex::invalidate_persisted(store)?;
        }
        *current = None;
        Ok(())
    }

    fn slot_locked(state: &mut IndexStoreState, store: &Store) -> Result<IndexSlot, StoreError> {
        let key = store.root().to_path_buf();
        if let Some(slot) = state.indices.get(&key).cloned() {
            touch(&mut state.order, &key);
            return Ok(slot);
        }
        let slot = Arc::new(Mutex::new(None));
        state.indices.insert(key.clone(), Arc::clone(&slot));
        state.order.push_back(key);
        while state.order.len() > MAX_INDEX_STORE_SIZE {
            let Some(oldest) = state.order.pop_front() else {
                break;
            };
            let Some(evicted) = state.indices.get(&oldest).cloned() else {
                continue;
            };
            let mut current = lock_slot(&evicted)?;
            if let Some(index) = current.as_mut() {
                index.clear_memory();
            }
            *current = None;
        }
        Ok(slot)
    }
}

fn touch(order: &mut VecDeque<PathBuf>, key: &PathBuf) {
    if let Some(position) = order.iter().position(|candidate| candidate == key) {
        order.remove(position);
    }
    order.push_back(key.clone());
}

fn lock_state<T>(mutex: &Mutex<T>) -> Result<std::sync::MutexGuard<'_, T>, StoreError> {
    mutex
        .lock()
        .map_err(|_| StoreError::Config("search index store lock poisoned".into()))
}

fn lock_slot(
    slot: &IndexSlot,
) -> Result<std::sync::MutexGuard<'_, Option<SearchIndex>>, StoreError> {
    slot.lock()
        .map_err(|_| StoreError::Config("search index slot lock poisoned".into()))
}
