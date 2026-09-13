//! Serialized process-local ownership for encrypted search indexes.
//!
//! The Go oracle keeps one index per canonical vault directory behind a
//! process-wide mutex.  This wrapper preserves that ownership boundary for
//! Rust callers: a load and an invalidation for the same vault cannot commit
//! out of order and resurrect an index after it was invalidated.

use std::{
    collections::{BTreeMap, VecDeque},
    path::PathBuf,
    sync::{Arc, Mutex},
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

/// Thread-safe process-local collection of per-vault search indexes.
///
/// Disk files are retained when an entry is evicted from the bounded in-memory
/// collection, but [`Self::invalidate_all`] removes both memory and persisted
/// state.  Operations on one vault are serialized without blocking unrelated
/// vaults.
pub struct SearchIndexStore {
    state: Mutex<IndexStoreState>,
}

impl Default for SearchIndexStore {
    fn default() -> Self {
        Self::new()
    }
}

impl SearchIndexStore {
    /// Creates an empty bounded index store.
    #[must_use]
    pub fn new() -> Self {
        Self {
            state: Mutex::new(IndexStoreState::default()),
        }
    }

    /// Builds and installs the index for `store` only after a successful build.
    pub fn build(&self, store: &Store, identity: &Identity) -> Result<(), StoreError> {
        let slot = self.slot(store)?;
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
        let slot = self.slot(store)?;
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
        let slot = self.slot(store)?;
        let mut current = lock_slot(&slot)?;
        current
            .as_mut()
            .ok_or_else(|| StoreError::Config("search index is not loaded".into()))?
            .search(candidates, needle)
    }

    /// Invalidates one vault's index, clearing memory and deleting its file.
    pub fn invalidate(&self, store: &Store) -> Result<(), StoreError> {
        let slot = self.slot(store)?;
        let mut current = lock_slot(&slot)?;
        if let Some(index) = current.as_mut() {
            index.invalidate()?;
        }
        *current = None;
        Ok(())
    }

    /// Invalidates every cached vault index and removes every persisted file.
    pub fn invalidate_all(&self) -> Result<(), StoreError> {
        let mut state = lock_state(&self.state)?;
        let slots: Vec<_> = state.indices.values().cloned().collect();
        let mut first_error = None;
        for slot in slots {
            let mut current = lock_slot(&slot)?;
            if let Some(Err(error)) = current.as_mut().map(SearchIndex::invalidate) {
                first_error.get_or_insert(error);
            }
            *current = None;
        }
        state.indices.clear();
        state.order.clear();
        first_error.map_or(Ok(()), Err)
    }

    fn slot(&self, store: &Store) -> Result<IndexSlot, StoreError> {
        let key = store.root().to_path_buf();
        let mut state = lock_state(&self.state)?;
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
            let Some(evicted) = state.indices.remove(&oldest) else {
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
