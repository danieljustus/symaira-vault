//! In-memory approval requests for server-side callers.

use std::{
    collections::HashMap,
    sync::{Condvar, Mutex, MutexGuard},
    time::{Duration, SystemTime},
};

pub const DEFAULT_TTL: Duration = Duration::from_secs(5 * 60);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Pending,
    Approved,
    Denied,
    Expired,
}

#[derive(Debug, Clone)]
pub struct Request {
    pub agent_name: String,
    pub path: String,
    pub write: bool,
    pub reason: String,
    pub created_at: Option<SystemTime>,
    pub expires_at: Option<SystemTime>,
}

impl Request {
    pub fn new(agent_name: impl Into<String>, path: impl Into<String>, write: bool) -> Self {
        Self {
            agent_name: agent_name.into(),
            path: path.into(),
            write,
            reason: String::new(),
            created_at: None,
            expires_at: None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Entry {
    pub id: String,
    pub agent_name: String,
    pub path: String,
    pub write: bool,
    pub reason: String,
    pub created_at: SystemTime,
    pub expires_at: SystemTime,
    pub status: Status,
    pub decided_at: Option<SystemTime>,
    pub decided_by: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outcome {
    pub id: String,
    pub status: Status,
    pub decided_at: Option<SystemTime>,
    pub decided_by: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QueueError {
    NotFound,
    Closed,
    InvalidTtl,
    AlreadyDecided(Status),
    Random(String),
    Poisoned,
}

#[derive(Default)]
struct State {
    entries: HashMap<String, Entry>,
    closed: bool,
}

/// A thread-safe, process-local approval queue. Expiry is enforced by waits
/// and lazily by reads; callers may also run [`Queue::reap_expired`].
pub struct Queue {
    state: Mutex<State>,
    changed: Condvar,
    ttl: Duration,
}

impl Default for Queue {
    fn default() -> Self {
        Self::new()
    }
}

impl Queue {
    pub fn new() -> Self {
        Self::with_ttl(DEFAULT_TTL)
    }

    pub fn with_ttl(ttl: Duration) -> Self {
        Self {
            state: Mutex::new(State::default()),
            changed: Condvar::new(),
            ttl: if ttl.is_zero() { DEFAULT_TTL } else { ttl },
        }
    }

    pub fn enqueue(&self, request: Request) -> Result<String, QueueError> {
        let mut state = self.lock()?;
        if state.closed {
            return Err(QueueError::Closed);
        }
        let now = SystemTime::now();
        let ttl = request
            .expires_at
            .and_then(|expires| expires.duration_since(now).ok())
            .filter(|ttl| !ttl.is_zero())
            .unwrap_or(self.ttl);
        let id = loop {
            let mut bytes = [0; 6];
            getrandom::fill(&mut bytes).map_err(|error| QueueError::Random(error.to_string()))?;
            let id = format!(
                "apr-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
                bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]
            );
            if !state.entries.contains_key(&id) {
                break id;
            }
        };
        let expires_at = now.checked_add(ttl).ok_or(QueueError::InvalidTtl)?;
        state.entries.insert(
            id.clone(),
            Entry {
                id: id.clone(),
                agent_name: request.agent_name,
                path: request.path,
                write: request.write,
                reason: request.reason,
                created_at: request.created_at.unwrap_or(now),
                expires_at,
                status: Status::Pending,
                decided_at: None,
                decided_by: None,
            },
        );
        self.changed.notify_all();
        Ok(id)
    }

    pub fn get(&self, id: &str) -> Result<Entry, QueueError> {
        let mut state = self.lock()?;
        self.expire(&mut state);
        state.entries.get(id).cloned().ok_or(QueueError::NotFound)
    }

    /// Pending entries come first, then newest first, with ID as the tie break.
    pub fn list(&self) -> Result<Vec<Entry>, QueueError> {
        let mut state = self.lock()?;
        self.expire(&mut state);
        let mut entries: Vec<_> = state.entries.values().cloned().collect();
        entries.sort_by(|a, b| {
            (b.status == Status::Pending)
                .cmp(&(a.status == Status::Pending))
                .then_with(|| b.created_at.cmp(&a.created_at))
                .then_with(|| a.id.cmp(&b.id))
        });
        Ok(entries)
    }

    pub fn pending(&self) -> Result<Vec<Entry>, QueueError> {
        Ok(self
            .list()?
            .into_iter()
            .filter(|entry| entry.status == Status::Pending)
            .collect())
    }

    pub fn approve(&self, id: &str, decided_by: impl Into<String>) -> Result<Outcome, QueueError> {
        self.decide(id, Status::Approved, decided_by.into())
    }

    pub fn deny(&self, id: &str, decided_by: impl Into<String>) -> Result<Outcome, QueueError> {
        self.decide(id, Status::Denied, decided_by.into())
    }

    fn decide(&self, id: &str, status: Status, decided_by: String) -> Result<Outcome, QueueError> {
        let mut state = self.lock()?;
        self.expire(&mut state);
        let entry = state.entries.get_mut(id).ok_or(QueueError::NotFound)?;
        if entry.status != Status::Pending {
            return Err(QueueError::AlreadyDecided(entry.status));
        }
        let now = SystemTime::now();
        entry.status = status;
        entry.decided_at = Some(now);
        entry.decided_by = Some(decided_by.clone());
        let outcome = outcome(entry);
        self.changed.notify_all();
        Ok(outcome)
    }

    /// Waits until a request is decided, expired, or the queue is closed.
    pub fn wait(&self, id: &str) -> Result<Outcome, QueueError> {
        let mut state = self.lock()?;
        loop {
            if state.closed {
                return Err(QueueError::Closed);
            }
            expire_pending(&mut state, SystemTime::now());
            let entry = state.entries.get(id).ok_or(QueueError::NotFound)?;
            if entry.status != Status::Pending {
                return Ok(outcome(entry));
            }
            let timeout = entry
                .expires_at
                .duration_since(SystemTime::now())
                .unwrap_or_default();
            let (next, _) = self
                .changed
                .wait_timeout(state, timeout)
                .map_err(|_| QueueError::Poisoned)?;
            state = next;
        }
    }

    pub fn reap_expired(&self) -> Result<usize, QueueError> {
        let mut state = self.lock()?;
        Ok(self.expire(&mut state))
    }

    pub fn close(&self) -> Result<(), QueueError> {
        let mut state = self.lock()?;
        if !state.closed {
            state.closed = true;
            for entry in state.entries.values_mut() {
                if entry.status == Status::Pending {
                    entry.status = Status::Expired;
                    entry.decided_at = Some(SystemTime::now());
                }
            }
            self.changed.notify_all();
        }
        Ok(())
    }

    fn lock(&self) -> Result<MutexGuard<'_, State>, QueueError> {
        self.state.lock().map_err(|_| QueueError::Poisoned)
    }

    fn expire(&self, state: &mut State) -> usize {
        let expired = expire_pending(state, SystemTime::now());
        if expired > 0 {
            self.changed.notify_all();
        }
        expired
    }
}

fn expire_pending(state: &mut State, now: SystemTime) -> usize {
    let mut expired = 0;
    for entry in state.entries.values_mut() {
        if entry.status == Status::Pending && now >= entry.expires_at {
            entry.status = Status::Expired;
            entry.decided_at = Some(entry.expires_at);
            expired += 1;
        }
    }
    expired
}

fn outcome(entry: &Entry) -> Outcome {
    Outcome {
        id: entry.id.clone(),
        status: entry.status,
        decided_at: entry.decided_at,
        decided_by: entry.decided_by.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{sync::mpsc, thread};

    #[test]
    fn enqueue_list_get_and_decide_once() {
        let queue = Queue::new();
        let id = queue
            .enqueue(Request::new("agent", "vault/key", true))
            .unwrap();
        let pending = queue.pending().unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].id, id);
        assert_eq!(queue.get(&id).unwrap().status, Status::Pending);
        assert_eq!(
            queue.approve(&id, "device").unwrap().status,
            Status::Approved
        );
        assert_eq!(
            queue.deny(&id, "other"),
            Err(QueueError::AlreadyDecided(Status::Approved))
        );
        let pending_id = queue
            .enqueue(Request::new("agent", "vault/pending", false))
            .unwrap();
        let listed = queue.list().unwrap();
        assert_eq!(listed[0].id, pending_id);
        assert_eq!(listed[1].id, id);
        let denied = queue
            .enqueue(Request::new("agent", "vault/other", false))
            .unwrap();
        assert_eq!(
            queue.deny(&denied, "device").unwrap().status,
            Status::Denied
        );
    }

    #[test]
    fn wait_wakes_on_decision() {
        let queue = std::sync::Arc::new(Queue::with_ttl(Duration::from_secs(10)));
        let (tx, rx) = mpsc::channel();
        let id = queue
            .enqueue(Request::new("agent", "vault/key", false))
            .unwrap();
        let waiter = queue.clone();
        let waiter_id = id.clone();
        thread::spawn(move || tx.send(waiter.wait(&waiter_id)).unwrap());
        thread::sleep(Duration::from_millis(5));
        assert_eq!(
            queue.approve(&id, "device").unwrap().status,
            Status::Approved
        );
        assert_eq!(
            rx.recv_timeout(Duration::from_secs(5))
                .unwrap()
                .unwrap()
                .status,
            Status::Approved
        );
    }

    #[test]
    fn wait_self_enforces_expiry() {
        let queue = std::sync::Arc::new(Queue::with_ttl(Duration::from_millis(40)));
        let id = queue
            .enqueue(Request::new("agent", "vault/key", false))
            .unwrap();
        let waiter = queue.clone();
        let waiter_id = id.clone();
        let done = thread::spawn(move || waiter.wait(&waiter_id));
        thread::sleep(Duration::from_millis(5));
        assert_eq!(done.join().unwrap().unwrap().status, Status::Expired);
        assert_eq!(queue.get(&id).unwrap().status, Status::Expired);
    }

    #[test]
    fn close_expires_requests_and_wakes_waiters() {
        let queue = std::sync::Arc::new(Queue::new());
        let id = queue
            .enqueue(Request::new("agent", "vault/key", false))
            .unwrap();
        let waiter = queue.clone();
        let waiter_id = id.clone();
        let done = thread::spawn(move || waiter.wait(&waiter_id));
        thread::sleep(Duration::from_millis(5));
        queue.close().unwrap();
        assert_eq!(done.join().unwrap(), Err(QueueError::Closed));
        assert_eq!(queue.get(&id).unwrap().status, Status::Expired);
        assert_eq!(
            queue.enqueue(Request::new("other", "vault/key", false)),
            Err(QueueError::Closed)
        );
    }
}
