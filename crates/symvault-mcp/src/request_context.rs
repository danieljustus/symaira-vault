//! Application-owned cancellation and an absolute per-call deadline.

use std::{
    future::Future,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

#[derive(Clone, Default)]
pub struct RequestContext {
    cancelled: Arc<AtomicBool>,
    deadline: Option<Instant>,
}

impl RequestContext {
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
    }

    pub fn with_timeout(&self, timeout: Duration) -> Self {
        let deadline = Instant::now().checked_add(timeout);
        Self {
            cancelled: Arc::clone(&self.cancelled),
            deadline: match (self.deadline, deadline) {
                (Some(a), Some(b)) => Some(a.min(b)),
                (a, b) => a.or(b),
            },
        }
    }

    pub fn check(&self) -> Result<(), String> {
        if self.cancelled.load(Ordering::Acquire) {
            Err("upstream request cancelled".into())
        } else if self
            .deadline
            .is_some_and(|deadline| Instant::now() >= deadline)
        {
            Err("upstream request timed out".into())
        } else {
            Ok(())
        }
    }

    /// Go's `ctx.Err()` text once the context is done, for handlers that
    /// wrap the context error itself (`requireApproval`).
    pub fn go_err(&self) -> Option<&'static str> {
        if self.cancelled.load(Ordering::Acquire) {
            Some("context canceled")
        } else if self
            .deadline
            .is_some_and(|deadline| Instant::now() >= deadline)
        {
            Some("context deadline exceeded")
        } else {
            None
        }
    }

    pub(crate) async fn wait<T>(
        &self,
        future: impl Future<Output = Result<T, String>>,
    ) -> Result<T, String> {
        let mut future = std::pin::pin!(future);
        loop {
            self.check()?;
            match tokio::time::timeout(Duration::from_millis(10), &mut future).await {
                Ok(result) => {
                    self.check()?;
                    return result;
                }
                Err(_) => continue,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn go_err_matches_go_context_errors() {
        let context = RequestContext::default();
        assert_eq!(context.go_err(), None);
        assert_eq!(
            context.with_timeout(Duration::ZERO).go_err(),
            Some("context deadline exceeded")
        );
        context.cancel();
        assert_eq!(context.go_err(), Some("context canceled"));
    }
}
