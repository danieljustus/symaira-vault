//! Per-client request limiter for the MCP HTTP transport.
//!
//! Port of Go's `auth.RateLimiter` / `auth.RateLimiterMiddleware` /
//! `auth.clientIP` / `mcp.IsTrustedProxy` (`internal/mcp/auth/auth.go`,
//! `internal/mcp/util.go`). Semantics recorded from the production code in
//! `testdata/port/mcp/http-ratelimit.json`:
//!
//! * a **fixed window** per client key: the first request opens a window of
//!   `window`; up to `limit` requests are served inside it, further ones are
//!   refused until the window has *strictly* elapsed; a refused request is not
//!   counted and does not extend the window;
//! * the key is the socket peer host, or, when the peer is a trusted proxy, the
//!   first `X-Forwarded-For` element (trimmed, not validated as an IP) else
//!   `X-Real-IP`;
//! * at most [`MAX_RATE_LIMITER_ENTRIES`] keys are tracked: at the cap expired
//!   keys are dropped first, then the key whose window ends first.
//!
//! Go sweeps expired keys from a ticker goroutine every five minutes; this
//! port sweeps lazily on the first request after that interval, which is
//! observably the same (an expired key is indistinguishable from an absent one)
//! and needs no thread to stop.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

/// Cap on tracked keys (Go `MaxRateLimiterEntries`).
pub const MAX_RATE_LIMITER_ENTRIES: usize = 10_000;
/// Interval of the expired-key sweep (Go `defaultCleanupInterval`).
pub const CLEANUP_INTERVAL: Duration = Duration::from_secs(5 * 60);
/// Window of the served limiter (Go `time.Minute` in `setupRateLimiter`).
pub const WINDOW: Duration = Duration::from_secs(60);
/// Limit used when `mcp.rate_limit` is negative or no `mcp` section exists.
pub const DEFAULT_LIMIT: i64 = 60;

/// Response body of a refused request (Go `http.Error(w, "too many requests", 429)`).
pub const REFUSED_BODY: &str = "too many requests\n";

#[derive(Clone, Debug, PartialEq, Eq)]
enum TrustedProxy {
    Addr(IpAddr),
    Prefix(IpAddr, u8),
}

struct Entry {
    reset_at: Instant,
    count: u64,
}

struct State {
    attempts: HashMap<String, Entry>,
    next_cleanup: Instant,
    eviction_count: u64,
    cleanup_count: u64,
}

/// The limiter. Shared between connections behind an `Arc`.
pub struct RateLimiter {
    state: Mutex<State>,
    limit: u64,
    window: Duration,
    max_entries: usize,
    trusted: Vec<TrustedProxy>,
}

impl RateLimiter {
    /// Resolves Go's `setupRateLimiter`: `configured < 0` selects the default
    /// of 60, `0` disables the limiter (`None`), anything else is the limit.
    #[must_use]
    pub fn from_config(configured: i64, trusted_proxy_ips: &[String]) -> Option<Self> {
        let limit = if configured < 0 {
            DEFAULT_LIMIT
        } else {
            configured
        };
        if limit == 0 {
            return None;
        }
        Some(Self::new(limit.unsigned_abs(), WINDOW, trusted_proxy_ips))
    }

    #[must_use]
    pub fn new(limit: u64, window: Duration, trusted_proxy_ips: &[String]) -> Self {
        Self::new_at(limit, window, trusted_proxy_ips, Instant::now())
    }

    /// Like [`Self::new`] with an explicit clock origin (the cleanup deadline
    /// is measured from it).
    #[must_use]
    pub fn new_at(
        limit: u64,
        window: Duration,
        trusted_proxy_ips: &[String],
        origin: Instant,
    ) -> Self {
        Self {
            state: Mutex::new(State {
                attempts: HashMap::new(),
                next_cleanup: origin.checked_add(CLEANUP_INTERVAL).unwrap_or(origin),
                eviction_count: 0,
                cleanup_count: 0,
            }),
            limit,
            window,
            max_entries: MAX_RATE_LIMITER_ENTRIES,
            trusted: trusted_proxy_ips
                .iter()
                .filter_map(|entry| parse_trusted(entry))
                .collect(),
        }
    }

    /// Lowers the key cap (Go `SetMaxEntriesForTests`).
    #[must_use]
    pub fn with_max_entries(mut self, max_entries: usize) -> Self {
        self.max_entries = max_entries;
        self
    }

    /// Reports whether a request of `key` is served now.
    pub fn allow(&self, key: &str) -> bool {
        self.allow_at(key, Instant::now())
    }

    /// Like [`Self::allow`] with an injected clock.
    pub fn allow_at(&self, key: &str, now: Instant) -> bool {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        if now >= state.next_cleanup {
            let before = state.attempts.len();
            state.attempts.retain(|_, entry| now <= entry.reset_at);
            state.cleanup_count += (before - state.attempts.len()) as u64;
            state.next_cleanup = now.checked_add(CLEANUP_INTERVAL).unwrap_or(now);
        }
        if let Some(entry) = state.attempts.get_mut(key)
            && now <= entry.reset_at
        {
            if entry.count >= self.limit {
                return false;
            }
            entry.count += 1;
            return true;
        }
        if self.max_entries > 0 && state.attempts.len() >= self.max_entries {
            self.evict_oldest(&mut state, now);
        }
        state.attempts.insert(
            key.to_owned(),
            Entry {
                reset_at: now.checked_add(self.window).unwrap_or(now),
                count: 1,
            },
        );
        true
    }

    /// Drops expired keys first; if still at the cap, the key whose window
    /// ends first (Go `evictOldestLocked`).
    fn evict_oldest(&self, state: &mut State, now: Instant) {
        let expired: Vec<String> = state
            .attempts
            .iter()
            .filter(|(_, entry)| now > entry.reset_at)
            .map(|(key, _)| key.clone())
            .collect();
        for key in expired {
            state.attempts.remove(&key);
            state.eviction_count += 1;
            if state.attempts.len() < self.max_entries {
                return;
            }
        }
        if state.attempts.len() < self.max_entries {
            return;
        }
        let oldest = state
            .attempts
            .iter()
            .min_by_key(|(_, entry)| entry.reset_at)
            .map(|(key, _)| key.clone());
        if let Some(key) = oldest {
            state.attempts.remove(&key);
            state.eviction_count += 1;
        }
    }

    /// Keys dropped to honour the cap (Go `EvictionCount`).
    #[must_use]
    pub fn eviction_count(&self) -> u64 {
        self.state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .eviction_count
    }

    /// Keys removed by the periodic sweep (Go `CleanupCount`).
    #[must_use]
    pub fn cleanup_count(&self) -> u64 {
        self.state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .cleanup_count
    }

    /// Number of tracked keys.
    #[must_use]
    pub fn len(&self) -> usize {
        self.state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .attempts
            .len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Go's `clientIP(r, trustedProxies)` over the textual `RemoteAddr` and the
    /// first values of `X-Forwarded-For` / `X-Real-IP` (empty = absent).
    #[must_use]
    pub fn client_key(&self, remote_addr: &str, forwarded_for: &str, real_ip: &str) -> String {
        if self.is_trusted_proxy(remote_addr) {
            if !forwarded_for.is_empty() {
                let first = forwarded_for.split(',').next().unwrap_or_default();
                return first.trim().to_owned();
            }
            if !real_ip.is_empty() {
                return real_ip.to_owned();
            }
        }
        if !remote_addr.is_empty() {
            return match split_host_port(remote_addr) {
                Some(host) if !host.is_empty() => host.to_owned(),
                _ => remote_addr.to_owned(),
            };
        }
        "unknown".to_owned()
    }

    /// Go's `mcp.IsTrustedProxy`.
    fn is_trusted_proxy(&self, remote_addr: &str) -> bool {
        if self.trusted.is_empty() {
            return false;
        }
        let host = split_host_port(remote_addr).unwrap_or(remote_addr);
        if host.is_empty() {
            return false;
        }
        let Ok(addr) = host.parse::<IpAddr>() else {
            return false;
        };
        self.trusted.iter().any(|entry| match entry {
            TrustedProxy::Addr(trusted) => *trusted == addr,
            TrustedProxy::Prefix(network, bits) => prefix_contains(*network, *bits, addr),
        })
    }
}

/// The textual form Go's `net.TCPAddr.String()` yields (`RemoteAddr`): an
/// IPv4-mapped IPv6 peer prints as IPv4.
#[must_use]
pub fn remote_addr_string(peer: SocketAddr) -> String {
    match peer {
        SocketAddr::V6(v6) => match v6.ip().to_ipv4_mapped() {
            Some(v4) => SocketAddr::new(IpAddr::V4(v4), v6.port()).to_string(),
            None => peer.to_string(),
        },
        SocketAddr::V4(_) => peer.to_string(),
    }
}

/// Go's `net.SplitHostPort`, returning the host only (`None` = error).
fn split_host_port(hostport: &str) -> Option<&str> {
    let i = hostport.rfind(':')?;
    let (host, start, port_from) = if hostport.starts_with('[') {
        let end = hostport.find(']')?;
        if end + 1 == hostport.len() {
            return None;
        }
        if end + 1 != i {
            return None;
        }
        (&hostport[1..end], 1, end + 1)
    } else {
        let host = &hostport[..i];
        if host.contains(':') {
            return None;
        }
        (host, 0, i)
    };
    if hostport[start..].contains('[') || hostport[port_from..].contains(']') {
        return None;
    }
    Some(host)
}

/// A `mcp.trusted_proxy_ips` entry: a bare address, or CIDR when it holds a
/// `/`. Anything `netip` would reject is ignored, as in Go.
fn parse_trusted(entry: &str) -> Option<TrustedProxy> {
    if entry.contains('/') {
        let slash = entry.rfind('/')?;
        let (address, bits_text) = (&entry[..slash], &entry[slash + 1..]);
        if address.contains('%') {
            return None;
        }
        let address: IpAddr = address.parse().ok()?;
        let first = bits_text.bytes().next()?;
        if bits_text.len() > 1 && !(b'1'..=b'9').contains(&first) {
            return None;
        }
        if !bits_text.bytes().all(|byte| byte.is_ascii_digit()) {
            return None;
        }
        let bits: u8 = bits_text.parse().ok()?;
        let width = if address.is_ipv4() { 32 } else { 128 };
        if bits > width {
            return None;
        }
        Some(TrustedProxy::Prefix(address, bits))
    } else {
        entry.parse().ok().map(TrustedProxy::Addr)
    }
}

fn prefix_contains(network: IpAddr, bits: u8, addr: IpAddr) -> bool {
    match (network, addr) {
        (IpAddr::V4(network), IpAddr::V4(addr)) => {
            let mask = u32::MAX.checked_shl(32 - u32::from(bits)).unwrap_or(0);
            u32::from(network) & mask == u32::from(addr) & mask
        }
        (IpAddr::V6(network), IpAddr::V6(addr)) => {
            let mask = u128::MAX.checked_shl(128 - u32::from(bits)).unwrap_or(0);
            u128::from(network) & mask == u128::from(addr) & mask
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(base: Instant, millis: u64) -> Instant {
        base + Duration::from_millis(millis)
    }

    #[test]
    fn fixed_window_counts_inclusive_and_does_not_extend_on_refusal() {
        let base = Instant::now();
        let limiter = RateLimiter::new_at(2, Duration::from_millis(500), &[], base);
        assert!(limiter.allow_at("a", at(base, 0)));
        assert!(limiter.allow_at("a", at(base, 100)));
        assert!(!limiter.allow_at("a", at(base, 200)));
        // Refusals neither count nor push the window out.
        assert!(!limiter.allow_at("a", at(base, 499)));
        // Exactly at the reset instant the window still holds (`After`).
        assert!(!limiter.allow_at("a", at(base, 500)));
        assert!(limiter.allow_at("a", at(base, 501)));
        assert!(limiter.allow_at("a", at(base, 502)));
        assert!(!limiter.allow_at("a", at(base, 503)));
    }

    #[test]
    fn keys_are_independent() {
        let base = Instant::now();
        let limiter = RateLimiter::new_at(1, Duration::from_secs(60), &[], base);
        assert!(limiter.allow_at("a", base));
        assert!(limiter.allow_at("b", base));
        assert!(!limiter.allow_at("a", base));
    }

    #[test]
    fn cap_evicts_expired_then_oldest_window() {
        let base = Instant::now();
        let limiter =
            RateLimiter::new_at(1, Duration::from_secs(60), &[], base).with_max_entries(3);
        for (index, key) in ["a", "b", "c"].iter().enumerate() {
            assert!(limiter.allow_at(key, at(base, index as u64 * 3)));
        }
        assert!(limiter.allow_at("d", at(base, 9)));
        assert_eq!(limiter.eviction_count(), 1);
        assert_eq!(limiter.len(), 3);
        assert!(limiter.allow_at("a", at(base, 12)), "a was the oldest");
        assert!(!limiter.allow_at("c", at(base, 15)));
        assert!(!limiter.allow_at("d", at(base, 15)));
        assert!(limiter.allow_at("b", at(base, 15)), "b evicted by a");
        assert_eq!(limiter.len(), 3);

        let limiter =
            RateLimiter::new_at(1, Duration::from_millis(150), &[], base).with_max_entries(3);
        for key in ["a", "b", "c"] {
            assert!(limiter.allow_at(key, base));
        }
        assert!(limiter.allow_at("d", at(base, 350)));
        assert!(!limiter.allow_at("d", at(base, 351)));
        assert_eq!(limiter.eviction_count(), 1);
        assert_eq!(limiter.len(), 3);
    }

    #[test]
    fn memory_stays_bounded_under_many_distinct_keys() {
        let base = Instant::now();
        let limiter =
            RateLimiter::new_at(1, Duration::from_secs(60), &[], base).with_max_entries(64);
        for index in 0..10_000_u64 {
            assert!(limiter.allow_at(&format!("10.0.{}.{}", index / 256, index % 256), base));
            assert!(limiter.len() <= 64);
        }
        assert_eq!(limiter.eviction_count(), 10_000 - 64);
    }

    #[test]
    fn lazy_sweep_removes_expired_keys_after_the_cleanup_interval() {
        let base = Instant::now();
        let limiter = RateLimiter::new_at(1, Duration::from_secs(60), &[], base);
        for index in 0..100 {
            assert!(limiter.allow_at(&format!("k{index}"), base));
        }
        assert_eq!(limiter.len(), 100);
        // Still before the interval: expired but retained (Go's ticker has not fired).
        assert!(limiter.allow_at("late", at(base, 120_000)));
        assert_eq!(limiter.len(), 101);
        assert_eq!(limiter.cleanup_count(), 0);
        // First request after five minutes sweeps everything that expired.
        assert!(limiter.allow_at("later", base + CLEANUP_INTERVAL + Duration::from_secs(1)));
        assert_eq!(limiter.cleanup_count(), 101);
        assert_eq!(limiter.len(), 1);
    }

    #[test]
    fn config_resolution_matches_setup_rate_limiter() {
        assert!(RateLimiter::from_config(0, &[]).is_none());
        for configured in [-1, -5, i64::MIN, 60] {
            let limiter = RateLimiter::from_config(configured, &[]).expect("enabled");
            let base = Instant::now();
            for _ in 0..60 {
                assert!(limiter.allow_at("a", base));
            }
            assert!(!limiter.allow_at("a", base), "limit for {configured}");
        }
        let limiter = RateLimiter::from_config(1, &[]).expect("enabled");
        assert!(limiter.allow("a"));
        assert!(!limiter.allow("a"));
        assert!(RateLimiter::from_config(i64::MAX, &[]).is_some());
    }

    #[test]
    fn split_host_port_follows_go() {
        for (input, expected) in [
            ("192.0.2.1:80", Some("192.0.2.1")),
            ("[2001:db8::1]:80", Some("2001:db8::1")),
            ("192.0.2.1", None),
            ("2001:db8::1", None),
            ("[2001:db8::1]", None),
            ("[2001:db8::1]x:80", None),
            ("a:b:80", None),
            (":80", Some("")),
            ("[::1]:", Some("::1")),
            ("a[b:80", None),
        ] {
            assert_eq!(split_host_port(input), expected, "{input}");
        }
    }

    #[test]
    fn trusted_entries_follow_netip() {
        for valid in [
            "10.0.0.1",
            "10.0.0.0/8",
            "10.0.0.5/24",
            "::1",
            "2001:db8::/32",
            "0.0.0.0/0",
            "10.0.0.0/0",
        ] {
            assert!(parse_trusted(valid).is_some(), "{valid}");
        }
        for invalid in [
            "",
            "bogus",
            "10.0.0.0/33",
            "10.0.0.0/08",
            "10.0.0.0/+8",
            "10.0.0.0/-1",
            "10.0.0.0/",
            "10.0.0.0/8/8",
            "010.0.0.1",
            "10.0.0.256",
            "fe80::1%eth0/64",
            "2001:db8::/129",
            "/8",
        ] {
            assert!(parse_trusted(invalid).is_none(), "{invalid}");
        }
        let limiter = RateLimiter::new(
            1,
            WINDOW,
            &["10.0.0.0/8".to_owned(), "2001:db8::/32".to_owned()],
        );
        assert!(limiter.is_trusted_proxy("10.255.0.1:1"));
        assert!(limiter.is_trusted_proxy("10.255.0.1"));
        assert!(!limiter.is_trusted_proxy("11.0.0.1:1"));
        assert!(limiter.is_trusted_proxy("[2001:db8:1::1]:1"));
        assert!(!limiter.is_trusted_proxy("[2001:db9::1]:1"));
        assert!(!limiter.is_trusted_proxy(""));
        assert!(!limiter.is_trusted_proxy("not-an-ip:1"));
    }

    #[test]
    fn mapped_ipv4_peer_prints_as_ipv4() {
        let peer: SocketAddr = "[::ffff:192.0.2.1]:8080".parse().expect("socket address");
        assert_eq!(remote_addr_string(peer), "192.0.2.1:8080");
        let peer: SocketAddr = "[2001:db8::1]:8080".parse().expect("socket address");
        assert_eq!(remote_addr_string(peer), "[2001:db8::1]:8080");
    }

    #[test]
    fn client_key_without_remote_is_unknown() {
        let limiter = RateLimiter::new(1, WINDOW, &[]);
        assert_eq!(limiter.client_key("", "1.1.1.1", ""), "unknown");
    }
}
