//! Rate limits on the endpoints that take a credential or mint an account.
//!
//! argon2's cost is a brake on password guessing, not a wall, and nothing
//! else stood between an anonymous caller and unlimited attempts: at the
//! login form, at the registration form and the accounts API — each of which
//! provisions a pod, keypairs and an identity — and at the password-change
//! form from inside a hijacked session. One token bucket per `(gate, key)`,
//! in memory: a single-host, single-image server (D1) has no second node to
//! share counters with, and a restart forgetting the counters is a cost the
//! attacker pays too.
//!
//! The key is the caller's address as the proxy in front of the deployment
//! reports it — the rightmost `X-Forwarded-For` entry, which is the one that
//! proxy appended; everything left of it is whatever the client chose to
//! send — or the peer address when there is no proxy. Login is additionally
//! keyed by username, so that rotating addresses buys nothing against one
//! account, and password change by member, so that the thief's address is
//! irrelevant.

use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

/// What is being gated. Each has a burst — how many attempts a fresh key may
/// make at once — and how long one attempt takes to come back.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Gate {
    /// `POST /login`, keyed by address and, separately, by username.
    Login,
    /// `POST /register` and `POST /api/accounts`, keyed by address.
    Signup,
    /// `POST /account/security`, keyed by member.
    PasswordChange,
}

impl Gate {
    pub fn burst(self) -> u32 {
        match self {
            Gate::Login => 10,
            Gate::Signup => 5,
            Gate::PasswordChange => 5,
        }
    }

    pub fn refill_every(self) -> Duration {
        match self {
            Gate::Login => Duration::from_secs(30),
            Gate::Signup => Duration::from_secs(10 * 60),
            Gate::PasswordChange => Duration::from_secs(60),
        }
    }
}

/// A token bucket: `tokens` as of `at`, refilled lazily on the next look.
struct Bucket {
    tokens: f64,
    at: Instant,
}

/// Every bucket the instance is keeping. Prunes itself: once the map is
/// large, every bucket that has refilled to full is dropped on the next
/// check, which is what a fresh key would start from anyway.
pub struct Limiter {
    buckets: Mutex<HashMap<(Gate, String), Bucket>>,
}

/// Above this many live buckets, a check first drops the ones that are full.
const PRUNE_ABOVE: usize = 10_000;

impl Default for Limiter {
    fn default() -> Self {
        Self::new()
    }
}

impl Limiter {
    pub fn new() -> Self {
        Limiter {
            buckets: Mutex::new(HashMap::new()),
        }
    }

    /// Spend one attempt for `key` at `gate`. `Err` carries how long until
    /// the next attempt would be allowed.
    pub fn check(&self, gate: Gate, key: &str) -> Result<(), Duration> {
        self.check_at(gate, key, Instant::now())
    }

    pub fn check_at(&self, gate: Gate, key: &str, now: Instant) -> Result<(), Duration> {
        let burst = f64::from(gate.burst());
        let refill = gate.refill_every().as_secs_f64();
        let mut buckets = self.buckets.lock().unwrap_or_else(PoisonError::into_inner);

        if buckets.len() > PRUNE_ABOVE {
            buckets.retain(|(g, _), b| {
                let elapsed = now.saturating_duration_since(b.at).as_secs_f64();
                b.tokens + elapsed / g.refill_every().as_secs_f64() < f64::from(g.burst())
            });
        }

        let bucket = buckets.entry((gate, key.to_string())).or_insert(Bucket {
            tokens: burst,
            at: now,
        });
        let elapsed = now.saturating_duration_since(bucket.at).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed / refill).min(burst);
        bucket.at = now;

        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            Ok(())
        } else {
            let wait = (1.0 - bucket.tokens) * refill;
            Err(Duration::from_secs_f64(wait))
        }
    }
}

/// The caller's address for keying: the rightmost `X-Forwarded-For` entry
/// when there is one, else the peer, else a shared key for a deployment
/// that has neither — which limits everyone together rather than nobody.
pub fn client_key(headers: &HeaderMap, peer: Option<SocketAddr>) -> String {
    headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.rsplit(',').next())
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(str::to_string)
        .or_else(|| peer.map(|p| p.ip().to_string()))
        .unwrap_or_else(|| "unknown".to_string())
}

/// The caller's address, resolved once per request by the `client_address`
/// middleware and read by the handlers that gate on it.
#[derive(Debug, Clone)]
pub struct ClientKey(pub String);

/// 429 with `Retry-After` in whole seconds, rounded up so the number named
/// is never shorter than the wait.
pub fn too_many(wait: Duration) -> Response {
    let seconds = wait.as_secs_f64().ceil().max(1.0) as u64;
    (
        StatusCode::TOO_MANY_REQUESTS,
        [(header::RETRY_AFTER, seconds.to_string())],
        format!("Too many attempts. Try again in {seconds} seconds."),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderMap;
    use std::time::{Duration, Instant};

    #[test]
    fn a_gate_allows_its_burst_and_then_refuses() {
        let limiter = Limiter::new();
        let now = Instant::now();
        for i in 0..Gate::Login.burst() {
            assert!(
                limiter.check_at(Gate::Login, "203.0.113.7", now).is_ok(),
                "attempt {i} is within the burst"
            );
        }
        let refused = limiter.check_at(Gate::Login, "203.0.113.7", now);
        assert!(refused.is_err(), "the burst is spent");
    }

    #[test]
    fn a_refused_key_says_how_long_to_wait_and_is_let_back_in_after_it() {
        let limiter = Limiter::new();
        let now = Instant::now();
        for _ in 0..Gate::Login.burst() {
            limiter.check_at(Gate::Login, "k", now).unwrap();
        }
        let wait = limiter.check_at(Gate::Login, "k", now).unwrap_err();
        assert!(wait > Duration::ZERO && wait <= Gate::Login.refill_every());
        assert!(limiter.check_at(Gate::Login, "k", now + wait).is_ok());
    }

    #[test]
    fn keys_and_gates_do_not_share_a_bucket() {
        let limiter = Limiter::new();
        let now = Instant::now();
        for _ in 0..Gate::Login.burst() {
            limiter.check_at(Gate::Login, "a", now).unwrap();
        }
        assert!(limiter.check_at(Gate::Login, "a", now).is_err());
        assert!(
            limiter.check_at(Gate::Login, "b", now).is_ok(),
            "another key"
        );
        assert!(
            limiter.check_at(Gate::Signup, "a", now).is_ok(),
            "another gate"
        );
    }

    #[test]
    fn the_client_key_is_the_nearest_proxys_word_or_the_peer() {
        let mut headers = HeaderMap::new();
        let peer: std::net::SocketAddr = "198.51.100.9:4242".parse().unwrap();
        assert_eq!(client_key(&headers, Some(peer)), "198.51.100.9");
        assert_eq!(client_key(&headers, None), "unknown");

        // The rightmost entry is the one the proxy in front of us appended;
        // everything left of it is whatever the client chose to send.
        headers.insert("x-forwarded-for", "1.2.3.4, 203.0.113.7 ".parse().unwrap());
        assert_eq!(client_key(&headers, Some(peer)), "203.0.113.7");
    }
}
