// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2026 The `OpenHTTPA` Foundation (AIQL.org)

//! Per-IP sliding-window rate limiting middleware.
//!
//! [`RateLimitLayer`] wraps any Axum-compatible Tower service and rejects
//! requests from an IP address that exceeds a configurable threshold within a
//! rolling time window.
//!
//! ## Algorithm
//!
//! A **sliding window** counter is maintained per remote IP address.  Every
//! accepted request appends its timestamp.  On each new request the list is
//! pruned to keep only entries within the last `window` duration.  If the
//! remaining count equals or exceeds `max_requests` the request is rejected
//! with `429 Too Many Requests`.
//!
//! The pruning operation is O(k) where k is the number of entries in the
//! window, typically small.  Under high load a [`DashMap`] shard ensures only
//! per-shard contention, not a global lock.
//!
//! ## Usage
//!
//! ```rust,no_run
//! use std::time::Duration;
//! use openhttpa_server::rate_limit::RateLimitLayer;
//!
//! let layer = RateLimitLayer::new(100, Duration::from_secs(60));
//! ```
//!
//! Wire it onto an Axum router using `.layer(...)` after the
//! `axum::middleware::from_extractor::<ConnectInfo<_>>()` layer (so that the
//! remote address is available).

use std::{
    net::{IpAddr, Ipv6Addr, SocketAddr},
    sync::Arc,
    task::{Context, Poll},
    time::{Duration, Instant},
};

use axum::{body::Body, extract::ConnectInfo};
use dashmap::DashMap;
use http::{Request, Response, StatusCode};
use tower::{Layer, Service};

// ─── State ───────────────────────────────────────────────────────────────────

/// Shared rate-limiting state held by all clones of [`RateLimitService`].
#[derive(Debug)]
struct RateLimitState {
    /// Per-IP list of request timestamps within the current window.
    clients: Arc<DashMap<IpAddr, Vec<Instant>>>,
    /// Maximum number of requests allowed per `window`.
    max_requests: usize,
    /// The duration of the rolling window.
    window: Duration,
}

impl RateLimitState {
    fn new(max_requests: usize, window: Duration) -> Arc<Self> {
        let state = Arc::new(Self {
            clients: Arc::new(DashMap::new()),
            max_requests,
            window,
        });

        // Start background cleanup task to prevent memory leaks from unique IPs.
        state.start_cleanup_task();
        state
    }

    /// Spawns a background task that periodically prunes inactive IP entries.
    fn start_cleanup_task(&self) {
        if tokio::runtime::Handle::try_current().is_err() {
            return;
        }
        let clients = Arc::clone(&self.clients);
        let window = self.window;
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(window.max(Duration::from_secs(60)));
            loop {
                ticker.tick().await;
                let now = Instant::now();
                let cutoff = now.checked_sub(window).unwrap_or(now);

                // Prune empty or expired entries.
                clients.retain(|_ip, entry| {
                    // Keep entry if it has any non-expired timestamps.
                    entry.retain(|&ts| ts >= cutoff);
                    !entry.is_empty()
                });
            }
        });
    }

    /// Returns `true` if the request from `ip` should be allowed through.
    ///
    /// Side effect: prunes expired timestamps and appends the current
    /// timestamp when the request is accepted.
    fn check_and_record(&self, ip: IpAddr) -> bool {
        // RATE-IPv6-01: Normalise IPv6 addresses to their /64 prefix.
        // A single /64 allocation (standard ISP assignment) gives an attacker
        // 2⁶⁴ unique /128 source addresses, trivially exhausting per-/128
        // rate-limit windows.  Collapsing to /64 ensures the window is shared
        // across all addresses in the same allocation.
        let ip = normalize_ip(ip);
        let now = Instant::now();
        let cutoff = now.checked_sub(self.window).unwrap_or(now);

        let mut entry = self.clients.entry(ip).or_default();
        // Remove timestamps outside the rolling window.
        entry.retain(|&ts| ts >= cutoff);

        if entry.len() >= self.max_requests {
            // Rate limit exceeded — do NOT record; caller will reject.
            return false;
        }
        entry.push(now);
        true
    }
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

/// Normalise an [`IpAddr`] for rate-limiting purposes.
///
/// * IPv4 addresses are returned as-is.
/// * IPv6 addresses are collapsed to their /64 network prefix (the high-order
///   64 bits). This ensures that all addresses within a single ISP /64
///   allocation share one rate-limit window and cannot trivially bypass it by
///   cycling through the 2⁶⁴ addresses in their allocation (RATE-IPv6-01).
#[must_use]
const fn normalize_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(_) => ip,
        IpAddr::V6(v6) => {
            let segs = v6.segments();
            // Zero out the low 64 bits (segments 4-7), keeping the /64 prefix.
            IpAddr::V6(Ipv6Addr::new(
                segs[0], segs[1], segs[2], segs[3], 0, 0, 0, 0,
            ))
        }
    }
}

// ─── Layer ───────────────────────────────────────────────────────────────────

/// Tower [`Layer`] that applies per-IP sliding-window rate limiting.
///
/// Clone-safe: all clones share the same underlying [`DashMap`].
#[derive(Clone, Debug)]
pub struct RateLimitLayer {
    state: Arc<RateLimitState>,
}

impl RateLimitLayer {
    /// Create a new `RateLimitLayer`.
    ///
    /// # Arguments
    ///
    /// * `max_requests` — maximum number of requests per IP per `window`.
    /// * `window` — duration of the rolling window.
    ///
    /// # Example
    ///
    /// ```rust
    /// use std::time::Duration;
    /// use openhttpa_server::rate_limit::RateLimitLayer;
    ///
    /// // Allow 200 requests per minute per IP address.
    /// let layer = RateLimitLayer::new(200, Duration::from_secs(60));
    /// ```
    #[must_use]
    pub fn new(max_requests: usize, window: Duration) -> Self {
        Self {
            state: RateLimitState::new(max_requests, window),
        }
    }
}

impl<S> Layer<S> for RateLimitLayer {
    type Service = RateLimitService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        RateLimitService {
            inner,
            state: Arc::clone(&self.state),
        }
    }
}

// ─── Service ─────────────────────────────────────────────────────────────────

/// Tower [`Service`] produced by [`RateLimitLayer`].
#[derive(Clone, Debug)]
pub struct RateLimitService<S> {
    inner: S,
    state: Arc<RateLimitState>,
}

impl<S> Service<Request<Body>> for RateLimitService<S>
where
    S: Service<Request<Body>, Response = Response<Body>> + Clone + Send + 'static,
    S::Future: Send + 'static,
{
    type Response = Response<Body>;
    type Error = S::Error;
    type Future = RateLimitFuture<S::Future>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<Body>) -> Self::Future {
        // Extract the client IP from the Axum `ConnectInfo` extension.
        // If unavailable (e.g. in unit tests), fall back to 127.0.0.1.
        let ip: IpAddr = req
            .extensions()
            .get::<ConnectInfo<SocketAddr>>()
            .map_or_else(|| IpAddr::from([127, 0, 0, 1]), |ci| ci.0.ip());

        if self.state.check_and_record(ip) {
            RateLimitFuture::Allowed(self.inner.call(req))
        } else {
            RateLimitFuture::Rejected
        }
    }
}

// ─── Future ──────────────────────────────────────────────────────────────────

/// Future returned by [`RateLimitService`].
#[pin_project::pin_project(project = RateLimitFutureProj)]
pub enum RateLimitFuture<F> {
    /// Request was within rate limit — delegate to inner service future.
    Allowed(#[pin] F),
    /// Request exceeded rate limit — immediately ready with `429`.
    Rejected,
}

impl<F, E> std::future::Future for RateLimitFuture<F>
where
    F: std::future::Future<Output = Result<Response<Body>, E>>,
{
    type Output = Result<Response<Body>, E>;

    fn poll(self: std::pin::Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match self.project() {
            RateLimitFutureProj::Allowed(f) => f.poll(cx),
            RateLimitFutureProj::Rejected => Poll::Ready(Ok(Response::builder()
                .status(StatusCode::TOO_MANY_REQUESTS)
                .body(Body::from("rate limit exceeded"))
                .unwrap())),
        }
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    /// Verify that requests within the limit pass and the (limit+1)th is blocked.
    #[tokio::test]
    async fn allows_up_to_max_and_then_blocks() {
        let state = RateLimitState::new(3, Duration::from_secs(10));
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));

        assert!(state.check_and_record(ip), "1st request should pass");
        assert!(state.check_and_record(ip), "2nd request should pass");
        assert!(state.check_and_record(ip), "3rd request should pass");
        assert!(!state.check_and_record(ip), "4th request should be blocked");
    }

    /// Verify that different IPs do not interfere with each other.
    #[tokio::test]
    async fn different_ips_are_independent() {
        let state = RateLimitState::new(2, Duration::from_secs(10));
        let ip1 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let ip2 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

        assert!(state.check_and_record(ip1));
        assert!(state.check_and_record(ip1));
        assert!(!state.check_and_record(ip1), "ip1 should be blocked");

        // ip2 is unaffected.
        assert!(state.check_and_record(ip2));
        assert!(state.check_and_record(ip2));
        assert!(
            !state.check_and_record(ip2),
            "ip2 should be blocked independently"
        );
    }

    /// Verify that expired entries in the window are pruned so the counter resets.
    #[test]
    fn window_expiry_resets_counter() {
        // Use a window size that is small but large enough to avoid race conditions
        // on slow CI runners.
        let state = Arc::new(RateLimitState {
            clients: Arc::new(DashMap::new()),
            max_requests: 2,
            window: Duration::from_millis(100), // 100ms window
        });

        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));

        // Fill the window.
        assert!(state.check_and_record(ip));
        assert!(state.check_and_record(ip));
        assert!(
            !state.check_and_record(ip),
            "should be blocked: window [100ms] is full"
        );

        // Wait for the window to definitely expire.
        std::thread::sleep(Duration::from_millis(250));

        // Now the window should have reset.
        assert!(
            state.check_and_record(ip),
            "should be allowed after window [100ms] expiry (slept 250ms)"
        );
    }

    /// Verify the `RateLimitLayer` constructs without panic.
    #[tokio::test]
    async fn layer_new_does_not_panic() {
        let _ = RateLimitLayer::new(100, Duration::from_secs(60));
    }

    // ── RATE-IPv6-01 ──────────────────────────────────────────────────────────

    /// IPv4 addresses are returned unchanged.
    #[test]
    fn normalize_ipv4_unchanged() {
        let ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 42));
        assert_eq!(normalize_ip(ip), ip);
    }

    /// Two IPv6 addresses in the same /64 collapse to the same key.
    #[test]
    fn normalize_ipv6_same_prefix_collapses() {
        use std::net::Ipv6Addr;
        let a: IpAddr = Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0x1111, 0x2222, 0x3333, 0x4444).into();
        let b: IpAddr = Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0x9999, 0xaaaa, 0xbbbb, 0xcccc).into();
        assert_eq!(
            normalize_ip(a),
            normalize_ip(b),
            "both /128 addresses must collapse to the same /64 key"
        );
    }

    /// Two IPv6 addresses in different /64 prefixes keep distinct keys.
    #[test]
    fn normalize_ipv6_different_prefix_distinct() {
        use std::net::Ipv6Addr;
        let a: IpAddr = Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0x1111, 0x2222, 0x3333, 0x4444).into();
        let b: IpAddr = Ipv6Addr::new(0x2001, 0x0db8, 0, 1, 0x1111, 0x2222, 0x3333, 0x4444).into();
        assert_ne!(
            normalize_ip(a),
            normalize_ip(b),
            "/64 prefixes differ; keys must differ"
        );
    }

    /// All IPv6 addresses in the same /64 share one rate-limit window (RATE-IPv6-01).
    #[test]
    fn ipv6_prefix_rotation_blocked_by_normalization() {
        use std::net::Ipv6Addr;
        let state = RateLimitState::new(2, Duration::from_secs(10));
        let prefix = [0x2001u16, 0x0db8, 0, 0];

        // Four requests from four different /128 addresses within the same /64.
        for host in 0..=3_u16 {
            let ip: IpAddr = Ipv6Addr::new(
                prefix[0], prefix[1], prefix[2], prefix[3], host, host, host, host,
            )
            .into();
            let allowed = state.check_and_record(ip);
            if host < 2 {
                assert!(allowed, "first 2 requests should be allowed (host={host})");
            } else {
                assert!(!allowed, "request 3+ should be blocked (host={host})");
            }
        }
    }
}
